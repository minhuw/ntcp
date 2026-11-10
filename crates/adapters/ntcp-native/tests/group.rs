use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketIo, PacketLayer, PacketTimestamp, PacketTimestamps,
    ReceivedPacket, TimestampCapabilities, TimestampPoint, TimestampSource, TimestampUnit,
    TxOutcome,
};
use ntcp_native::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

struct Wire {
    incoming: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outgoing: Rc<RefCell<VecDeque<Vec<u8>>>>,
    blocked: Rc<Cell<bool>>,
    fail_after_submit: Rc<Cell<bool>>,
    calls: Rc<Cell<usize>>,
    layer: PacketLayer,
    clock: Rc<Cell<Option<ClockDescriptor>>>,
    rx_tick: Rc<Cell<u64>>,
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65589)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        assert!(packet.len() <= out.len());
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        TimestampCapabilities {
            rx_hardware: self.clock.get().is_some(),
            ..Default::default()
        }
    }
    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        self.receive(out).map(|packet| {
            packet.map(|len| {
                self.rx_tick.set(self.rx_tick.get() + 1);
                ReceivedPacket {
                    len,
                    tcp_segment_size: None,
                    timestamps: PacketTimestamps {
                        software: None,
                        hardware: self.clock.get().map(|clock| PacketTimestamp {
                            value: self.rx_tick.get(),
                            source: TimestampSource::Hardware,
                            point: TimestampPoint::DeviceReceive,
                            clock,
                        }),
                    },
                }
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.calls.set(self.calls.get() + 1);
        if self.blocked.get() {
            return Ok(TxOutcome::WouldBlock);
        }
        self.outgoing.borrow_mut().push_back(packet.to_vec());
        if self.fail_after_submit.replace(false) {
            return Err(io::Error::other("uncertain submission"));
        }
        Ok(TxOutcome::Submitted)
    }
}
fn wires(layer: PacketLayer) -> (Wire, Wire) {
    let a = Rc::new(RefCell::new(VecDeque::new()));
    let b = Rc::new(RefCell::new(VecDeque::new()));
    let make = |incoming, outgoing| Wire {
        incoming,
        outgoing,
        blocked: Rc::new(Cell::new(false)),
        fail_after_submit: Rc::new(Cell::new(false)),
        calls: Rc::new(Cell::new(0)),
        layer,
        clock: Rc::new(Cell::new(None)),
        rx_tick: Rc::new(Cell::new(0)),
    };
    (make(a.clone(), b.clone()), make(b, a))
}
fn config(address: IpAddr, ethernet: bool, side: u8) -> NetworkConfig {
    let mut config = NetworkConfig::new(address, 1500);
    config.tcp.max_connections = 8;
    config.tcp.max_listeners = 2;
    config.tcp.connection.send_capacity = 256;
    config.tcp.connection.receive_capacity = 4096;
    config.tx_timestamp_phases = 4;
    config.rx_timestamp_ranges = 4;
    if ethernet {
        config.link = Link::Ethernet {
            local_mac: [2, 0, 0, 0, 0, side],
            next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
        };
    }
    config
}
const BUDGET: WorkBudget = WorkBudget::new(32, 32, 32, 32);
struct Pair {
    a: Network<Wire>,
    b: Network<Wire>,
    client: ConnId,
    server: ConnId,
    now: u64,
    listener: ListenerId,
}
impl Pair {
    fn new(ipv6: bool, ethernet: bool) -> Self {
        let (ip_a, ip_b): (IpAddr, IpAddr) = if ipv6 {
            (
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            )
        } else {
            ("10.73.0.1".parse().unwrap(), "10.73.0.2".parse().unwrap())
        };
        Self::with_addresses(ip_a, ip_b, ethernet)
    }
    fn with_addresses(ip_a: IpAddr, ip_b: IpAddr, ethernet: bool) -> Self {
        let (a, b) = wires(if ethernet {
            PacketLayer::Ethernet
        } else {
            PacketLayer::Ip
        });
        let mut a = Network::new(config(ip_a, ethernet, 1), a, [1; 32], 0).unwrap();
        let mut b = Network::new(config(ip_b, ethernet, 2), b, [2; 32], 0).unwrap();
        let listener = b.listen(9000, 4).unwrap();
        let client = a.connect(SocketAddr::new(ip_b, 9000)).unwrap();
        assert!(matches!(
            a.try_write(client, b"too early", WriteOptions::default()),
            Err(Error::WouldBlock(BlockReason::Connecting))
        ));
        assert!(matches!(
            a.try_read(client, &mut [0; 8]),
            Err(Error::WouldBlock(BlockReason::Connecting))
        ));
        for now in 1..1000u64 {
            a.drive(now * 100, BUDGET).unwrap();
            b.drive(now * 100, BUDGET).unwrap();
            match b.accept(listener) {
                Ok(server) => {
                    return Self {
                        a,
                        b,
                        client,
                        server,
                        now: now * 100,
                        listener,
                    };
                }
                Err(error) if error.is_would_block() => {}
                Err(error) => panic!("accept: {error:?}"),
            }
        }
        panic!("handshake did not finish");
    }
    fn step(&mut self) {
        self.now += 10_000;
        self.a.drive(self.now, BUDGET).unwrap();
        self.b.drive(self.now, BUDGET).unwrap();
    }
}
fn drain(network: &mut Network<Wire>) -> Vec<Event> {
    let mut result = Vec::new();
    let mut out = [Event::NetworkStopped; 1];
    for _ in 0..100 {
        let report = network.drain_events(&mut out);
        result.extend_from_slice(&out[..report.written]);
        if !report.more {
            return result;
        }
    }
    panic!("event draining did not finish");
}

#[test]
fn ipv4_ipv6_and_ethernet_streams_preserve_partial_write_ranges() {
    for ipv6 in [false, true] {
        for ethernet in [false, true] {
            let mut pair = Pair::new(ipv6, ethernet);
            let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
            let mut sent = 0;
            let mut received = Vec::new();
            let mut read_cursor = 0;
            let mut out = [0; 113];
            let mut partial = false;
            for _ in 0..10000 {
                if sent < data.len() {
                    match pair
                        .a
                        .try_write(pair.client, &data[sent..], WriteOptions::default())
                    {
                        Ok(receipt) => {
                            assert!(receipt.accepted > 0);
                            assert_eq!(
                                receipt.range,
                                TxStreamRange {
                                    start: sent as u64,
                                    end: (sent + receipt.accepted) as u64
                                }
                            );
                            partial |= receipt.accepted < data.len() - sent;
                            sent += receipt.accepted;
                        }
                        Err(error) if error.is_would_block() => {}
                        Err(error) => panic!("write: {error:?}"),
                    }
                }
                pair.step();
                loop {
                    match pair.b.try_read(pair.server, &mut out) {
                        Ok(ReadOutcome::Data { len, range, .. }) => {
                            assert_eq!(
                                range,
                                TxStreamRange {
                                    start: read_cursor,
                                    end: read_cursor + len as u64
                                }
                            );
                            read_cursor += len as u64;
                            received.extend_from_slice(&out[..len]);
                        }
                        Err(error) if error.is_would_block() => break,
                        other => panic!("read: {other:?}"),
                    }
                }
                if received.len() == data.len() {
                    break;
                }
            }
            assert!(partial);
            assert_eq!(
                received.len(),
                data.len(),
                "ipv6={ipv6} ethernet={ethernet} sent={sent} info={:?}",
                pair.a.connection_info(pair.client)
            );
            assert_eq!(received, data);
            assert_eq!(sent, data.len());
            assert_eq!(
                pair.a.try_read(pair.client, &mut []).unwrap(),
                ReadOutcome::EmptyBuffer
            );
            let events = drain(&mut pair.a);
            assert!(events.contains(&Event::Connected(pair.client)));
            assert!(matches!(
                pair.a
                    .try_write(pair.server, b"foreign", WriteOptions::default()),
                Err(Error::InvalidHandle)
            ));
        }
    }
}

#[test]
fn backend_backpressure_retains_received_datagrams_and_retries_without_duplication() {
    let mut pair = Pair::new(false, false);
    pair.a.backend().blocked.set(true);
    let receipt = pair
        .a
        .try_write(pair.client, b"client payload", WriteOptions::default())
        .unwrap();
    assert_eq!(receipt.accepted, 14);
    pair.a.drive(pair.now, BUDGET).unwrap();
    assert!(matches!(
        pair.a
            .try_write(pair.client, b"suffix", WriteOptions::default()),
        Err(Error::WouldBlock(BlockReason::OutputReserved))
    ));
    pair.b
        .try_write(pair.server, b"server payload", WriteOptions::default())
        .unwrap();
    for _ in 0..100 {
        pair.step();
        if pair.a.counters().retained_input > 0 {
            break;
        }
    }
    assert!(pair.a.counters().retained_input > 0);
    pair.a.backend().blocked.set(false);
    let mut from_a = Vec::new();
    let mut from_b = Vec::new();
    let mut out = [0; 128];
    for _ in 0..100 {
        pair.step();
        if let Ok(ReadOutcome::Data { len, .. }) = pair.a.try_read(pair.client, &mut out) {
            from_b.extend_from_slice(&out[..len]);
        }
        if let Ok(ReadOutcome::Data { len, .. }) = pair.b.try_read(pair.server, &mut out) {
            from_a.extend_from_slice(&out[..len]);
        }
        if from_a.len() == 14 && from_b.len() == 14 {
            break;
        }
    }
    assert_eq!(from_a, b"client payload");
    assert_eq!(from_b, b"server payload");
    assert!(pair.a.counters().backend_backpressure > 0);
    assert_eq!(pair.a.counters().retained_input, 0);
}

#[test]
fn timestamp_capacity_includes_staged_events_until_the_caller_drains_them() {
    let mut pair = Pair::new(false, false);
    let options = WriteOptions {
        timestamps: TxTimestampRequest {
            cookie: 41,
            scheduled: true,
            acknowledged: true,
            ..Default::default()
        },
    };
    pair.a.try_write(pair.client, b"one", options).unwrap();
    pair.a.try_write(pair.client, b"two", options).unwrap();
    let before = pair.a.send_progress(pair.client).unwrap();
    assert!(matches!(
        pair.a.try_write(pair.client, b"three", options),
        Err(Error::WouldBlock(BlockReason::TimestampCapacity))
    ));
    assert_eq!(pair.a.send_progress(pair.client).unwrap(), before);
    for _ in 0..100 {
        pair.step();
    }
    let empty = pair.a.drain_timestamps(&mut []);
    assert!(empty.more);
    // Peeking a completion out of the core must not prematurely free the
    // native admission charge while the result is still in the staging slot.
    assert!(matches!(
        pair.a.try_write(pair.client, b"three", options),
        Err(Error::WouldBlock(BlockReason::TimestampCapacity))
    ));
    let placeholder = TimestampEvent {
        connection: pair.client,
        observation: TxTimestampEvent {
            cookie: 0,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    };
    let mut out = [placeholder; 1];
    let mut events = Vec::new();
    loop {
        let report = pair.a.drain_timestamps(&mut out);
        events.extend_from_slice(&out[..report.written]);
        if !report.more {
            break;
        }
    }
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| e.observation.cookie == 41));
    assert!(
        events
            .iter()
            .all(|e| matches!(e.observation.outcome, TxTimestampOutcome::Recorded { .. }))
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.observation.stage == TxTimestampStage::Acknowledged)
            .count(),
        2
    );
    assert!(pair.a.try_write(pair.client, b"three", options).is_ok());
}

#[test]
fn unsupported_hardware_observation_rejects_before_byte_admission() {
    let mut pair = Pair::new(false, false);
    let before = pair.a.send_progress(pair.client).unwrap();
    let options = WriteOptions {
        timestamps: TxTimestampRequest {
            hardware_transmit: true,
            ..Default::default()
        },
    };
    assert!(matches!(
        pair.a
            .try_write(pair.client, b"must not be admitted", options),
        Err(Error::Unsupported(_))
    ));
    assert_eq!(pair.a.send_progress(pair.client).unwrap(), before);
    assert!(!pair.a.timestamp_capabilities().hardware_transmit);
}

#[test]
fn uncertain_submission_stops_the_instance_and_does_not_retry() {
    let mut pair = Pair::new(false, false);
    let options = WriteOptions {
        timestamps: TxTimestampRequest {
            cookie: 99,
            scheduled: true,
            acknowledged: true,
            ..Default::default()
        },
    };
    pair.a
        .try_write(pair.client, b"uncertain", options)
        .unwrap();
    pair.a.backend().fail_after_submit.set(true);
    assert!(matches!(
        pair.a.drive(pair.now, BUDGET),
        Err(Error::Backend(_))
    ));
    let calls = pair.a.backend().calls.get();
    assert!(pair.a.is_stopped());
    assert!(pair.a.failure().is_some());
    assert!(matches!(
        pair.a.drive(pair.now + 1, BUDGET),
        Err(Error::Stopped)
    ));
    assert!(matches!(
        pair.a
            .try_write(pair.client, b"retry", WriteOptions::default()),
        Err(Error::Stopped)
    ));
    assert_eq!(pair.a.backend().calls.get(), calls);
    assert!(drain(&mut pair.a).contains(&Event::NetworkStopped));
    let mut events = [TimestampEvent {
        connection: pair.client,
        observation: TxTimestampEvent {
            cookie: 0,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    }; 4];
    let report = pair.a.drain_timestamps(&mut events);
    assert_eq!(report.written, 2);
    assert!(
        events[..2]
            .iter()
            .any(|e| e.observation.outcome == TxTimestampOutcome::Cancelled)
    );
}

#[test]
fn write_shutdown_preserves_the_read_side_and_eof_is_not_would_block() {
    let mut pair = Pair::new(false, false);
    pair.a
        .try_write(pair.client, b"request", WriteOptions::default())
        .unwrap();
    pair.a.shutdown_write(pair.client).unwrap();
    let mut out = [0; 128];
    let mut request = Vec::new();
    let mut eof = false;
    for _ in 0..100 {
        pair.step();
        match pair.b.try_read(pair.server, &mut out) {
            Ok(ReadOutcome::Data { len, .. }) => request.extend_from_slice(&out[..len]),
            Ok(ReadOutcome::Eof) => {
                eof = true;
                break;
            }
            Err(e) if e.is_would_block() => {}
            other => panic!("read: {other:?}"),
        }
    }
    assert_eq!(request, b"request");
    assert!(eof);
    pair.b
        .try_write(pair.server, b"response", WriteOptions::default())
        .unwrap();
    let mut response = Vec::new();
    for _ in 0..100 {
        pair.step();
        if let Ok(ReadOutcome::Data { len, .. }) = pair.a.try_read(pair.client, &mut out) {
            response.extend_from_slice(&out[..len]);
        }
        if response.len() == 8 {
            break;
        }
    }
    assert_eq!(response, b"response");
}

#[test]
fn shared_admission_advances_the_payload_and_keeps_storage_until_ack() {
    let mut pair = Pair::new(false, false);
    // Payload release callbacks must be Send + Sync; use an atomic counter.
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback = count.clone();
    let original: Vec<u8> = (0..1024).map(|n| (n % 251) as u8).collect();
    let mut payload = Payload::from_vec(original.clone()).with_release(move || {
        callback.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    let receipt = pair.a.try_write_shared(pair.client, &mut payload).unwrap();
    assert!(receipt.accepted > 0 && receipt.accepted < original.len());
    assert_eq!(payload.as_slice(), &original[receipt.accepted..]);
    drop(payload);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut received = Vec::new();
    let mut out = [0; 512];
    for _ in 0..100 {
        pair.step();
        if let Ok(ReadOutcome::Data { len, .. }) = pair.b.try_read(pair.server, &mut out) {
            received.extend_from_slice(&out[..len]);
        }
        if count.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            break;
        }
    }
    assert_eq!(received, original[..receipt.accepted]);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn device_clock_metadata_preserves_calibration_identity_and_counts_capacity_loss() {
    let mut pair = Pair::new(false, false);
    pair.a.set_nodelay(pair.client, true).unwrap();
    let mut out = [0; 32];
    for epoch in 0..3 {
        let descriptor = ClockDescriptor {
            domain: ClockDomain::Device(17),
            unit: TimestampUnit::RawTicks {
                identity: 23 + epoch,
            },
        };
        pair.b.backend().clock.set(Some(descriptor));
        pair.a
            .try_write(pair.client, b"data", WriteOptions::default())
            .unwrap();
        let mut observed = None;
        for _ in 0..100 {
            pair.step();
            match pair.b.try_read(pair.server, &mut out) {
                Ok(ReadOutcome::Data {
                    len,
                    range,
                    last_byte_timestamps,
                }) => {
                    observed = Some((len, range, last_byte_timestamps));
                    break;
                }
                Err(e) if e.is_would_block() => {}
                other => panic!("read: {other:?}"),
            }
        }
        let (len, range, metadata) = observed.expect("data arrived");
        assert_eq!(len, 4);
        assert_eq!(&out[..len], b"data");
        assert_eq!(
            range,
            TxStreamRange {
                start: epoch * 4,
                end: epoch * 4 + 4
            }
        );
        let hardware = metadata.and_then(|m| m.timestamps.hardware);
        if epoch < 2 {
            let clock = hardware.expect("device timestamp retained").clock;
            assert_eq!(pair.b.backend_clock(clock), Some(descriptor));
        } else {
            assert!(hardware.is_none());
            assert!(pair.b.counters().timestamp_metadata_lost > 0);
        }
    }
}

#[test]
fn abort_retires_a_generation_and_stale_handles_cannot_reach_a_new_connection() {
    let mut pair = Pair::new(false, false);
    let old = pair.client;
    drain(&mut pair.a);
    drain(&mut pair.b);
    pair.a.abort(old).unwrap();
    for _ in 0..100 {
        pair.step();
        drain(&mut pair.a);
        drain(&mut pair.b);
        if matches!(pair.a.connection_info(old), Err(Error::InvalidHandle)) {
            break;
        }
    }
    assert!(pair.a.connection_info(old).unwrap().application_closed);
    // TCP retains a locally reset tuple for its TIME-WAIT duration. Releasing
    // the application handle must not make its port or slot reusable during
    // that interval.
    let retention = pair.a.config().tcp.connection.time_wait_us;
    // This fixture's caller clock is in microseconds, matching its durations.
    pair.now += retention;
    for _ in 0..10 {
        pair.step();
        drain(&mut pair.a);
        drain(&mut pair.b);
        if matches!(pair.a.connection_info(old), Err(Error::InvalidHandle)) {
            break;
        }
    }
    assert!(matches!(
        pair.a.connection_info(old),
        Err(Error::InvalidHandle)
    ));
    let peer = pair.b.config().local_address;
    let next = pair.a.connect(SocketAddr::new(peer, 9000)).unwrap();
    assert_ne!(next, old);
    assert!(matches!(
        pair.a.try_write(old, b"stale", WriteOptions::default()),
        Err(Error::InvalidHandle)
    ));
    let mut accepted = None;
    for _ in 0..100 {
        pair.step();
        if let Ok(id) = pair.b.accept(pair.listener) {
            accepted = Some(id);
            break;
        }
    }
    assert!(accepted.is_some());
    assert_eq!(
        pair.a.connection_info(next).unwrap().state,
        State::Established
    );
}

#[test]
fn zero_work_budget_and_backwards_time_do_not_touch_the_backend() {
    let mut pair = Pair::new(false, false);
    pair.a
        .try_write(pair.client, b"pending", WriteOptions::default())
        .unwrap();
    let calls = pair.a.backend().calls.get();
    let report = pair.a.drive(pair.now, WorkBudget::new(0, 0, 0, 0)).unwrap();
    assert_eq!(report.received, 0);
    assert_eq!(report.transmitted, 0);
    assert_eq!(pair.a.backend().calls.get(), calls);
    assert!(matches!(
        pair.a.drive(pair.now - 1, BUDGET),
        Err(Error::TimeWentBackwards)
    ));
    assert_eq!(pair.a.backend().calls.get(), calls);
}

#[test]
fn repeated_write_shutdown_is_idempotent() {
    let mut pair = Pair::new(false, false);
    pair.a.shutdown_write(pair.client).unwrap();
    pair.a.shutdown_write(pair.client).unwrap();
    pair.step();
    pair.a.shutdown_write(pair.client).unwrap();
}

#[test]
fn link_local_ipv6_uses_the_groups_link_and_preserves_held_input_scope() {
    for ethernet in [false, true] {
        let mut pair = Pair::with_addresses(
            "fe80::1".parse().unwrap(),
            "fe80::2".parse().unwrap(),
            ethernet,
        );
        let scoped = std::net::SocketAddrV6::new("fe80::2".parse().unwrap(), 9000, 0, 7);
        assert!(matches!(
            pair.a.connect(scoped.into()),
            Err(Error::Unsupported(_))
        ));
        pair.a.backend().blocked.set(true);
        pair.a
            .try_write(pair.client, b"outbound", WriteOptions::default())
            .unwrap();
        pair.a.drive(pair.now, BUDGET).unwrap();
        pair.b
            .try_write(pair.server, b"inbound", WriteOptions::default())
            .unwrap();
        for _ in 0..100 {
            pair.step();
            if pair.a.counters().retained_input != 0 {
                break;
            }
        }
        assert!(pair.a.counters().retained_input != 0);
        pair.a.backend().blocked.set(false);
        let mut received = Vec::new();
        let mut out = [0; 32];
        for _ in 0..100 {
            pair.step();
            if let Ok(ReadOutcome::Data { len, .. }) = pair.a.try_read(pair.client, &mut out) {
                received.extend_from_slice(&out[..len]);
            }
            if received.len() == 7 && pair.a.counters().retained_input == 0 {
                break;
            }
        }
        assert_eq!(received, b"inbound");
        assert_eq!(pair.a.counters().retained_input, 0);
    }
}

#[test]
fn abort_withdraws_a_certainly_unsubmitted_frame_without_transmitting_its_data() {
    let mut pair = Pair::new(false, false);
    pair.a.backend().blocked.set(true);
    pair.a
        .try_write(pair.client, b"withdrawn", WriteOptions::default())
        .unwrap();
    assert!(pair.a.drive(pair.now, BUDGET).unwrap().tx_blocked);
    pair.a.abort(pair.client).unwrap();
    pair.a.backend().blocked.set(false);
    let mut out = [0; 64];
    let mut reset = false;
    for _ in 0..100 {
        pair.step();
        match pair.b.try_read(pair.server, &mut out) {
            Err(Error::ConnectionClosed(Some(CloseReason::Reset))) => {
                reset = true;
                break;
            }
            Err(e) if e.is_would_block() => {}
            other => panic!("withdrawn data reached the peer: {other:?}"),
        }
    }
    assert!(reset);
    assert_eq!(pair.a.counters().retained_input, 0);
}

#[test]
fn close_keeps_the_handle_until_all_timestamp_obligations_are_drained() {
    let mut pair = Pair::new(false, false);
    let options = WriteOptions {
        timestamps: TxTimestampRequest {
            cookie: 123,
            scheduled: true,
            acknowledged: true,
            ..Default::default()
        },
    };
    pair.a.try_write(pair.client, b"tracked", options).unwrap();
    for _ in 0..100 {
        pair.step();
    }
    // Stage a ready result without returning it to the caller.
    assert!(pair.a.drain_timestamps(&mut []).more);
    pair.a.abort(pair.client).unwrap();
    for _ in 0..100 {
        pair.step();
        drain(&mut pair.a);
    }
    pair.now += pair.a.config().tcp.connection.time_wait_us;
    for _ in 0..10 {
        pair.step();
        drain(&mut pair.a);
    }
    assert!(
        pair.a
            .connection_info(pair.client)
            .unwrap()
            .application_closed
    );
    let mut out = [TimestampEvent {
        connection: pair.client,
        observation: TxTimestampEvent {
            cookie: 0,
            target: 0,
            stage: TxTimestampStage::Scheduled,
            source: TxTimestampSource::Software,
            outcome: TxTimestampOutcome::Cancelled,
        },
    }; 1];
    let first = pair.a.drain_timestamps(&mut out);
    assert_eq!(
        first,
        DrainReport {
            written: 1,
            more: true
        }
    );
    assert_eq!(out[0].connection, pair.client);
    assert_eq!(out[0].observation.cookie, 123);
    pair.step();
    assert!(pair.a.connection_info(pair.client).is_ok());
    let last = pair.a.drain_timestamps(&mut out);
    assert_eq!(
        last,
        DrainReport {
            written: 1,
            more: false
        }
    );
    assert_eq!(out[0].observation.cookie, 123);
    for _ in 0..10 {
        pair.step();
        if matches!(
            pair.a.connection_info(pair.client),
            Err(Error::InvalidHandle)
        ) {
            break;
        }
    }
    assert!(matches!(
        pair.a.connection_info(pair.client),
        Err(Error::InvalidHandle)
    ));
}

#[test]
fn write_readiness_is_rearmed_after_send_buffer_backpressure() {
    let mut pair = Pair::new(false, false);
    drain(&mut pair.a);
    let capacity = pair.a.config().tcp.connection.send_capacity;
    pair.a
        .try_write(pair.client, &vec![42; capacity], WriteOptions::default())
        .unwrap();
    assert!(matches!(
        pair.a
            .try_write(pair.client, b"later", WriteOptions::default()),
        Err(Error::WouldBlock(BlockReason::SendBuffer))
    ));
    assert!(!drain(&mut pair.a).contains(&Event::Writable(pair.client)));
    for _ in 0..100 {
        pair.step();
    }
    assert!(pair.a.drain_events(&mut []).more);
    let events = drain(&mut pair.a);
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::Writable(pair.client))
            .count(),
        1
    );
    assert!(
        pair.a
            .try_write(pair.client, b"later", WriteOptions::default())
            .is_ok()
    );
    assert!(!drain(&mut pair.a).contains(&Event::Writable(pair.client)));
}

#[test]
fn one_drive_reaches_data_queued_behind_idle_connections() {
    let mut pair = Pair::new(false, false);
    let peer = pair.a.connection_info(pair.client).unwrap().peer;
    let mut connections = vec![pair.client];
    for _ in 0..3 {
        let id = pair.a.connect(peer).unwrap();
        for _ in 0..100 {
            pair.step();
            while pair.b.accept(pair.listener).is_ok() {}
            if pair.a.connection_info(id).unwrap().state == State::Established {
                break;
            }
        }
        assert_eq!(
            pair.a.connection_info(id).unwrap().state,
            State::Established
        );
        connections.push(id);
    }
    for _ in 0..10 {
        pair.step();
    }
    drain(&mut pair.a);
    // Setting an option refreshes a connection without giving it output, so
    // each idle connection is queued ahead of the one with data.
    let (busy, idle) = connections.split_last().unwrap();
    for &id in idle {
        pair.a.set_nodelay(id, true).unwrap();
    }
    pair.a
        .try_write(*busy, b"hello", WriteOptions::default())
        .unwrap();
    let report = pair.a.drive(pair.now + 1, BUDGET).unwrap();
    assert_eq!(report.transmitted, 1, "{report:?}");
}

// Sending a FIN and having it acknowledged change a connection's state
// without an event: its information is the endpoint's state, current
// without draining events. The Closed event still arrives, and the handle
// is released only after the application drained it.
#[test]
fn connection_info_is_current_without_events_and_close_still_completes() {
    let mut pair = Pair::new(false, false);
    drain(&mut pair.a);
    drain(&mut pair.b);
    pair.a.close(pair.client).unwrap();
    pair.now += 10_000;
    pair.a.drive(pair.now, BUDGET).unwrap();
    let state = |pair: &Pair| pair.a.connection_info(pair.client).unwrap().state;
    assert_eq!(state(&pair), State::FinWait1);
    // The peer acknowledges the FIN; the next drive of `a` takes the ACK.
    pair.step();
    pair.step();
    assert_eq!(state(&pair), State::FinWait2);
    assert!(matches!(
        pair.b.try_read(pair.server, &mut [0; 8]),
        Ok(ReadOutcome::Eof)
    ));
    pair.b.close(pair.server).unwrap();
    pair.step();
    pair.step();
    assert_eq!(state(&pair), State::TimeWait);
    // Not released while its Closed event is undelivered.
    for _ in 0..3 {
        pair.step();
        assert!(pair.a.connection_info(pair.client).is_ok());
    }
    let events = drain(&mut pair.a);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Closed { connection, .. } if *connection == pair.client)),
        "{events:?}"
    );
    pair.now += pair.a.config().tcp.connection.time_wait_us;
    for _ in 0..10 {
        pair.step();
        drain(&mut pair.a);
        if pair.a.connection_info(pair.client).is_err() {
            break;
        }
    }
    assert!(matches!(
        pair.a.connection_info(pair.client),
        Err(Error::InvalidHandle)
    ));
}

// Readable is a level: a read that leaves bytes behind is followed by
// another Readable, and one that takes the rest by none.
#[test]
fn a_partial_read_raises_readable_again() {
    let mut pair = Pair::new(false, false);
    drain(&mut pair.a);
    pair.b
        .try_write(pair.server, &[7; 100], WriteOptions::default())
        .unwrap();
    pair.step();
    pair.step();
    let client = pair.client;
    let readable = |events: &[Event]| events.contains(&Event::Readable(client));
    assert!(readable(&drain(&mut pair.a)));
    assert!(!readable(&drain(&mut pair.a)));
    let mut buffer = [0; 64];
    assert!(matches!(
        pair.a.try_read(pair.client, &mut buffer[..10]),
        Ok(ReadOutcome::Data { len: 10, .. })
    ));
    assert!(readable(&drain(&mut pair.a)));
    assert!(matches!(
        pair.a.try_read(pair.client, &mut buffer),
        Ok(ReadOutcome::Data { len: 64, .. })
    ));
    assert!(matches!(
        pair.a.try_read(pair.client, &mut buffer),
        Ok(ReadOutcome::Data { len: 26, .. })
    ));
    assert!(!readable(&drain(&mut pair.a)));
}

// A listener with a connection left to accept after an accept is
// acceptable again, though the endpoint raises nothing for it.
#[test]
fn a_listener_is_acceptable_again_while_connections_wait() {
    let mut pair = Pair::new(false, false);
    let peer = pair.a.connection_info(pair.client).unwrap().peer;
    drain(&mut pair.b);
    let listener = pair.listener;
    let acceptable = |events: &[Event]| {
        events
            .iter()
            .filter(|e| **e == Event::Acceptable(listener))
            .count()
    };
    for _ in 0..2 {
        pair.a.connect(peer).unwrap();
    }
    for _ in 0..10 {
        pair.step();
    }
    assert_eq!(acceptable(&drain(&mut pair.b)), 1);
    pair.b.accept(pair.listener).unwrap();
    assert_eq!(acceptable(&drain(&mut pair.b)), 1);
    pair.b.accept(pair.listener).unwrap();
    assert_eq!(acceptable(&drain(&mut pair.b)), 0);
    assert!(pair.b.accept(pair.listener).unwrap_err().is_would_block());
}

// Connections that nothing happened to give no events, and a change gives
// events for its connection alone.
#[test]
fn idle_connections_give_no_events() {
    let mut pair = Pair::new(false, false);
    let peer = pair.a.connection_info(pair.client).unwrap().peer;
    for _ in 0..4 {
        pair.a.connect(peer).unwrap();
    }
    for _ in 0..10 {
        pair.step();
        while pair.b.accept(pair.listener).is_ok() {}
    }
    drain(&mut pair.a);
    drain(&mut pair.b);
    for _ in 0..3 {
        pair.step();
    }
    assert_eq!(drain(&mut pair.a), []);
    assert!(!pair.a.drain_events(&mut []).more);
    pair.b
        .try_write(pair.server, b"hello", WriteOptions::default())
        .unwrap();
    pair.step();
    pair.step();
    assert_eq!(drain(&mut pair.a), [Event::Readable(pair.client)]);
}

// The budget for n connections admits n connections, their timestamp
// capacities included, and one octet less admits one fewer.
#[test]
fn the_buffer_budget_admits_exactly_its_connections() {
    let address = "10.73.0.1".parse().unwrap();
    let peer = SocketAddr::new("10.73.0.2".parse().unwrap(), 9000);
    let budget = config(address, false, 1).buffer_budget(3).unwrap();
    let admitted = |budget: usize| {
        let mut config = config(address, false, 1);
        config.tcp.max_buffer_bytes = budget;
        let (wire, _) = wires(PacketLayer::Ip);
        let mut network = Network::new(config, wire, [1; 32], 0).unwrap();
        (0..8).take_while(|_| network.connect(peer).is_ok()).count()
    };
    assert_eq!(admitted(budget), 3);
    assert_eq!(admitted(budget - 1), 2);
}

// Applications that read, write and accept only when an event says so
// complete every exchange while transmits are refused at random and reads
// take random amounts: no event is lost. Debug builds also check after
// every drain that no connection has an event left unqueued.
#[test]
fn event_driven_exchanges_complete_under_backpressure_and_partial_reads() {
    const EXCHANGES: usize = 100;
    const SIZE: usize = 48;
    let mut pair = Pair::new(false, false);
    let peer = pair.a.connection_info(pair.client).unwrap().peer;
    let mut clients = vec![pair.client];
    for _ in 0..3 {
        clients.push(pair.a.connect(peer).unwrap());
    }
    let mut servers = vec![pair.server];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut random = move |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % bound as u64) as usize
    };
    // Per client: exchanges done, octets of the current response still to
    // come, and whether its request still has to be written.
    let mut done = vec![0; clients.len()];
    let mut awaited = vec![0; clients.len()];
    let mut unwritten = vec![true; clients.len()];
    // Per server: octets read and not yet echoed.
    let mut echo: Vec<usize> = Vec::new();
    let mut buffer = [0; SIZE];
    for _ in 0..20_000 {
        if done.iter().all(|&n| n == EXCHANGES) {
            return;
        }
        pair.a.backend().blocked.set(random(3) == 0);
        pair.b.backend().blocked.set(random(3) == 0);
        pair.step();
        for event in drain(&mut pair.b) {
            match event {
                Event::Acceptable(_) => {
                    while let Ok(server) = pair.b.accept(pair.listener) {
                        servers.push(server);
                    }
                }
                Event::Readable(id) | Event::Writable(id) => {
                    let index = servers.iter().position(|&s| s == id).unwrap();
                    echo.resize(servers.len(), 0);
                    if let Event::Readable(_) = event
                        && let Ok(ReadOutcome::Data { len, .. }) =
                            pair.b.try_read(id, &mut buffer[..1 + random(SIZE)])
                    {
                        echo[index] += len;
                    }
                    if echo[index] != 0 {
                        match pair
                            .b
                            .try_write(id, &buffer[..echo[index]], WriteOptions::default())
                        {
                            Ok(receipt) => echo[index] -= receipt.accepted,
                            Err(error) => assert!(error.is_would_block(), "{error:?}"),
                        }
                    }
                }
                _ => {}
            }
        }
        for event in drain(&mut pair.a) {
            let (Event::Connected(id) | Event::Readable(id) | Event::Writable(id)) = event else {
                continue;
            };
            let index = clients.iter().position(|&c| c == id).unwrap();
            if let Event::Readable(_) = event
                && let Ok(ReadOutcome::Data { len, .. }) =
                    pair.a.try_read(id, &mut buffer[..1 + random(SIZE)])
            {
                awaited[index] -= len;
                if awaited[index] == 0 {
                    done[index] += 1;
                    unwritten[index] = done[index] < EXCHANGES;
                }
            }
            if unwritten[index] && awaited[index] == 0 {
                match pair.a.try_write(id, &[7; SIZE], WriteOptions::default()) {
                    Ok(receipt) => {
                        assert_eq!(receipt.accepted, SIZE);
                        unwritten[index] = false;
                        awaited[index] = SIZE;
                    }
                    Err(error) => assert!(error.is_would_block(), "{error:?}"),
                }
            }
        }
    }
    panic!("exchanges stalled: {done:?}, awaiting {awaited:?}, unwritten {unwritten:?}");
}
