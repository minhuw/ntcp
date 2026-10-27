use super::super::tests::pair;
use super::*;
use ntcp_io::{OwnedPacket, Payload, ZeroCopyCapabilities};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct SharedState {
    block: bool,
    packet_limit: usize,
    held: Vec<OwnedPacket>,
    sent: Vec<Vec<u8>>,
}
struct AsyncShared(Arc<Mutex<SharedState>>);
impl PacketIo for AsyncShared {
    fn layer(&self) -> ntcp_io::PacketLayer {
        ntcp_io::PacketLayer::Ethernet
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(2048)
    }
    fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
        Ok(None)
    }
    fn transmit(&mut self, packet: &[u8]) -> std::io::Result<TxOutcome> {
        let mut state = self.0.lock().unwrap();
        if state.block {
            return Ok(TxOutcome::WouldBlock);
        }
        state.sent.push(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn zero_copy_capabilities(&self) -> Option<ZeroCopyCapabilities> {
        Some(ZeroCopyCapabilities {
            max_payload_segments: 4,
            max_packet_len: self.0.lock().unwrap().packet_limit,
        })
    }
    fn zero_copy_payload_supported(&self, payload: &Payload) -> bool {
        payload.storage::<Vec<u8>>().is_some()
    }
    fn transmit_zero_copy(&mut self, packet: &OwnedPacket) -> std::io::Result<TxOutcome> {
        let mut state = self.0.lock().unwrap();
        if state.block {
            return Ok(TxOutcome::WouldBlock);
        }
        // The asynchronous backend retains references. A separate test observer
        // materializes wire bytes for the receiving TCP implementation.
        state.held.push(OwnedPacket {
            header: packet.header.clone(),
            payload: packet.payload.clone(),
        });
        Ok(TxOutcome::Submitted)
    }
}
fn attach(owner: &mut Owner) -> Arc<Mutex<SharedState>> {
    attach_limit(owner, 2048)
}
fn attach_limit(owner: &mut Owner, packet_limit: usize) -> Arc<Mutex<SharedState>> {
    let state = Arc::new(Mutex::new(SharedState {
        packet_limit,
        ..Default::default()
    }));
    owner.ethernet = Some(EthernetBackend {
        io: Box::new(AsyncShared(state.clone())),
        local: [2; 6],
        next_hop: [4; 6],
        next_cookie: 1,
        pending: Vec::with_capacity(timestamps::PHASES),
    });
    owner.enable_egress(4, None).unwrap();
    state
}
fn drain_wire(state: &Arc<Mutex<SharedState>>, to: &mut Owner) {
    let state = state.lock().unwrap();
    for packet in &state.held {
        let mut wire = packet.header.clone();
        for part in &packet.payload {
            wire.extend_from_slice(part.as_slice());
        }
        let (_, total) = ntcp_ip::ipv4_bounds(&wire[14..]).unwrap();
        let ip = ntcp_ip::parse(&wire[14..14 + total], false).unwrap();
        to.input(to.now(), ip.ip, ip.traffic_class, ip.payload)
            .unwrap();
    }
}
fn send_registered(a: &mut Owner, id: u64, sources: Vec<(usize, usize)>) -> i32 {
    let (reply, result) = mpsc::sync_channel(1);
    let mut request = Request {
        id,
        op: Op::Send(sources, MSG_ZEROCOPY),
        reply,
        deadline: None,
        send: None,
        closing: None,
    };
    for _ in 0..BUDGET {
        if a.service(&mut request) {
            return result.recv().unwrap().unwrap().value;
        }
    }
    panic!("bounded send did not finish");
}
#[test]
fn registered_send_waits_for_ack_and_async_backend_reclaim() {
    let (mut a, mut b, client, server, _) = pair();
    let state = attach(&mut a);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let data: Vec<u8> = (0..1777).map(|n| (n % 251) as u8).collect();
    let registration = crate::RegisteredPayload::register(Payload::from_vec(data.clone())).unwrap();
    let pointer = registration.as_slice().as_ptr();
    assert_ne!(pointer, data.as_ptr());
    assert_eq!(
        send_registered(
            &mut a,
            client,
            vec![
                (pointer as usize, 503),
                (pointer.wrapping_add(503) as usize, data.len() - 503)
            ]
        ),
        data.len() as i32
    );
    assert!(a.sockets[&client].completions.is_empty());
    assert_eq!(a.sockets[&client].zc_reserved, 1);
    state.lock().unwrap().block = true;
    a.service_egress().unwrap();
    assert!(state.lock().unwrap().held.is_empty());
    assert!(a.egress.as_ref().unwrap().has_held());
    state.lock().unwrap().block = false;
    a.epoch -= std::time::Duration::from_millis(2);
    a.service_egress().unwrap();
    {
        let held = state.lock().unwrap();
        let parts: Vec<_> = held.held.iter().flat_map(|p| &p.payload).collect();
        let mut offset = 0;
        for part in parts {
            assert_eq!(part.as_slice().as_ptr(), pointer.wrapping_add(offset));
            offset += part.len();
        }
        assert_eq!(offset, data.len());
    }
    drop(registration); // no new admission; accepted references remain valid.
    drain_wire(&state, &mut b);
    b.epoch -= std::time::Duration::from_millis(210);
    b.endpoint.on_timeout(b.now(), BUDGET).unwrap();
    // Service real receiver ACKs without selecting sender output via legacy poll.
    for _ in 0..BUDGET {
        let mut bytes = [0; 2048];
        let Some(tx) = b
            .endpoint
            .poll_transmit(b.now(), &mut bytes, BUDGET)
            .unwrap()
            .packet
        else {
            break;
        };
        a.input(a.now(), tx.ip, tx.dscp << 2 | tx.ecn, &bytes[..tx.len])
            .unwrap();
    }
    assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(a.endpoint.acknowledged(cid), Ok(data.len() as u64));
    a.collect_zero_copy();
    assert!(a.sockets[&client].completions.is_empty());
    state.lock().unwrap().held.clear();
    a.collect_zero_copy();
    assert_eq!(a.sockets[&client].zc_reserved, 0);
    assert_eq!(
        a.sockets[&client].completions.front(),
        Some(&Completion::SharedZeroCopy(0, 0, false))
    );
    assert_eq!(a.execute(client, Op::ErrorQueueTo(1)).unwrap_err(), EFAULT);
    assert_eq!(a.sockets[&client].completions.len(), 1);
    let mut control = [0u8; 128];
    let mut message: msghdr = unsafe { std::mem::zeroed() };
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    a.execute(client, Op::ErrorQueueTo(&mut message as *mut _ as usize))
        .unwrap();
    let start = std::mem::size_of::<cmsghdr>();
    assert_eq!(control[start + 4], 5); // SO_EE_ORIGIN_ZEROCOPY
    assert_eq!(control[start + 6], 0); // true zero-copy, never COPIED
    assert_eq!(message.msg_flags & MSG_ERRQUEUE, MSG_ERRQUEUE);
    assert!(a.sockets[&client].completions.is_empty());
}
#[test]
fn registered_send_abort_waits_for_backend_and_unregistered_stays_copied() {
    let (mut a, _, client, _, _) = pair();
    let state = attach(&mut a);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let registration = crate::RegisteredPayload::register(Payload::from_vec(vec![9; 100])).unwrap();
    let address = registration.as_slice().as_ptr() as usize;
    assert_eq!(send_registered(&mut a, client, vec![(address, 100)]), 100);
    a.service_egress().unwrap();
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    a.endpoint.abort(cid).unwrap();
    a.collect_zero_copy();
    assert!(a.sockets[&client].completions.is_empty());
    state.lock().unwrap().held.clear();
    a.collect_zero_copy();
    assert_eq!(
        a.sockets[&client].completions.front(),
        Some(&Completion::SharedZeroCopy(0, 0, false))
    );
    // A separate ordinary pointer continues to use the fault-safe copied API.
    let (mut a, _, client, _, _) = pair();
    attach(&mut a);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    assert_eq!(send_registered(&mut a, client, vec![(address, 100)]), 100);
    let copied = vec![3; 71];
    assert_eq!(
        send_registered(
            &mut a,
            client,
            vec![(copied.as_ptr() as usize, copied.len())]
        ),
        71
    );
    assert_eq!(
        a.sockets[&client].completions.back(),
        Some(&Completion::ZeroCopy(1, 1))
    );
}

#[test]
fn mixed_and_faulted_iovecs_keep_one_id_and_truthful_completion_code() {
    for fault in [false, true] {
        let (mut a, _, client, _, _) = pair();
        let state = attach(&mut a);
        a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
            .unwrap();
        a.execute(client, Op::Flags(F_SETFL, 0)).unwrap();
        let registration =
            crate::RegisteredPayload::register(Payload::from_vec(vec![8; 100])).unwrap();
        let pointer = registration.as_slice().as_ptr();
        let ordinary = [3; 23];
        let sources = vec![
            (pointer as usize, 37),
            (
                if fault { 1 } else { ordinary.as_ptr() as usize },
                ordinary.len(),
            ),
            (pointer.wrapping_add(37) as usize, 40),
        ];
        let (reply, result) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(Op::Send(sources, MSG_ZEROCOPY)), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        for _ in 0..BUDGET {
            if a.service(&mut request) {
                break;
            }
        }
        assert_eq!(
            result.try_recv().unwrap().unwrap().value,
            if fault { 37 } else { 100 }
        );
        assert_eq!(a.sockets[&client].zc_next, 1);
        assert_eq!(a.sockets[&client].zc_reserved, 1);
        a.service_egress().unwrap();
        let Handle::Connection(cid) = a.sockets[&client].handle else {
            panic!()
        };
        a.endpoint.abort(cid).unwrap();
        a.collect_zero_copy();
        assert!(a.sockets[&client].completions.is_empty());
        state.lock().unwrap().held.clear();
        a.collect_zero_copy();
        assert_eq!(
            a.sockets[&client].completions.front(),
            Some(&Completion::SharedZeroCopy(0, 0, !fault))
        );
        assert_eq!(a.sockets[&client].zc_reserved, 0);
    }
}

#[test]
fn backend_can_reclaim_before_ack_without_releasing_tcp_ownership() {
    let (mut a, _, client, _, _) = pair();
    let state = attach(&mut a);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    let registration = crate::RegisteredPayload::register(Payload::from_vec(vec![2; 79])).unwrap();
    assert_eq!(
        send_registered(
            &mut a,
            client,
            vec![(registration.as_slice().as_ptr() as usize, 79)]
        ),
        79
    );
    a.service_egress().unwrap();
    assert!(!state.lock().unwrap().held.is_empty());
    state.lock().unwrap().held.clear();
    a.collect_zero_copy();
    assert!(a.sockets[&client].completions.is_empty());
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    a.endpoint.abort(cid).unwrap();
    a.collect_zero_copy();
    assert_eq!(
        a.sockets[&client].completions.front(),
        Some(&Completion::SharedZeroCopy(0, 0, false))
    );
}

#[test]
fn external_backend_is_created_used_and_dropped_on_owner_thread() {
    struct LocalIo {
        thread: std::thread::ThreadId,
        _local: std::rc::Rc<()>,
        dropped: mpsc::SyncSender<()>,
        reclaims: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl PacketIo for LocalIo {
        fn reclaim_transmit(&mut self, budget: usize) -> std::io::Result<usize> {
            assert_eq!(self.thread, std::thread::current().id());
            assert_eq!(budget, BUDGET);
            self.reclaims
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        fn layer(&self) -> ntcp_io::PacketLayer {
            ntcp_io::PacketLayer::Ethernet
        }
        fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
            Ok(Some(1500))
        }
        fn max_packet_len(&self) -> Option<usize> {
            Some(1514)
        }
        fn receive(&mut self, _: &mut [u8]) -> std::io::Result<Option<usize>> {
            assert_eq!(self.thread, std::thread::current().id());
            Ok(None)
        }
        fn transmit(&mut self, _: &[u8]) -> std::io::Result<TxOutcome> {
            assert_eq!(self.thread, std::thread::current().id());
            Ok(TxOutcome::Submitted)
        }
    }
    impl Drop for LocalIo {
        fn drop(&mut self) {
            assert_eq!(self.thread, std::thread::current().id());
            self.dropped.send(()).unwrap();
        }
    }
    let original = std::thread::current().id();
    let (dropped, observed) = mpsc::sync_channel(1);
    let reclaims = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reclaimed = reclaims.clone();
    let runtime = Runtime::spawn(
        move || {
            assert_ne!(original, std::thread::current().id());
            let io = LocalIo {
                thread: std::thread::current().id(),
                _local: std::rc::Rc::new(()),
                dropped,
                reclaims,
            };
            let mut config = SocketConfig::new("external", Ipv4Addr::new(10, 73, 0, 2));
            config.io.prefix = Some(24);
            Owner::external_backend(
                &config,
                crate::EthernetPacketIo {
                    io: Box::new(io),
                    local_mac: [2; 6],
                    next_hop_mac: [4; 6],
                },
            )
        },
        false,
    )
    .unwrap();
    assert!(runtime.call(0, Op::New(SOCK_NONBLOCK)).unwrap().value > 0);
    runtime.stop();
    observed
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(reclaimed.load(std::sync::atomic::Ordering::Relaxed) > 0);
}

#[test]
fn concurrent_logical_sends_and_option_clone_keep_reserved_release_capacity() {
    let (mut a, _, client, _, _) = pair();
    attach(&mut a);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Flags(F_SETFL, 0)).unwrap();
    let registration = crate::RegisteredPayload::register(Payload::from_vec(vec![8; 37])).unwrap();
    let mut requests = Vec::new();
    let mut results = Vec::new();
    for _ in 0..2 {
        let (reply, result) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(
                Box::new(Op::Send(
                    vec![(registration.as_slice().as_ptr() as usize, 37), (1, 1)],
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
        requests.push(request);
        results.push(result);
    }
    assert_eq!(a.sockets[&client].zc_reserved, 2);
    assert!(a.sockets[&client].zc_leases.capacity() >= 2);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    assert!(a.sockets[&client].zc_leases.capacity() >= 2);
    for (request, result) in requests.iter_mut().zip(results) {
        assert!(a.service(request));
        assert_eq!(result.try_recv().unwrap().unwrap().value, 37);
    }
    assert_eq!(a.sockets[&client].zc_leases.len(), 2);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    a.endpoint.abort(cid).unwrap();
    a.collect_zero_copy();
    assert_eq!(
        a.sockets[&client].completions.front(),
        Some(&Completion::SharedZeroCopy(0, 1, false))
    );
    assert_eq!(a.sockets[&client].zc_reserved, 0);
}

#[test]
fn shared_backend_packet_bound_clips_selection_before_submission() {
    let (mut a, _, client, _, _) = pair();
    let state = attach_limit(&mut a, 512);
    a.execute(client, Op::Set(SOL_SOCKET, SO_ZEROCOPY, 1))
        .unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
        .unwrap();
    let registration =
        crate::RegisteredPayload::register(Payload::from_vec(vec![8; 1000])).unwrap();
    let pointer = registration.as_slice().as_ptr();
    assert_eq!(
        send_registered(&mut a, client, vec![(pointer as usize, 1000)]),
        1000
    );
    a.service_egress().unwrap();
    let state = state.lock().unwrap();
    let mut offset = 0;
    for packet in &state.held {
        assert!(packet.checked_len().unwrap() <= 512);
        for part in &packet.payload {
            assert_eq!(part.as_slice().as_ptr(), pointer.wrapping_add(offset));
            offset += part.len();
        }
    }
    assert_eq!(offset, 1000);
}
