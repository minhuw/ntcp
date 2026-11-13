use super::*;

fn close_full_listener(
    start: impl FnOnce() -> Owner + Send + 'static + std::panic::UnwindSafe,
    packet: bool,
) {
    let (initialized, initialization) = mpsc::sync_channel(1);
    let runtime = std::sync::Arc::new(
        Runtime::spawn(
            move || {
                let mut owner = start();
                let listener = owner.execute(0, Op::New(0)).unwrap().value as u64;
                owner
                    .execute(listener, Op::Bind(SocketAddr::new(owner.local, 8080)))
                    .unwrap();
                owner.execute(listener, Op::Listen(1)).unwrap();
                let mut waiters = Vec::new();
                for _ in 0..owner.request_limit() {
                    let (reply, rx) = mpsc::sync_channel(1);
                    let mut request = Request {
                        id: listener,
                        op: Op::Wait(Box::new(Op::Accept(0)), None),
                        reply,
                        deadline: None,
                        send: None,
                        closing: None,
                    };
                    assert!(!owner.admission_full(&request));
                    assert!(!owner.service(&mut request));
                    owner.pending.push_back(request);
                    waiters.push(rx);
                }
                assert_eq!(owner.pending.len(), owner.request_limit());
                initialized.send((listener, waiters)).unwrap();
                Ok(owner)
            },
            packet,
        )
        .unwrap(),
    );
    let (listener, waiters) = initialization.recv().unwrap();
    assert_eq!(runtime.call(0, Op::New(0)).unwrap_err(), EAGAIN);
    let worker = runtime.clone();
    let (done, completed) = mpsc::sync_channel(1);
    let join = std::thread::spawn(move || {
        done.send(worker.call(listener, Op::Close)).unwrap();
    });
    // No incoming traffic or capture is needed to close an idle listener.
    let result = completed.recv_timeout(std::time::Duration::from_secs(2));
    runtime.stop();
    join.join().unwrap();
    result
        .expect("close stranded behind blocking accepts")
        .unwrap();
    for waiter in waiters {
        assert_eq!(waiter.try_recv().unwrap().unwrap_err(), EBADF);
    }
}

#[test]
fn full_native_accept_queue_admits_close() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    close_full_listener(
        move || {
            let mut owner = Owner::with_config(
                local,
                (local, 32),
                [2; 32],
                None,
                SocketConfig::new("test", local).tcp,
            )
            .unwrap();
            // run() requires the Egress every runtime constructor enables.
            owner.enable_egress(1, None).unwrap();
            owner
        },
        false,
    );
}

#[cfg(feature = "packet-test")]
#[test]
fn full_packet_accept_queue_admits_close() {
    close_full_listener(
        || {
            Owner::packet((
                Ipv4Addr::new(192, 0, 2, 1),
                crate::packet_profile::Profile::Pipeline,
            ))
            .unwrap()
        },
        true,
    );
}

#[test]
fn teardown_and_ordinary_admission_have_independent_bounds() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let mut owner = Owner::with_config(
        local,
        (local, 32),
        [2; 32],
        None,
        SocketConfig::new("test", local).tcp,
    )
    .unwrap();
    let request = |op| Request {
        id: 1,
        op,
        reply: mpsc::sync_channel(1).0,
        deadline: None,
        send: None,
        closing: None,
    };
    for op in [Op::Accept(0), Op::Close] {
        for _ in 0..owner.request_limit() {
            let r = request(op.clone());
            assert!(!owner.admission_full(&r));
            owner.pending.push_back(r);
        }
        assert!(owner.admission_full(&request(op)));
    }
    assert_eq!(owner.pending.len(), 2 * owner.request_limit());
    assert!(owner.admission_full(&request(Op::Accept(0))));
    assert!(owner.admission_full(&request(Op::Close)));
}

// As Linux's __sys_listen, the backlog is clamped as an unsigned value to
// somaxconn, here the endpoint's connections: a negative one is the
// largest, and 0 is kept, a SYN queue and an accept queue of one each.
#[test]
fn listen_clamps_the_backlog_as_linux_does() {
    let local = Ipv4Addr::new(10, 73, 0, 2);
    let config = SocketConfig::new("test", local).tcp;
    let limit = config.max_connections;
    for (backlog, expected) in [(0, 0), (5, 5), (-1, limit), (i32::MAX, limit)] {
        let mut owner =
            Owner::with_config(local, (local, 32), [2; 32], None, config.clone()).unwrap();
        let listener = owner.execute(0, Op::New(0)).unwrap().value as u64;
        owner
            .execute(listener, Op::Bind(SocketAddr::new(owner.local, 8080)))
            .unwrap();
        owner.execute(listener, Op::Listen(backlog)).unwrap();
        let Handle::Listener(id) = owner.sockets[&listener].handle else {
            panic!("not listening");
        };
        assert_eq!(owner.endpoint.listener_queue_info(id), Ok((0, expected)));
    }
}
