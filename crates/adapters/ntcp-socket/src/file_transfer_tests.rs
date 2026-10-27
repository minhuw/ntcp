// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::large_write_tests::advance;
use super::timestamp_tests::timestamp_set;
use super::*;
use crate::timestamping as ts;

#[test]
fn transfer_reserves_bytes_and_timestamp_metadata_before_pipe_consumption() {
    let (mut a, mut b, client, server, _) = pair();
    let mut source = [-1; 2];
    let mut staging = [-1; 2];
    unsafe {
        assert_eq!(
            syscall(SYS_pipe2, source.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(
            syscall(SYS_pipe2, staging.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(syscall(SYS_write, source[1], b"abc".as_ptr(), 3), 3);
    }
    let _fds: Vec<_> = source.into_iter().chain(staging).map(Retained).collect();
    let queued = || {
        let mut count = 0i32;
        assert_eq!(
            unsafe { syscall(SYS_ioctl, source[0], FIONREAD, &mut count) },
            0
        );
        count
    };
    let op = Op::Transfer {
        source: source[0],
        staging,
        offset: None,
        count: 3,
        flags: MSG_MORE,
    };
    a.execute(client, Op::Write(vec![7; BYTES])).unwrap();
    assert_eq!(a.execute(client, op.clone()).unwrap_err(), EAGAIN);
    assert_eq!(queued(), 3);
    pump(&mut a, &mut b);
    while b.execute(server, Op::Read(BYTES)).is_ok() {}
    advance(&mut a, &mut b);
    a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 1))
        .unwrap();
    timestamp_set(
        &mut a,
        client,
        ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_ACK | ts::SOFTWARE | ts::OPT_TSONLY,
    );
    // Exhaust the small receive metadata budget without touching the pipe.
    let mut records = 0;
    loop {
        match a.execute(client, Op::WriteFlags(vec![9], MSG_MORE)) {
            Ok(_) => {
                records += 1;
                assert!(records < 128);
            }
            Err(error) => {
                assert_eq!(error, ENOBUFS);
                break;
            }
        }
    }
    assert_eq!(a.execute(client, op.clone()).unwrap_err(), ENOBUFS);
    assert_eq!(queued(), 3);
    a.execute(client, Op::Set(SOL_SOCKET, SO_RCVBUF, 65536))
        .unwrap();
    assert_eq!(a.execute(client, op.clone()).unwrap().value, 3);
    assert_eq!(queued(), 0);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(
        a.endpoint.send_progress(cid).unwrap().queued_end,
        BYTES as u64 + records + 3
    );
    assert_eq!(
        a.sockets[&client].timestamps.reserved(),
        (records as usize + 1) * 3
    );
    // Isolate MORE from the earlier large send's outstanding PUSH boundary.
    let (mut fresh, _, client, _, _) = pair();
    assert_eq!(
        unsafe { syscall(SYS_write, source[1], b"abc".as_ptr(), 3) },
        3
    );
    fresh
        .execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 2))
        .unwrap();
    assert_eq!(fresh.execute(client, op.clone()).unwrap().value, 3);
    assert_eq!(queued(), 0);
    let mut packet = [0; 1480];
    assert!(
        fresh
            .endpoint
            .poll_transmit(fresh.now(), &mut packet, BUDGET)
            .unwrap()
            .packet
            .is_none()
    );
    let Handle::Connection(cid) = fresh.sockets[&client].handle else {
        panic!()
    };
    let goal = send::batch_goal(&fresh.endpoint.transport_info(cid).unwrap());
    assert_eq!(
        fresh
            .execute(client, Op::WriteFlags(vec![8; goal], MSG_MORE))
            .unwrap()
            .value as usize,
        goal - 3
    );
    assert_eq!(
        unsafe { syscall(SYS_write, source[1], b"x".as_ptr(), 1) },
        1
    );
    assert_eq!(fresh.execute(client, op.clone()).unwrap_err(), EAGAIN);
    assert_eq!(queued(), 1); // A new batch must reject before consuming native input.
    fresh
        .execute(client, Op::Set(IPPROTO_TCP, TCP_NOTSENT_LOWAT, 0))
        .unwrap();
    assert_eq!(fresh.execute(client, op).unwrap().value, 1);
    assert_eq!(queued(), 0);
}

#[test]
fn freebind_local_nonlocal_policy_and_passive_snapshot() {
    let mut a = owner(2);
    let nonlocal: SocketAddr = "198.51.100.17:18000".parse().unwrap();
    let id = new(&mut a, 0);
    assert_eq!(
        a.execute(id, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        0
    );
    assert_eq!(
        a.execute(id, Op::Bind(nonlocal)).unwrap_err(),
        EADDRNOTAVAIL
    );
    a.execute(id, Op::Set(IPPROTO_IP, IP_FREEBIND, 1)).unwrap();
    a.execute(id, Op::Bind(nonlocal)).unwrap();
    assert_eq!(a.execute(id, Op::Name(false)).unwrap().addr, Some(nonlocal));
    // Binding permission must not grant a new backend source route.
    assert!(
        a.execute(id, Op::Connect("10.73.0.3:18000".parse().unwrap()))
            .is_err()
    );
    a.execute(id, Op::Listen(1)).unwrap();

    let mut b = owner(3);
    let listener = new(&mut b, 0);
    b.execute(listener, Op::Set(IPPROTO_IP, IP_FREEBIND, 1))
        .unwrap();
    b.execute(listener, Op::Bind("10.73.0.3:18001".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(1)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("10.73.0.3:18001".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    pump(&mut a, &mut b);
    b.execute(listener, Op::Set(IPPROTO_IP, IP_FREEBIND, 0))
        .unwrap();
    let child = b.execute(listener, Op::Accept(0)).unwrap().value as u64;
    assert_eq!(
        b.execute(child, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        1
    );
    assert_eq!(
        b.execute(listener, Op::Get(IPPROTO_IP, IP_FREEBIND))
            .unwrap()
            .value,
        0
    );
}

#[test]
fn transfer_and_external_native_reader_partition_pipe_bytes() {
    let (mut a, mut b, client, server, _) = pair();
    let mut source = [-1; 2];
    let mut staging = [-1; 2];
    unsafe {
        assert_eq!(
            syscall(SYS_pipe2, source.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(
            syscall(SYS_pipe2, staging.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(
            syscall(SYS_write, source[1], [7u8; 4096].as_ptr(), 4096),
            4096
        );
        assert_eq!(syscall(SYS_close, source[1]), 0);
    }
    let _fds: Vec<_> = [source[0], staging[0], staging[1]]
        .into_iter()
        .map(Retained)
        .collect();
    let start = Arc::new(std::sync::Barrier::new(2));
    let reader_start = start.clone();
    let reader = std::thread::spawn(move || {
        let mut count = 0;
        let mut bytes = [0u8; 13];
        reader_start.wait();
        loop {
            let n = raw(unsafe { syscall(SYS_read, source[0], bytes.as_mut_ptr(), bytes.len()) })
                .unwrap() as usize;
            if n == 0 {
                break;
            }
            assert!(bytes[..n].iter().all(|&b| b == 7));
            count += n;
            std::thread::yield_now();
        }
        count
    });
    start.wait();
    let mut sent = 0;
    loop {
        let n = a
            .transfer_once(client, source[0], staging, None, 19, MSG_MORE)
            .unwrap();
        if n == 0 {
            break;
        }
        assert!(n > 0);
        sent += n as usize;
        std::thread::yield_now();
    }
    assert_eq!(sent + reader.join().unwrap(), 4096);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(
        a.endpoint.send_progress(cid).unwrap().queued_end,
        sent as u64
    );
    if sent != 0 {
        a.endpoint
            .finish_send(cid, sent as u64, false, false, true)
            .unwrap();
        pump(&mut a, &mut b);
        let received = b.execute(server, Op::Read(BYTES)).unwrap();
        assert_eq!(received.bytes, vec![7; sent]);
    }
}
