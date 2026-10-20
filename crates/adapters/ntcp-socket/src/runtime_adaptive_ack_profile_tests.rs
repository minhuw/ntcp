// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Included by runtime_memory_tests: configured production PacketIo and reservations.
fn adaptive_peer(a: &mut Owner, packet: &[u8], syn: bool, mss: u16, payload: &[u8]) {
    let incoming = ntcp_ip::parse(packet, false).unwrap().ip;
    let ip = ntcp::IpMetadata {
        source: incoming.destination,
        destination: incoming.source,
    };
    let sent = segment(packet);
    let [hi, lo] = mss.to_be_bytes();
    let options = [
        2, 4, hi, lo, 1, 1, 4, 2, 1, 3, 3, 6, 34, 6, 0xab, 0xcd, 0x12, 0x34, 1, 1,
    ];
    let mut tcp = [0; 1024];
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: sent.header.destination_port,
            destination_port: sent.header.source_port,
            sequence: if syn { 100 } else { sent.header.acknowledgment },
            acknowledgment: sent.header.sequence.wrapping_add(
                sent.payload.len() as u32 + u32::from(sent.header.flags & ntcp::wire::SYN != 0),
            ),
            flags: ntcp::wire::ACK
                | if syn {
                    ntcp::wire::SYN
                } else {
                    ntcp::wire::PSH
                },
            window: if syn { 5840 } else { 257 },
            urgent_pointer: 0,
        },
        if syn { &options } else { &[] },
        payload,
        &mut tcp,
    )
    .unwrap();
    let reply = a
        .frame(
            ntcp::Transmit {
                tx_timestamp: None,
                connection: None,
                ip,
                len: n,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..n],
        )
        .unwrap();
    tfo_deliver(a, reply);
}

#[test]
fn adaptive_ack_profile_syn_only_vs_fresh_data_fin_and_timer() {
    for (total, close) in [(1000, true), (1900, true), (1900, false)] {
        let mut a = owner(
            1,
            upstream_runtime_adaptive_ack_profile_tests(
                "no-timestamps,budget224m,prealloc3,adaptive-ack",
            ),
            8,
        );
        let warm = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
            EINPROGRESS
        );
        let request = tfo_capture(&mut a);
        a.test_now = Some(11_000);
        adaptive_peer(
            &mut a,
            &request,
            true,
            if total == 1000 { 1460 } else { 940 },
            &[],
        );
        assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
        // Keep warmup idle so no unrelated FIN timer can affect the trace.
        let client = new(&mut a, SOCK_NONBLOCK);
        a.test_now = Some(21_000);
        let data = vec![7; total];
        let syn_len = if total == 1000 { 1000 } else { 900 };
        assert_eq!(
            a.execute(client, tfo_send(&data, MSG_FASTOPEN))
                .unwrap()
                .value,
            syn_len as i32
        );
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).payload, &data[..syn_len]);
        assert_eq!(segment(&syn).header.flags, ntcp::wire::SYN);
        assert_eq!(
            segment(&syn).options.fast_open.unwrap().as_bytes(),
            [0xab, 0xcd, 0x12, 0x34]
        );
        a.test_now = Some(41_000);
        adaptive_peer(
            &mut a,
            &syn,
            true,
            if total == 1000 { 940 } else { 1460 },
            &[],
        );
        if total == 1900 {
            // Complete the nonblocking short send through the real adapter, with Nagle unchanged.
            assert_eq!(
                a.execute(client, tfo_send(&data[syn_len..], MSG_FASTOPEN))
                    .unwrap()
                    .value,
                1000
            );
        }
        let sent = tfo_capture(&mut a);
        assert_eq!(segment(&sent).payload, &data[syn_len..]);
        assert_eq!(
            segment(&sent).header.sequence,
            segment(&syn)
                .header
                .sequence
                .wrapping_add(1 + syn_len as u32)
        );
        assert_eq!(segment(&sent).header.flags & ntcp::wire::SYN, 0);
        assert!(!a.endpoint.is_output_reserved(cid(&a, client)));
        tfo_no_output(&mut a);
        a.test_now = Some(61_000);
        adaptive_peer(&mut a, &sent, false, 0, &[9; 500]);
        let ack = tfo_capture(&mut a);
        assert_eq!(segment(&ack).header.flags, ntcp::wire::ACK);
        assert_eq!(segment(&ack).header.acknowledgment, 601);
        assert!(segment(&ack).payload.is_empty());
        tfo_no_output(&mut a);
        assert_eq!(a.execute(client, Op::Read(4096)).unwrap().bytes, [9; 500]);
        tfo_no_output(&mut a);
        // A real receive followed by an accepted send still enables interactive delay.
        a.test_now = Some(62_000);
        a.execute(client, Op::Write(b"request".to_vec())).unwrap();
        let request = tfo_capture(&mut a);
        assert_eq!(segment(&request).payload, b"request");
        a.test_now = Some(63_000);
        adaptive_peer(&mut a, &request, false, 0, &[8; 500]);
        tfo_no_output(&mut a);
        assert_eq!(a.execute(client, Op::Read(4096)).unwrap().bytes, [8; 500]);
        tfo_no_output(&mut a);
        if close {
            a.test_now = Some(65_000);
            a.execute(client, Op::Close).unwrap();
            let fin = tfo_capture(&mut a);
            assert_eq!(
                segment(&fin).header.flags,
                ntcp::wire::FIN | ntcp::wire::ACK
            );
            assert_eq!(segment(&fin).header.acknowledgment, 1101);
            assert!(segment(&fin).payload.is_empty());
        } else {
            let deadline = a.endpoint.next_deadline().unwrap();
            assert_eq!(deadline, 103_000); // Initial 40ms ATO, not the 200ms maximum.
            a.test_now = Some(deadline - 1);
            a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
            tfo_no_output(&mut a);
            a.test_now = Some(deadline);
            a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
            let ack = tfo_capture(&mut a);
            assert_eq!(segment(&ack).header.flags, ntcp::wire::ACK);
            assert_eq!(segment(&ack).header.acknowledgment, 1101);
            assert!(segment(&ack).payload.is_empty());
        }
        tfo_no_output(&mut a);
    }
}

fn upstream_runtime_adaptive_ack_profile_tests(options: &str) -> crate::packet_profile::Profile {
    crate::packet_profile::profile(&format!(
        "upstream,local=192.0.2.1{}{}",
        if options.is_empty() { "" } else { "," },
        options
    ))
    .unwrap()
    .1
}

// Bounded owner-loop slice using the same pre-output admission as run().
fn adaptive_tfo_owner_turn(a: &mut Owner) -> Vec<Vec<u8>> {
    if a.reservation.is_none() {
        a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
    }
    receive(a);
    a.events();
    let mut after_output = Vec::new();
    a.service_before_output(&mut after_output);
    a.service_egress().unwrap();
    a.events();
    for (mut request, retried) in after_output {
        if retried || !a.service(&mut request) {
            a.pending.push_back(request);
        }
    }
    let mut packets = Vec::new();
    loop {
        match a.execute(0, Op::Capture(65535)) {
            Ok(reply) => packets.push(reply.bytes),
            Err(EAGAIN) => break,
            Err(error) => panic!("capture: {error}"),
        }
    }
    packets
}

// Blocking writers initialize the ACK engine, not stream receive history.
#[test]
fn adaptive_ack_blocking_tfo_writer_vs_nonblocking() {
    for total in [1000usize, 1900] {
        let syn_len = if total == 1000 { 1000 } else { 900 };
        for mode in [
            "sendto",
            "sendmsg-multi-iov",
            "deferred-sendto",
            "nonblocking-multi-iov",
        ] {
            let blocking = mode != "nonblocking-multi-iov";
            let mut a = owner(
                1,
                upstream_runtime_adaptive_ack_profile_tests(
                    "no-timestamps,budget224m,prealloc3,adaptive-ack",
                ),
                8,
            );
            // Isolate the fixture's second connection: identical cached cookie/MSS,
            // without unrelated warmup close/FIN timers.
            let warm = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(
                a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
                EINPROGRESS
            );
            let request = tfo_capture(&mut a);
            a.test_now = Some(11_000);
            adaptive_peer(
                &mut a,
                &request,
                true,
                if total == 1000 { 1460 } else { 940 },
                &[],
            );
            assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
            tfo_no_output(&mut a);

            // The nonblocking multi-iov fixture uses MSG_DONTWAIT, not O_NONBLOCK.
            let client = new(&mut a, 0);
            if mode == "deferred-sendto" {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
                    .unwrap();
                assert_eq!(
                    a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                        .unwrap()
                        .value,
                    0
                );
                tfo_no_output(&mut a);
            }
            a.test_now = Some(21_000);
            let data: Vec<u8> = (0..total).map(|n| (n % 251) as u8).collect();
            let iov = if mode.contains("multi-iov") && total == 1900 {
                vec![
                    (data.as_ptr() as usize, 500),
                    (data[500..].as_ptr() as usize, 1000),
                    (data[1500..].as_ptr() as usize, 400),
                ]
            } else {
                vec![(data.as_ptr() as usize, data.len())]
            };
            let op = Op::SendTo(
                iov,
                if mode == "deferred-sendto" {
                    0
                } else {
                    MSG_FASTOPEN | MSG_NOSIGNAL | if blocking { 0 } else { MSG_DONTWAIT }
                },
                Some("192.0.2.2:8080".parse().unwrap()),
                None,
            );
            let (reply, rx) = mpsc::sync_channel(1);
            if blocking {
                let mut request = Request {
                    id: client,
                    op: Op::Wait(Box::new(op), None),
                    reply,
                    deadline: None,
                    send: None,
                    closing: None,
                };
                assert!(!a.service(&mut request));
                assert_eq!(request.send.as_ref().unwrap().accepted, syn_len);
                a.pending.push_back(request);
            } else {
                assert_eq!(a.execute(client, op).unwrap().value, syn_len as i32);
            }
            let syn = tfo_capture(&mut a);
            let initial = segment(&syn).header.sequence;
            assert_eq!(segment(&syn).header.flags, ntcp::wire::SYN);
            assert_eq!(segment(&syn).payload, &data[..syn_len]);
            assert_eq!(
                segment(&syn).options.fast_open.unwrap().as_bytes(),
                [0xab, 0xcd, 0x12, 0x34]
            );
            if blocking {
                assert!(adaptive_tfo_owner_turn(&mut a).is_empty());
                assert!(rx.try_recv().is_err());
                assert_eq!(
                    a.pending.front().unwrap().send.as_ref().unwrap().accepted,
                    syn_len
                );
            }
            a.test_now = Some(41_000);
            adaptive_peer(&mut a, &syn, true, 1460, &[]);
            let mut handshake = adaptive_tfo_owner_turn(&mut a);
            if blocking {
                assert_eq!(rx.try_recv().unwrap().unwrap().value, total as i32);
                assert!(a.pending.is_empty());
            } else if total == 1900 {
                // The actual nonblocking fixture captures the handshake ACK first,
                // then submits the remaining two iovecs as a separate syscall.
                assert_eq!(
                    a.execute(
                        client,
                        Op::SendTo(
                            vec![
                                (data[900..].as_ptr() as usize, 600),
                                (data[1500..].as_ptr() as usize, 400)
                            ],
                            MSG_FASTOPEN | MSG_DONTWAIT | MSG_NOSIGNAL,
                            Some("192.0.2.2:8080".parse().unwrap()),
                            None
                        )
                    )
                    .unwrap()
                    .value,
                    1000
                );
            }
            handshake.extend(adaptive_tfo_owner_turn(&mut a));
            let piggyback = blocking && total == 1900;
            assert_eq!(
                handshake.len(),
                if !blocking && total == 1900 { 2 } else { 1 },
                "{mode}/{total}"
            );
            if !piggyback {
                assert_eq!(segment(&handshake[0]).header.flags, ntcp::wire::ACK);
                assert!(segment(&handshake[0]).payload.is_empty());
                assert_eq!(
                    segment(&handshake[0]).header.sequence.wrapping_sub(initial),
                    1 + syn_len as u32
                );
            }
            let tail = handshake.last().unwrap();
            assert_eq!(segment(tail).payload, &data[syn_len..]);
            assert_eq!(
                segment(tail).header.sequence.wrapping_sub(initial),
                1 + syn_len as u32
            );
            assert_eq!(
                segment(tail).header.flags,
                ntcp::wire::ACK | if total == 1900 { ntcp::wire::PSH } else { 0 }
            );
            assert_eq!(segment(tail).header.acknowledgment, 101);
            for packet in &handshake {
                let tcp = segment(packet);
                assert_eq!(tcp.header.source_port, segment(&syn).header.source_port);
                assert_eq!(tcp.header.destination_port, 8080);
                assert_eq!(
                    ntcp_ip::parse(packet, false).unwrap().ip,
                    ntcp_ip::parse(&syn, false).unwrap().ip
                );
            }
            assert!(!a.endpoint.is_output_reserved(cid(&a, client)));
            assert!(adaptive_tfo_owner_turn(&mut a).is_empty());

            a.test_now = Some(61_000);
            adaptive_peer(&mut a, tail, false, 0, &[9; 500]);
            let response = adaptive_tfo_owner_turn(&mut a);
            assert_eq!(response.len(), usize::from(!piggyback), "{mode}/{total}");
            if !piggyback {
                let ack = segment(&response[0]);
                assert_eq!(ack.header.flags, ntcp::wire::ACK);
                assert!(ack.payload.is_empty());
                assert_eq!(ack.header.sequence.wrapping_sub(initial), 1 + total as u32);
                assert_eq!(ack.header.acknowledgment, 601);
            }
            assert_eq!(a.execute(client, Op::Read(4096)).unwrap().bytes, [9; 500]);
            assert!(adaptive_tfo_owner_turn(&mut a).is_empty());
            a.test_now = Some(63_000);
            a.execute(client, Op::Close).unwrap();
            let closed = adaptive_tfo_owner_turn(&mut a);
            assert_eq!(closed.len(), 1);
            let fin = segment(&closed[0]);
            assert_eq!(fin.header.flags, ntcp::wire::FIN | ntcp::wire::ACK);
            assert_eq!(fin.header.sequence.wrapping_sub(initial), 1 + total as u32);
            assert_eq!(fin.header.acknowledgment, 601);
            assert!(fin.payload.is_empty());
            assert!(adaptive_tfo_owner_turn(&mut a).is_empty());
            for (stage, packets) in [
                ("after_synack", &handshake),
                ("response_before_read_close", &response),
                ("after_read_close", &closed),
            ] {
                for packet in packets {
                    let tcp = segment(packet);
                    println!(
                        "{{\"mode\":\"{mode}\",\"stage\":\"{stage}\",\"time_us\":{},\"seq\":{},\"ack\":{},\"flags\":{},\"len\":{}}}",
                        if stage == "after_synack" {
                            41_000
                        } else if stage == "response_before_read_close" {
                            61_000
                        } else {
                            63_000
                        },
                        tcp.header.sequence.wrapping_sub(initial),
                        tcp.header.acknowledgment.wrapping_sub(100),
                        tcp.header.flags,
                        tcp.payload.len()
                    );
                }
            }
        }
    }
}

#[test]
fn adaptive_ack_cancelled_fast_open_waiter_does_not_initialize_later_handshake() {
    for error in [ECANCELED, EAGAIN, EFAULT] {
        let mut a = owner(
            1,
            upstream_runtime_adaptive_ack_profile_tests("no-timestamps,budget224m,prealloc3,adaptive-ack"),
            8,
        );
        let warm = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
            EINPROGRESS
        );
        let request = tfo_capture(&mut a);
        a.test_now = Some(11_000);
        adaptive_peer(&mut a, &request, true, 940, &[]);
        tfo_capture(&mut a);
        let client = new(&mut a, 0);
        let bytes = [1; 1900];
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(tfo_send(&bytes, MSG_FASTOPEN)), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        assert!(request.send.as_ref().unwrap().waiting_fast_open());
        assert_eq!(request.send.as_ref().unwrap().accepted, 900);
        let syn = tfo_capture(&mut a);
        if error == EAGAIN {
            request.deadline = Some(Instant::now());
            assert!(a.service(&mut request));
            assert_eq!(rx.try_recv().unwrap().unwrap_err(), EAGAIN);
        } else {
            let mut send = request.send.take().unwrap();
            assert_eq!(
                a.finish_send(client, &mut send, Err(error)).unwrap_err(),
                error
            );
        }
        a.test_now = Some(41_000);
        adaptive_peer(&mut a, &syn, true, 1460, &[]);
        tfo_capture(&mut a); // Handshake only, no retained tail.
        a.execute(client, Op::Write(vec![2; 1000])).unwrap();
        let tail = tfo_capture(&mut a);
        assert_eq!(segment(&tail).payload, [2; 1000]);
        a.test_now = Some(61_000);
        adaptive_peer(&mut a, &tail, false, 0, &[9; 500]);
        let ack = tfo_capture(&mut a);
        assert_eq!(segment(&ack).header.flags, ntcp::wire::ACK);
        assert_eq!(segment(&ack).header.acknowledgment, 601);
    }
}

// Deterministic inq/server.pkt continuation under the common coalescing baseline
// and an explicit test-only eager-update control, including reserved output.
#[test]
fn upstream_inq_server_read_window_ack_and_fin_schedules() {
    fn input(a: &mut Owner, h: ntcp::wire::Header, options: &[u8], payload: &[u8]) {
        let ip = ntcp::IpMetadata {
            source: Ipv4Addr::new(192, 0, 2, 2).into(),
            destination: Ipv4Addr::new(192, 0, 2, 1).into(),
        };
        let mut tcp = vec![0; 60 + payload.len()];
        let len = ntcp::wire::encode(ip, h, options, payload, &mut tcp).unwrap();
        let bytes = a
            .frame(
                ntcp::Transmit {
                    tx_timestamp: None,
                    connection: None,
                    ip,
                    len,
                    hop_limit: 64,
                    dscp: 0,
                    ecn: 0,
                    ipv4_options: Default::default(),
                },
                &tcp[..len],
            )
            .unwrap();
        tfo_deliver(a, bytes);
    }
    fn snapshot(a: &Owner, server: u64, coalesce: bool, schedule: &str, stage: &str) {
        let id = cid(a, server);
        let info = a.endpoint.transport_info(id).unwrap();
        println!(
            "{{\"control_coalesce\":{coalesce},\"schedule\":\"{schedule}\",\"stage\":\"{stage}\",\"caller_time_us\":{},\"receive_used\":{},\"readable\":{},\"state\":\"{:?}\",\"reserved\":{},\"egress_held\":{}}}",
            a.now(),
            info.receive_used,
            a.endpoint.readable_bytes(id).unwrap(),
            info.state,
            a.endpoint.is_output_reserved(id),
            a.egress.as_ref().unwrap().has_held()
        );
        let free = info.receive_capacity - info.receive_used;
        println!(
            "{{\"control_coalesce\":{coalesce},\"schedule\":\"{schedule}\",\"stage\":\"{stage}-window-state\",\"caller_time_us\":{},\"free_capacity\":{free},\"floor_free_to_scale\":{},\"one_mss_read_threshold\":{},\"endpoint_output_ready\":{}}}",
            a.now(),
            free / 256 * 256,
            info.mss,
            a.endpoint.ready_connections().any(|ready| ready == id)
        );
    }
    fn output(
        a: &mut Owner,
        coalesce: bool,
        schedule: &str,
        stage: &str,
    ) -> Vec<ntcp::wire::Header> {
        a.service_egress().unwrap();
        let mut headers = Vec::new();
        loop {
            let reply = match a.execute(0, Op::Capture(65535)) {
                Ok(reply) => reply,
                Err(EAGAIN) => break,
                Err(error) => panic!("capture failed: {error}"),
            };
            let tcp = segment(&reply.bytes);
            assert!(tcp.payload.is_empty());
            assert_eq!(tcp.header.flags, ntcp::wire::ACK);
            let h = tcp.header;
            println!(
                "{{\"control_coalesce\":{coalesce},\"schedule\":\"{schedule}\",\"stage\":\"{stage}\",\"caller_time_us\":{},\"ack\":{},\"window_field\":{},\"encoded_right_edge\":{}}}",
                a.now(),
                h.acknowledgment,
                h.window,
                h.acknowledgment.wrapping_add(u32::from(h.window) << 8)
            );
            headers.push(h);
        }
        headers
    }
    fn recvmsg(a: &mut Owner, server: u64, count: usize, expected_inq: i32) {
        // Same peek -> post-read INQ/cmsg construction -> consume sequence as
        // managed recvmsg/read_into, without a background owner or wall clock.
        let staged = a.execute(server, Op::Peek(count)).unwrap().bytes;
        assert_eq!(staged, vec![7; count]);
        let inq = a.execute(server, Op::Inq(count)).unwrap();
        assert_ne!(inq.timeout_us, 0);
        assert_eq!(inq.value, expected_inq);
        let mut control = [0u8; 32];
        let mut message: msghdr = unsafe { std::mem::zeroed() };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        copy_recvmsg_timestamp(&mut message, message, Some(inq.value), None).unwrap();
        assert_eq!(message.msg_flags, 0);
        assert_eq!(message.msg_controllen, 24);
        assert_eq!(usize::from_ne_bytes(control[..8].try_into().unwrap()), 20);
        assert_eq!(
            i32::from_ne_bytes(control[8..12].try_into().unwrap()),
            IPPROTO_TCP
        );
        assert_eq!(
            i32::from_ne_bytes(control[12..16].try_into().unwrap()),
            TCP_INQ
        );
        assert_eq!(
            i32::from_ne_bytes(control[16..20].try_into().unwrap()),
            expected_inq
        );
        assert_eq!(a.execute(server, Op::Read(count)).unwrap().bytes, staged);
        println!(
            "{{\"stage\":\"recvmsg-cmsg\",\"caller_time_us\":{},\"read_bytes\":{count},\"inq\":{expected_inq}}}",
            a.now()
        );
    }
    for coalesce in [false, true] {
        for schedule in [
            "after-each-read",
            "after-both-reads",
            "after-fin",
            "reserved-before-fin",
        ] {
            if coalesce && schedule == "reserved-before-fin" {
                continue; // The common baseline schedules no read-only output to reserve.
            }
            let profile = upstream_runtime_adaptive_ack_profile_tests("");
            let mut cfg = crate::packet_profile::config(profile);
            assert!(cfg.connection.coalesce_read_window_updates);
            // Retain all four eager schedules without adding a public profile option.
            cfg.connection.coalesce_read_window_updates = coalesce;
            assert_eq!(cfg.connection.receive_capacity, 8 * 1024 * 1024);
            assert!(cfg.connection.adaptive_ack);
            assert_eq!(cfg.connection.delayed_ack_us, 200_000);
            assert_eq!(cfg.connection.coalesce_read_window_updates, coalesce);
            let mut a = owner(1, profile, 8);
            if !coalesce {
                a.defaults = cfg.clone();
                a.endpoint = Endpoint::new(cfg, [42; 32], 0, |_| true).unwrap();
                a.enable_egress(2, crate::packet_profile::gso(profile)).unwrap();
            }
            a.test_now = Some(0);
            let listener = new(&mut a, SOCK_NONBLOCK);
            a.execute(listener, Op::Set(SOL_SOCKET, SO_REUSEADDR, 1))
                .unwrap();
            a.execute(listener, Op::Bind("192.0.2.1:8080".parse().unwrap()))
                .unwrap();
            a.execute(listener, Op::Listen(1)).unwrap();
            let mut h = ntcp::wire::Header {
                source_port: 50000,
                destination_port: 8080,
                sequence: 0,
                acknowledgment: 0,
                flags: ntcp::wire::SYN,
                window: 32792,
                urgent_pointer: 0,
            };
            input(&mut a, h, &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 10], &[]);
            let synack = tfo_capture(&mut a);
            let synack = segment(&synack);
            assert_eq!(synack.header.flags, ntcp::wire::SYN | ntcp::wire::ACK);
            assert_eq!(synack.options.window_scale, Some(8));
            h.sequence = 1;
            h.acknowledgment = synack.header.sequence.wrapping_add(1);
            h.flags = ntcp::wire::ACK;
            h.window = 514;
            a.test_now = Some(10_000);
            input(&mut a, h, &[], &[]);
            let server = a
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            a.execute(server, Op::Set(IPPROTO_TCP, TCP_INQ, 1)).unwrap();
            let id = cid(&a, server);
            let info = a.endpoint.transport_info(id).unwrap();
            assert!(!info.timestamps_negotiated);
            assert_eq!(info.receive_window_scale, 8);
            assert_eq!(info.send_window_scale, 10);
            assert_eq!(info.mss, 1000);
            input(&mut a, h, &[], &[7; 10_000]);
            let initial = output(&mut a, coalesce, schedule, "first-10k-ack");
            assert_eq!(initial.len(), 1);
            assert_eq!(initial[0].acknowledgment, 10001);
            assert_eq!(initial[0].window, 32728);
            assert!(u32::from(initial[0].window) * 256 <= 8 * 1024 * 1024 - 10000);
            let edge = initial[0].acknowledgment + (u32::from(initial[0].window) << 8);
            snapshot(&a, server, coalesce, schedule, "before-reads");
            recvmsg(&mut a, server, 2000, 8000);
            snapshot(&a, server, coalesce, schedule, "after-2k-read");
            if schedule == "after-each-read" {
                let updates = output(&mut a, coalesce, schedule, "after-2k-read");
                assert_eq!(updates.len(), usize::from(!coalesce));
                if !coalesce {
                    assert_eq!(updates[0].acknowledgment, 10001);
                    let advanced = updates[0].acknowledgment + (u32::from(updates[0].window) << 8);
                    assert!(advanced > edge);
                    assert_eq!(advanced - edge, 2048);
                    assert_eq!(updates[0].window, 32736);
                    // The prior floor withheld 240 bytes; the new floor withholds
                    // 192, so freeing 2000 safely advances the edge by 2048.
                    assert_eq!((8 * 1024 * 1024 - 10000) % 256, 240);
                    assert_eq!((8 * 1024 * 1024 - 8000) % 256, 192);
                    assert!(advanced <= 10001 + 8 * 1024 * 1024 - 8000);
                }
            }
            recvmsg(&mut a, server, 8000, 0);
            snapshot(&a, server, coalesce, schedule, "after-8k-read");
            if matches!(schedule, "after-each-read" | "after-both-reads") {
                let updates = output(&mut a, coalesce, schedule, "after-8k-read");
                assert_eq!(updates.len(), usize::from(!coalesce));
                if !coalesce {
                    assert_eq!(updates[0].acknowledgment, 10001);
                }
            }
            let reserved = if schedule == "reserved-before-fin" {
                let mut bytes = [0; 64];
                let (selected, attempt) = a
                    .endpoint
                    .poll_reserved_transmit_for(a.now(), id, &mut bytes, BUDGET)
                    .unwrap();
                let selected = selected.packet.unwrap();
                let selected = ntcp::wire::parse(selected.ip, &bytes[..selected.len]).unwrap();
                assert_eq!(selected.header.acknowledgment, 10001);
                println!(
                    "{{\"control_coalesce\":false,\"schedule\":\"{schedule}\",\"stage\":\"selected-before-fin\",\"caller_time_us\":{},\"ack\":{},\"window_field\":{}}}",
                    a.now(),
                    selected.header.acknowledgment,
                    selected.header.window
                );
                assert!(a.endpoint.is_output_reserved(id));
                Some(attempt.unwrap())
            } else {
                None
            };
            h.sequence = 10001;
            h.flags |= ntcp::wire::FIN;
            input(&mut a, h, &[], &[7; 10_000]);
            snapshot(&a, server, coalesce, schedule, "fin-input-attempt");
            if let Some(attempt) = reserved {
                assert_eq!(a.endpoint.state(id).unwrap(), State::Established);
                assert_eq!(a.endpoint.readable_bytes(id).unwrap(), 0);
                assert!(a.egress.as_ref().unwrap().has_held());
                assert_eq!(a.execute(server, Op::Read(1)).unwrap_err(), EAGAIN);
                // Commit the already-selected ACK=10001, then permit FIN input.
                assert!(a.endpoint.accept_transmit(a.now(), attempt).unwrap());
                println!(
                    "{{\"control_coalesce\":false,\"schedule\":\"{schedule}\",\"stage\":\"old-ack-commit-before-fin-processing\",\"caller_time_us\":{},\"ack\":10001}}",
                    a.now()
                );
                receive(&mut a);
                snapshot(
                    &a,
                    server,
                    coalesce,
                    schedule,
                    "fin-replayed-after-old-ack-commit",
                );
            }
            assert_eq!(a.endpoint.state(id).unwrap(), State::CloseWait);
            assert_eq!(a.endpoint.transport_info(id).unwrap().receive_used, 10000);
            assert_eq!(a.endpoint.readable_bytes(id).unwrap(), 10000);
            let final_ack = output(&mut a, coalesce, schedule, "fin-ack");
            assert_eq!(final_ack.len(), 1);
            assert_eq!(final_ack[0].acknowledgment, 20002);
            recvmsg(&mut a, server, 10000, 1);
            assert_eq!(a.execute(server, Op::Read(2000)).unwrap().value, 0);
            snapshot(&a, server, coalesce, schedule, "eof");
            assert!(output(&mut a, coalesce, schedule, "after-eof").is_empty());
        }
    }
}
