use super::*;

fn adaptive_config() -> ConnectionConfig {
    ConnectionConfig {
        adaptive_ack: true,
        ..config(8192, 1000)
    }
}

fn data(c: &mut Connection, now: Instant, payload: &[u8]) {
    inject(c, now, c.receive.next(), c.snd_nxt, ACK, 8192, payload);
}

fn selected(c: &mut Connection, now: Instant) -> Departure {
    c.transmit_selected(now, &mut [0; 2048], true)
        .unwrap()
        .expect("selected output");
    c.last_departure.take().unwrap()
}

#[test]
fn startup_response_delayed_fin_and_timer_in_both_clock_units() {
    for units in [1_000_000, 1_000_000_000] {
        for fin in [false, true] {
            let mut cfg = adaptive_config();
            cfg.timebase.units_per_second = units;
            let ticks = |us| cfg.timebase.ticks_from_us(us);
            let (mut a, _) = pair(cfg.clone(), 100);
            assert_eq!(a.ack_ato, ticks(40_000));
            for (i, expected) in [(0, 3), (1, 2)] {
                data(&mut a, ticks(100 + i), b"request");
                assert!(a.ack_pending);
                packet(&mut a, ticks(100 + i));
                assert_eq!(a.ack_quick, expected);
            }
            a.read(&mut [0; 32]).unwrap();
            assert!(!a.ack_interactive);
            a.write(b"response").unwrap();
            assert!(!a.ack_interactive);
            assert_eq!(
                a.transmit(ticks(102), &mut [0; 19]),
                Err(Error::OutputTooSmall)
            );
            assert!(!a.ack_interactive);
            packet(&mut a, ticks(102));
            assert!(a.ack_interactive);
            data(&mut a, ticks(103), b"last");
            assert!(!a.ack_pending);
            let deadline = ticks(40_103);
            assert_eq!(a.ack_deadline, Some(deadline));
            assert_eq!(a.transmit(ticks(104), &mut [0; 2048]), Ok(None));
            if fin {
                a.read(&mut [0; 32]).unwrap();
                a.close().unwrap();
                let bytes = packet(&mut a, ticks(105));
                let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                assert_eq!(segment.header.flags & (ACK | FIN), ACK | FIN);
                assert!(segment.payload.is_empty());
                assert_eq!(a.ack_deadline, None);
            } else {
                a.timeout(deadline).unwrap();
                assert!(a.ack_pending);
                assert!(!a.ack_interactive);
                assert_eq!(a.ack_quick, 4);
                packet(&mut a, deadline);
                assert_eq!(a.ack_quick, 3);
            }
        }
    }
}

#[test]
fn reserved_commit_not_selection_counts_once_and_uses_departure_time() {
    for late in [false, true] {
        let (mut a, _) = pair(adaptive_config(), 100);
        data(&mut a, 100, b"request");
        assert_eq!(a.transmit(101, &mut [0; 19]), Err(Error::OutputTooSmall));
        assert_eq!(a.ack_quick, 4);
        let mut ack = selected(&mut a, 101);
        assert!(ack.data_ack);
        assert_eq!(a.ack_quick, 4);
        assert!(!a.ack_pending); // Selection remains the ownership barrier.
        assert_eq!(a.ack_deadline, None);
        a.accept_reserved_output(102, &mut ack, 0, 0, false)
            .unwrap();
        assert_eq!(a.ack_quick, 3);
        a.accept_reserved_output(103, &mut ack, 0, 0, true).unwrap();
        assert_eq!(a.ack_quick, 3);
        a.write(&[7; 100]).unwrap();
        let mut reply = selected(&mut a, 104);
        assert!(!a.ack_interactive); // A rejected/held submission does nothing.
        let at = if late { 40_100 } else { 105 };
        a.accept_reserved_output(at, &mut reply, 0, 40, false)
            .unwrap();
        assert_eq!(a.ack_interactive, !late);
        a.accept_reserved_output(at + 1, &mut reply, 40, 60, true)
            .unwrap();
        assert_eq!(a.ack_quick, 3);
    }
    let (mut a, _) = pair(adaptive_config(), 100);
    data(&mut a, 100, b"request");
    a.write(&[1; 100]).unwrap();
    let mut reply = selected(&mut a, 101);
    assert!(reply.data_ack);
    a.accept_reserved_output(102, &mut reply, 0, 40, false)
        .unwrap();
    assert_eq!(a.ack_quick, 3);
    a.accept_reserved_output(103, &mut reply, 40, 60, true)
        .unwrap();
    assert_eq!(a.ack_quick, 3);
}

#[test]
fn pure_fin_is_not_response_and_reserved_fin_commits_data_ack() {
    let (mut a, _) = pair(adaptive_config(), 100);
    data(&mut a, 100, b"request");
    a.read(&mut [0; 32]).unwrap();
    a.close().unwrap();
    assert!(!a.ack_interactive);
    let mut fin = selected(&mut a, 101);
    assert!(fin.fin && fin.data_ack && !fin.fresh_data);
    assert_eq!(a.ack_quick, 4);
    a.accept_reserved_output(102, &mut fin, 0, 0, true).unwrap();
    assert!(!a.ack_interactive);
    assert_eq!(a.ack_quick, 3);
}

#[test]
fn mandatory_feedback_overrides_interactive_delay() {
    for case in 0..7 {
        let (mut a, _) = pair(adaptive_config(), 100);
        data(&mut a, 35, b"seed");
        a.read(&mut [0; 4]).unwrap();
        a.write(b"request").unwrap();
        packet(&mut a, 40);
        assert!(a.ack_interactive);
        match case {
            0 => {
                data(&mut a, 100, b"a");
                assert_eq!(a.ack_deadline, Some(40_100));
                data(&mut a, 101, b"b"); // Two small segments.
            }
            1 => data(&mut a, 100, &[1; 2000]), // Two RMSS in one arrival.
            2 => {
                let next = a.receive.next();
                inject(&mut a, 100, next.wrapping_add(2), Seq(108), ACK, 8192, b"x");
            }
            3 => {
                let next = a.receive.next();
                inject(&mut a, 100, next.wrapping_add(2), Seq(108), ACK, 8192, b"x");
                packet(&mut a, 100);
                data(&mut a, 101, b"ab"); // Gap fill.
            }
            4 => {
                let next = a.receive.next();
                inject(&mut a, 100, next, Seq(108), ACK | FIN, 8192, b"");
            }
            5 => data(&mut a, 100, &[1; 8192]), // Receive window exhausted.
            _ => {
                data(&mut a, 100, b"a");
                let history = a.ack_receive;
                let next = a.receive.next();
                inject(
                    &mut a,
                    101,
                    next.wrapping_add(u32::MAX),
                    Seq(108),
                    ACK,
                    8192,
                    b"a",
                );
                assert_eq!(a.ack_receive, history); // Duplicate does not train.
            }
        }
        assert!(a.ack_pending, "case {case}");
        assert_eq!(a.ack_deadline, None, "case {case}");
    }
}

#[test]
fn spacing_bounds_long_idle_and_terminal_history() {
    for max in [1, 20_000, 40_000, 499_999] {
        let mut cfg = adaptive_config();
        cfg.delayed_ack_us = max;
        let (mut a, _) = pair(cfg, 100);
        let min = max.min(ACK_TIMEOUT_FLOOR_US);
        data(&mut a, 100, b"x");
        assert_eq!(a.ack_ato, min);
        packet(&mut a, 100);
        a.ack_ato = max;
        data(&mut a, 101, b"x");
        assert_eq!(a.ack_ato, (max / 2 + min / 2).clamp(min, max));
        packet(&mut a, 101);
        a.write(b"reply").unwrap();
        packet(&mut a, 101);
        a.ack_ato = max;
        let gap = max * 3 / 4;
        data(&mut a, 102 + gap, b"x");
        assert!((min..=max).contains(&a.ack_ato));
        let deadline = a.ack_deadline.unwrap();
        a.timeout(deadline).unwrap();
        packet(&mut a, deadline);
        a.ack_interactive = true;
        let idle = a.now + a.rto() + 1;
        data(&mut a, idle, b"x");
        assert!(!a.ack_interactive);
        assert_eq!(a.ack_quick, a.adaptive_quick_budget());
        assert!(a.ack_pending);
        a.terminal(CloseReason::Reset);
        assert_eq!(a.ack_receive, None);
        assert!(!a.ack_interactive);
        assert_eq!(a.ack_ato, min);
    }
}

#[test]
fn adaptive_config_bounds_and_unchanged_fixed_modes() {
    for adaptive in [false, true] {
        for max in [0, 1, 499_999, 500_000, u64::MAX] {
            let mut cfg = adaptive_config();
            cfg.adaptive_ack = adaptive;
            cfg.delayed_ack_us = max;
            assert_eq!(
                Connection::active(tuple(), cfg, 100, 0).is_ok(),
                max < 500_000 && (!adaptive || max != 0)
            );
        }
    }
    assert!(!ConnectionConfig::default().adaptive_ack);
    for delay in [0, 200_000] {
        let mut cfg = config(8192, 1000);
        cfg.delayed_ack_us = delay;
        let (mut a, _) = pair(cfg, 100);
        data(&mut a, 100, b"x");
        assert_eq!(a.ack_pending, delay == 0);
        assert_eq!(a.ack_deadline, (delay != 0).then_some(200_100));
    }
}

#[test]
fn fast_open_syn_only_and_post_handshake_request_fixtures() {
    for units in [1_000_000, 1_000_000_000] {
        for (syn_bytes, total) in [(1000, 1000), (900, 1900)] {
            for reserved in [false, true] {
                let mut cfg = adaptive_config();
                cfg.timebase.units_per_second = units;
                let ticks = |us| cfg.timebase.ticks_from_us(us);
                cfg.mss = 1460;
                cfg.send_ip_payload_limit = 1500;
                cfg.receive_ip_payload_limit = 1500;
                let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
                let mut cache = crate::fast_open::FastOpen::new().unwrap();
                cache.learn(
                    0,
                    tuple().local.ip(),
                    tuple().remote.ip(),
                    wire::FastOpenCookie::new(&[7; 8]).unwrap(),
                    syn_bytes + 40,
                );
                a.prepare_fast_open(
                    cache.get(0, 100, tuple().local.ip(), tuple().remote.ip()),
                    &vec![42; total],
                )
                .unwrap();
                let mut out = [0; 2048];
                let n = a.transmit_selected(0, &mut out, reserved).unwrap().unwrap();
                assert_eq!(
                    wire::parse(ip(tuple()), &out[..n]).unwrap().payload.len(),
                    syn_bytes as usize
                );
                assert!(!a.ack_interactive);
                assert_eq!(a.ack_receive, None);
                if reserved {
                    let mut d = a.last_departure.take().unwrap();
                    a.accept_reserved_output(ticks(1), &mut d, 0, syn_bytes as usize, true)
                        .unwrap();
                }
                assert!(!a.ack_interactive);
                let synack = Segment {
                    header: Header {
                        source_port: tuple().remote.port(),
                        destination_port: tuple().local.port(),
                        sequence: 900,
                        acknowledgment: 101 + syn_bytes as u32,
                        flags: SYN | ACK,
                        window: 8192,
                        urgent_pointer: 0,
                    },
                    options: wire::Options {
                        mss: Some(1000),
                        ..Default::default()
                    },
                    raw_options: &[],
                    payload: &[],
                };
                a.input(ticks(100), &synack).unwrap();
                assert_eq!(a.ack_receive, Some((ticks(100), false)));
                if total > syn_bytes as usize {
                    a.write(&vec![42; total - syn_bytes as usize]).unwrap();
                }
                let n = a
                    .transmit_selected(ticks(101), &mut out, reserved)
                    .unwrap()
                    .unwrap();
                let payload = wire::parse(ip(tuple()), &out[..n]).unwrap().payload.len();
                assert_eq!(payload, total - syn_bytes as usize);
                if reserved {
                    assert!(!a.ack_interactive);
                    let mut d = a.last_departure.take().unwrap();
                    a.accept_reserved_output(ticks(102), &mut d, 0, payload, true)
                        .unwrap();
                }
                assert!(!a.ack_interactive);
                data(&mut a, ticks(200), &[9; 500]);
                assert!(a.ack_pending);
                assert_eq!(a.ack_deadline, None);
                a.read(&mut [0; 500]).unwrap();
                a.close().unwrap();
                let bytes = packet(&mut a, ticks(201));
                assert_eq!(
                    wire::parse(ip(tuple()), &bytes).unwrap().header.flags & (FIN | ACK),
                    FIN | ACK
                );
                assert_eq!(a.ack_deadline, None);
            }
        }
    }
}
#[test]
fn invalid_and_paws_failed_data_do_not_train_or_defer_deadline() {
    let mut cfg = adaptive_config();
    cfg.timestamps = true;
    let (mut a, mut b) = pair(cfg, 100);
    b.write(b"seed").unwrap();
    deliver(&mut b, &mut a, 35);
    a.write(b"request").unwrap();
    packet(&mut a, 40);
    assert!(a.ack_interactive);
    let mut segment = Segment {
        header: Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: a.receive.next().0,
            acknowledgment: a.snd_nxt.0,
            flags: ACK,
            window: 8192,
            urgent_pointer: 0,
        },
        options: wire::Options {
            timestamps: Some((100, 0)),
            ..Default::default()
        },
        raw_options: &[],
        payload: b"x",
    };
    a.input(100, &segment).unwrap();
    assert_eq!(a.ack_deadline, Some(40_100));
    let history = a.ack_receive;
    segment.header.sequence += 1;
    segment.options.timestamps = Some((99, 0));
    a.input(101, &segment).unwrap();
    assert_eq!(a.ack_receive, history);
    // A PAWS rejection can demand immediate feedback, but never move it later.
    assert!(a.ack_pending || a.ack_deadline == Some(40_100));
    segment.options.timestamps = Some((101, 0));
    segment.header.acknowledgment = a.snd_nxt.wrapping_add(100).0;
    a.input(102, &segment).unwrap();
    assert_eq!(a.ack_receive, history);
    assert_eq!(a.receive.next().0, segment.header.sequence);
}

#[test]
fn pending_deadline_survives_spacing_change_and_long_idle() {
    let (mut a, _) = pair(adaptive_config(), 100);
    data(&mut a, 35, b"seed");
    a.write(b"request").unwrap();
    packet(&mut a, 40);
    data(&mut a, 100, b"x");
    let first = a.ack_deadline;
    // Exercise estimator independently: scheduling must never be postponed by it.
    a.now = 30_100;
    a.adaptive_receive();
    assert_eq!(a.ack_ato, 50_000);
    assert_eq!(a.ack_deadline, first);
    a.now += a.rto() + 1;
    a.adaptive_receive();
    assert_eq!(a.ack_deadline, first);
    assert_eq!(a.ack_quick, 4);
    assert!(!a.ack_interactive);
}

#[test]
fn ecn_window_reopening_and_peer_reset_keep_mandatory_feedback() {
    let mut cfg = adaptive_config();
    cfg.ecn = true;
    let (mut a, mut b) = pair(cfg, 100);
    b.write(b"seed").unwrap();
    deliver(&mut b, &mut a, 35);
    a.read(&mut [0; 4]).unwrap();
    a.write(b"request").unwrap();
    deliver(&mut a, &mut b, 40);
    assert!(a.ack_interactive);
    b.write(b"response").unwrap();
    let bytes = packet(&mut b, 41);
    let segment = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
    a.input_with_traffic_class(41, 3, &segment).unwrap();
    assert!(a.ack_pending);
    assert_eq!(a.ack_deadline, None);
    let bytes = packet(&mut a, 42);
    assert_ne!(
        wire::parse(ip(tuple()), &bytes).unwrap().header.flags & ECE,
        0
    );
    data(&mut a, 43, &[1; 8184]);
    assert_eq!(a.receive_window(), 0);
    packet(&mut a, 43);
    a.read(&mut [0; 8192]).unwrap();
    assert!(a.ack_pending);
    packet(&mut a, 44);
    let next = a.receive.next();
    let ack = a.snd_nxt;
    inject(&mut a, 45, next, ack, RST | ACK, 8192, b"");
    assert_eq!(a.close_reason(), Some(CloseReason::Reset));
    assert_eq!(a.ack_receive, None);
    assert!(!a.ack_interactive);
}

#[test]
fn only_frontier_advancing_new_data_trains_receive_timing() {
    let (mut a, _) = pair(adaptive_config(), 100);
    data(&mut a, 100, b"a");
    packet(&mut a, 100);
    data(&mut a, 30_100, b"b");
    packet(&mut a, 30_100);
    assert_eq!(a.ack_ato, 50_000);
    let history = a.ack_receive;
    let next = a.receive.next();
    let ack = a.snd_nxt;
    let used = a.receive_used;
    inject(&mut a, 60_100, next.wrapping_add(2), ack, ACK, 8192, b"e");
    assert_eq!(a.receive_used, used + 1); // Accepted, but still above a hole.
    assert_eq!(a.receive.next(), next);
    assert!(a.ack_pending);
    assert_eq!(a.ack_deadline, None);
    assert_eq!(a.ack_receive, history);
    assert_eq!(a.ack_ato, 50_000);
    packet(&mut a, 60_100);

    // Outside the last frontier sample's ATO, but inside the OOO arrival's ATO.
    a.write(b"independent").unwrap();
    let mut departure = selected(&mut a, 90_101);
    assert!(departure.fresh_data);
    assert_eq!(departure.payload, b"independent".len());
    a.accept_reserved_output(90_102, &mut departure, 0, b"independent".len(), true)
        .unwrap();
    assert!(!a.ack_interactive);

    // Overlap below RCV.NXT fills the hole and releases the buffered suffix.
    let ack = a.snd_nxt;
    inject(
        &mut a,
        100_100,
        next.wrapping_add(u32::MAX),
        ack,
        ACK,
        8192,
        b"bcd",
    );
    assert_eq!(a.receive.next(), next.wrapping_add(3));
    assert_eq!(a.ack_receive, Some((100_100, true)));
    assert_eq!(a.ack_ato, 50_000);
    assert!(a.ack_pending);
    assert_eq!(a.ack_deadline, None);
    packet(&mut a, 100_100);

    // An ordinary frontier-extending overlap also contributes its receive gap.
    inject(&mut a, 130_100, next.wrapping_add(2), ack, ACK, 8192, b"ef");
    assert_eq!(a.receive.next(), next.wrapping_add(4));
    assert_eq!(a.ack_receive, Some((130_100, true)));
    assert_eq!(a.ack_ato, 55_000);
    assert!(a.ack_pending);
    assert_eq!(a.ack_deadline, None);
}

#[test]
fn direct_and_reserved_departure_use_actual_clock_at_ato_boundary() {
    for units in [1_000_000, 1_000_000_000] {
        for offset in [-1i64, 0, 1] {
            for reserved in [false, true] {
                for ack_first in [false, true] {
                    let mut cfg = adaptive_config();
                    cfg.timebase.units_per_second = units;
                    let received = cfg.timebase.ticks_from_us(100);
                    let ato = cfg.timebase.ticks_from_us(40_000);
                    let departed = (received + ato).checked_add_signed(offset).unwrap();
                    let (mut a, _) = pair(cfg, 100);
                    data(&mut a, received, b"request");
                    if ack_first {
                        packet(&mut a, received);
                    }
                    let quick = a.ack_quick;
                    a.write(b"response").unwrap();
                    let before = (
                        a.now,
                        a.ack_receive,
                        a.ack_ato,
                        a.ack_pending,
                        a.ack_deadline,
                    );
                    assert_eq!(
                        a.transmit_selected(received - 1, &mut [0; 2048], reserved),
                        Err(Error::TimeWentBackwards)
                    );
                    assert_eq!(
                        a.transmit_selected(departed, &mut [0; 19], reserved),
                        Err(Error::OutputTooSmall)
                    );
                    assert_eq!(
                        (
                            a.now,
                            a.ack_receive,
                            a.ack_ato,
                            a.ack_pending,
                            a.ack_deadline
                        ),
                        before
                    );
                    assert_eq!(a.ack_quick, quick);
                    assert!(!a.ack_interactive);
                    if reserved {
                        let mut d = selected(&mut a, received + 1);
                        assert!(d.fresh_data);
                        assert_eq!(d.data_ack, !ack_first);
                        assert_eq!(a.ack_quick, quick);
                        assert!(!a.ack_interactive);
                        assert_eq!(
                            a.accept_reserved_output(received, &mut d, 0, 8, true),
                            Err(Error::TimeWentBackwards)
                        );
                        assert_eq!(a.ack_quick, quick);
                        assert!(!a.ack_interactive);
                        assert_eq!(d.data_ack, !ack_first);
                        a.accept_reserved_output(departed, &mut d, 0, 8, true)
                            .unwrap();
                    } else {
                        let bytes = packet(&mut a, departed);
                        assert_eq!(
                            wire::parse(ip(tuple()), &bytes).unwrap().payload,
                            b"response"
                        );
                    }
                    assert_eq!(a.now, departed);
                    assert_eq!(a.ack_quick, quick - u8::from(!ack_first));
                    assert_eq!(
                        a.ack_interactive,
                        offset < 0,
                        "units={units}, offset={offset}, reserved={reserved}, ack_first={ack_first}"
                    );
                    data(&mut a, departed + 1, b"next");
                    assert_eq!(a.ack_pending, offset >= 0);
                    assert_eq!(a.ack_deadline.is_some(), offset < 0);
                }
            }
        }
    }
}

#[test]
fn handshake_only_https_request_does_not_suppress_first_response_ack() {
    for units in [1_000_000, 1_000_000_000] {
        for reserved in [false, true] {
            let mut cfg = adaptive_config();
            cfg.mss = 1460;
            cfg.nagle = false;
            cfg.timebase.units_per_second = units;
            let ticks = |us| cfg.timebase.ticks_from_us(us);
            let (mut a, _) = pair(cfg.clone(), 100);
            assert_eq!(a.ack_receive, Some((20, false)));
            assert_eq!(a.ack_quick, 0);
            a.write(&[7; 517]).unwrap();
            let now = ticks(30);
            if reserved {
                let mut request = selected(&mut a, now);
                assert!(request.fresh_data);
                a.accept_reserved_output(now, &mut request, 0, 517, true)
                    .unwrap();
            } else {
                let bytes = packet(&mut a, now);
                assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 517);
            }
            assert!(!a.ack_interactive);
            data(&mut a, ticks(100_030), &[9; 143]);
            assert_eq!(a.ack_receive, Some((ticks(100_030), true)));
            assert!(a.ack_pending);
            assert_eq!(a.ack_deadline, None);
            let quick = a.ack_quick;
            if reserved {
                let mut ack = selected(&mut a, ticks(100_030));
                assert_eq!(a.ack_quick, quick);
                a.accept_reserved_output(ticks(100_030), &mut ack, 0, 0, true)
                    .unwrap();
            } else {
                packet(&mut a, ticks(100_030));
            }
            assert_eq!(a.ack_quick, quick - 1);
            a.write(b"real reply").unwrap();
            packet(&mut a, ticks(100_031));
            assert!(a.ack_interactive);
            data(&mut a, ticks(100_032), b"next");
            assert!(!a.ack_pending);
            assert_eq!(a.ack_deadline, Some(ticks(140_032)));
        }
    }
}

#[test]
fn epoll_4000_6000_read_1000_then_2000_keeps_quick_credit() {
    for units in [1_000_000, 1_000_000_000] {
        for reserved in [false, true] {
            let mut cfg = adaptive_config();
            cfg.receive_capacity = 131_072;
            cfg.mss = 1460;
            cfg.timebase.units_per_second = units;
            let ticks = |us| cfg.timebase.ticks_from_us(us);
            let (mut a, _) = pair(cfg.clone(), 100);
            let mut quick = 16;
            for (at, len) in [(100, 4000), (101, 6000), (102, 2000)] {
                if len == 2000 {
                    assert_eq!(a.read(&mut [0; 1000]), Ok(1000));
                }
                // The peer's scaled send window is unrelated to our quick budget.
                let next = a.receive.next();
                inject(&mut a, ticks(at), next, Seq(101), ACK, 257, &vec![1; len]);
                assert!(a.ack_pending);
                assert_eq!(a.ack_deadline, None);
                assert_eq!(a.ack_quick, quick);
                if reserved {
                    let mut ack = selected(&mut a, ticks(at));
                    assert!(ack.data_ack);
                    assert_eq!(a.ack_quick, quick);
                    a.accept_reserved_output(ticks(at), &mut ack, 0, 0, true)
                        .unwrap();
                } else {
                    packet(&mut a, ticks(at));
                }
                quick -= 1;
                assert_eq!(a.ack_quick, quick);
            }
        }
    }
}

#[test]
fn quick_budget_uses_local_unscaled_window_and_receive_mss_with_safe_bounds() {
    let (mut a, _) = pair(adaptive_config(), 100);
    a.snd_wnd = 1;
    for (window, expected) in [
        (0, 2),
        (1, 2),
        (1999, 2),
        (2000, 1),
        (3999, 1),
        (4000, 2),
        (31_999, 15),
        (32_000, 16),
        (131_072, 16),
        ((1 << 31) - 1, 16),
    ] {
        a.advertised_edge = a.receive.next().wrapping_add(window);
        assert_eq!(a.adaptive_quick_budget(), expected, "window={window}");
    }
    // Receive MSS is constrained by the actual local SYN offer. Configure each
    // connection before its handshake rather than rewriting an advertised offer.
    for (limit, window, expected) in [(520, 3000, 3), (u16::MAX, 131_030, 1)] {
        let mut cfg = adaptive_config();
        cfg.mss = 65495; // Maximum legal IPv4 MSS, before the receive-IP clamp.
        cfg.receive_ip_payload_limit = limit;
        let (mut a, _) = pair(cfg, 100);
        a.advertised_edge = a.receive.next().wrapping_add(window);
        assert_eq!(a.adaptive_quick_budget(), expected);
    }

    for (capacity, expected) in [(1, 2), (2000, 2), (2001, 1), (4001, 2), (64001, 16)] {
        let mut cfg = adaptive_config();
        cfg.receive_capacity = capacity;
        let (mut a, _) = pair(cfg, 100);
        assert_eq!(a.ack_quick, 0);
        data(&mut a, 100, b"x");
        assert_eq!(a.ack_quick, expected, "capacity={capacity}");
        a.terminal(CloseReason::Reset);
        assert_eq!(a.ack_quick, 0);
    }
}

#[test]
fn quick_budget_is_not_minted_per_arrival_and_refills_on_timer_and_idle() {
    for units in [1_000_000, 1_000_000_000] {
        let mut cfg = adaptive_config();
        cfg.timebase.units_per_second = units;
        let ticks = |us| cfg.timebase.ticks_from_us(us);
        let (mut a, _) = pair(cfg.clone(), 100);
        for i in 0..4 {
            data(&mut a, ticks(100 + i), b"x");
            assert_eq!(a.ack_quick, 4 - i as u8);
            packet(&mut a, ticks(100 + i));
            assert_eq!(a.ack_quick, 3 - i as u8);
        }
        data(&mut a, ticks(104), b"x");
        assert!(!a.ack_pending);
        let deadline = ticks(40_104);
        assert_eq!(a.ack_deadline, Some(deadline));
        a.timeout(deadline).unwrap();
        assert_eq!(a.ack_quick, a.adaptive_quick_budget());
        packet(&mut a, deadline);
        assert_eq!(a.ack_quick, 3);
        // A genuine response suppresses quick mode until an idle receive resets it.
        data(&mut a, deadline + 1, b"next");
        a.write(b"reply").unwrap();
        packet(&mut a, deadline + 2);
        assert!(a.ack_interactive);
        let idle = a.now + a.rto() + 1;
        let next = a.receive.next();
        let ack = a.snd_una; // Do not change the RTT/RTO with the idle arrival.
        inject(&mut a, idle, next, ack, ACK, 8192, b"x");
        assert!(!a.ack_interactive);
        assert_eq!(a.ack_quick, a.adaptive_quick_budget());
        assert!(a.ack_pending);
    }
}

#[test]
fn staged_syn_and_early_response_do_not_initialize_stream_ack_history() {
    for authenticated in [false, true] {
        for reserved in [false, true] {
            let mut cfg = adaptive_config();
            cfg.fast_open_early_response = true;
            let syn = Segment {
                header: Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: 900,
                    acknowledgment: 0,
                    flags: SYN,
                    window: 8192,
                    urgent_pointer: 0,
                },
                options: wire::Options::default(),
                raw_options: &[],
                payload: b"request",
            };
            let mut a = Connection::passive_with_receive(
                tuple(),
                cfg,
                100,
                0,
                &syn,
                authenticated,
                &mut None,
                RxTimestamps::default(),
                RxPacketTimestamps::default(),
            )
            .unwrap();
            a.write(b"reply").unwrap();
            if reserved {
                let mut synack = selected(&mut a, 10);
                a.accept_reserved_output(10, &mut synack, 0, 0, true)
                    .unwrap();
            } else {
                packet(&mut a, 10);
            }
            assert_eq!(a.ack_quick, 0);
            assert_eq!(a.ack_receive, None);
            if authenticated {
                if reserved {
                    let mut reply = selected(&mut a, 20);
                    a.accept_reserved_output(20, &mut reply, 0, 5, true)
                        .unwrap();
                } else {
                    packet(&mut a, 20);
                }
                assert!(!a.ack_interactive);
            }
            let ack = a.snd_nxt;
            inject(&mut a, 30, Seq(908), ack, ACK, 8192, b"");
            assert_eq!(a.state, State::Established);
            assert_eq!(a.ack_receive, Some((30, false)));
            if !authenticated {
                if reserved {
                    let mut reply = selected(&mut a, 31);
                    a.accept_reserved_output(31, &mut reply, 0, 5, true)
                        .unwrap();
                } else {
                    packet(&mut a, 31);
                }
            }
            assert!(!a.ack_interactive);
            assert_eq!(a.ack_quick, 0);
            data(&mut a, 40, b"new stream data");
            assert_eq!(a.ack_receive, Some((40, true)));
            assert_eq!(a.ack_quick, a.adaptive_quick_budget());
            assert!(a.ack_pending);
        }
    }
}
