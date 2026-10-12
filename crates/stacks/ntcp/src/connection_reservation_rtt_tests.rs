use super::*;

fn output(c: &mut Connection, selected: u64, accepted: u64, reserved: bool) -> Vec<u8> {
    if !reserved {
        return packet(c, accepted);
    }
    let mut bytes = vec![0; 2048];
    let n = c
        .transmit_selected(selected, &mut bytes, true)
        .unwrap()
        .unwrap();
    let mut d = c.last_departure.unwrap();
    let count = d.payload;
    c.accept_reserved_output(accepted, &mut d, 0, count, true)
        .unwrap();
    bytes.truncate(n);
    bytes
}

// Service the same core timer/output loop as the adapter, including an idle
// PTO (no fresh RTT) that rearms RTO without producing a packet.
fn first_loss_output(c: &mut Connection, reserved: bool) -> (u64, Vec<u8>) {
    for _ in 0..3 {
        let now = c.loss_timer.unwrap().1;
        c.timeout(now).unwrap();
        let mut bytes = vec![0; 2048];
        if let Some(n) = c.transmit_selected(now, &mut bytes, reserved).unwrap() {
            if reserved {
                let mut d = c.last_departure.unwrap();
                let count = d.payload;
                c.accept_reserved_output(now, &mut d, 0, count, true)
                    .unwrap();
            }
            bytes.truncate(n);
            return (now, bytes);
        }
    }
    panic!("no output after three loss deadlines");
}

// UpstreamBasic's core policy, without any socket/runner timing tolerance.
fn script_config() -> ConnectionConfig {
    ConnectionConfig {
        receive_capacity: 8 * 1024 * 1024,
        mss: 1460,
        delayed_ack_us: 0,
        peer_max_ack_delay_us: 200_000,
        initial_window: InitialWindow::Iw10,
        abort_with_ack: true,
        timestamps: true,
        rack: true,
        prr: true,
        prr_algorithm: PrrAlgorithm::LegacyInitialCredit,
        prr_pacing: true,
        tlp: true,
        rto_min_us: 200_000,
        sack: true,
        coalesce_read_window_updates: true,
        recovery_algorithm: RecoveryAlgorithm::Reno,
        receive_ip_payload_limit: 65515,
        send_ip_payload_limit: 65515,
        ..ConnectionConfig::default()
    }
}

fn handshake(reserved: bool, timestamps: bool, delay: u64, rtt: u64) -> (Connection, Connection) {
    handshake_with_config(reserved, timestamps, delay, rtt, script_config())
}

fn handshake_with_config(
    reserved: bool,
    timestamps: bool,
    delay: u64,
    rtt: u64,
    cfg: ConnectionConfig,
) -> (Connection, Connection) {
    let mut a = Connection::active(
        tuple(),
        ConnectionConfig {
            timestamps,
            mss: 1000,
            ..cfg.clone()
        },
        0,
        0,
    )
    .unwrap();
    let bytes = output(&mut a, 0, delay, reserved);
    let syn = wire::parse(ip(tuple()), &bytes).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 0, delay, &syn).unwrap();
    let bytes = output(&mut b, delay, 2 * delay, reserved);
    a.input(
        2 * delay + rtt,
        &wire::parse(ip(b.tuple()), &bytes).unwrap(),
    )
    .unwrap();
    let bytes = output(&mut a, 2 * delay + rtt, 2 * delay + rtt, reserved);
    b.input(
        2 * delay + rtt,
        &wire::parse(ip(a.tuple()), &bytes).unwrap(),
    )
    .unwrap();
    (a, b)
}

#[test]
fn fresh_handshake_scalar_and_reserved_local_rtt() {
    for timestamps in [false, true] {
        for delay in [0, 2_000_000] {
            let (a, b) = handshake(false, timestamps, delay, 100_000);
            let (x, y) = handshake(true, timestamps, delay, 100_000);
            for (scalar, reserved) in [(&a, &x), (&b, &y)] {
                assert_eq!(scalar.state(), State::Established);
                assert_eq!(reserved.state(), State::Established);
                assert_eq!(
                    (reserved.rtt.srtt(), reserved.rto()),
                    (scalar.rtt.srtt(), scalar.rto()),
                    "timestamps={timestamps}, delay={delay}"
                );
            }
            assert_eq!(y.rtt.srtt(), Some(100_000));
        }
    }
}

#[test]
fn script_user_timeout_fin_timer() {
    for reserved in [false, true] {
        let (_, mut b) = handshake(reserved, false, 0, 100_000);
        b.update_time(2_100_000).unwrap(); // Idle before the socket closes.
        b.set_user_timeout(3_000_000).unwrap();
        b.shutdown().unwrap();
        output(&mut b, 2_100_000, 2_100_000, reserved);
        let (at, bytes) = first_loss_output(&mut b, reserved);
        assert_eq!(at, 2_400_000, "FIN reserved={reserved}");
        let fin = wire::parse(ip(b.tuple()), &bytes).unwrap();
        assert_eq!(fin.header.flags & FIN, FIN);
        assert!(fin.payload.is_empty());
        assert_eq!(b.loss_timer, Some((LossTimer::Rto, 2_700_000)));
        let (at, _) = first_loss_output(&mut b, reserved);
        assert_eq!(at, 2_700_000);
        let (at, _) = first_loss_output(&mut b, reserved);
        assert_eq!(at, 3_300_000);
    }
}

#[test]
fn script_last_byte_sack_timer() {
    for reserved in [false, true] {
        // UpstreamSack differs from UpstreamBasic in these core policies.
        let defaults = ConnectionConfig::default();
        let cfg = ConnectionConfig {
            delayed_ack_us: defaults.delayed_ack_us,
            peer_max_ack_delay_us: defaults.peer_max_ack_delay_us,
            abort_with_ack: false,
            coalesce_read_window_updates: false,
            recovery_algorithm: RecoveryAlgorithm::NewReno,
            ..script_config()
        };
        let (_, mut b) = handshake_with_config(reserved, false, 0, 100_000, cfg);
        b.write(&[0; 4000]).unwrap();
        for _ in 0..4 {
            output(&mut b, 200_000, 200_000, reserved);
        }
        rack_sack(&mut b, 300_000, 0, &[(3999, 4000)]);
        let (at, bytes) = first_loss_output(&mut b, reserved);
        assert_eq!(at, 400_000, "SACK reserved={reserved}");
        let tail = wire::parse(ip(b.tuple()), &bytes).unwrap();
        assert_eq!(tail.header.sequence, 3001);
        assert_eq!(tail.payload.len(), 1000);
        assert_ne!(tail.header.flags & PSH, 0);
        let (at, bytes) = first_loss_output(&mut b, reserved);
        assert_eq!(at, 700_000);
        let head = wire::parse(ip(b.tuple()), &bytes).unwrap();
        assert_eq!(head.header.sequence, 1);
        assert_eq!(head.payload.len(), 1000);
    }
}

#[test]
fn script_shutdown_outstanding_data_probes_fin_not_head() {
    for reserved in [false, true] {
        let (_, mut b) = handshake(reserved, false, 0, 10_000);
        b.write(&[0; 10_000]).unwrap();
        for _ in 0..10 {
            output(&mut b, 20_000, 20_000, reserved);
        }
        b.shutdown().unwrap();
        output(&mut b, 30_000, 30_000, reserved);
        let (at, bytes) = first_loss_output(&mut b, reserved);
        let payload_len = wire::parse(ip(b.tuple()), &bytes).unwrap().payload.len();
        assert_eq!((at, payload_len), (50_000, 0), "reserved={reserved}");
        let fin = wire::parse(ip(b.tuple()), &bytes).unwrap();
        assert_eq!(fin.header.sequence, 10_001);
        assert_eq!(fin.header.flags & FIN, FIN);
        assert!(fin.payload.is_empty());
    }
}

#[test]
fn reserved_control_echo_validation_karn_and_syn_backoff() {
    for passive in [false, true] {
        for timestamps in [false, true] {
            for retry in [false, true] {
                for valid_echo in [false, true] {
                    let cfg = ConnectionConfig {
                        timestamps,
                        ..script_config()
                    };
                    let mut c = Connection::active(tuple(), cfg.clone(), 0, 0).unwrap();
                    if passive {
                        let bytes = packet(&mut c, 0);
                        c = Connection::passive(
                            reverse(tuple()),
                            cfg,
                            0,
                            0,
                            &wire::parse(ip(tuple()), &bytes).unwrap(),
                        )
                        .unwrap();
                    }
                    let selected = if retry {
                        output(&mut c, 0, 0, true);
                        c.timeout(1_000_000).unwrap();
                        assert!(c.sample.is_none());
                        1_000_000
                    } else {
                        0
                    };
                    output(&mut c, selected, 2_000_000, true);
                    assert!(!c.syn_delivered);
                    assert_eq!(c.rto(), if retry { 2_000_000 } else { 1_000_000 });
                    assert_eq!(
                        c.rto_deadline,
                        Some(if retry { 4_000_000 } else { 3_000_000 })
                    );
                    let echo = if retry && !valid_echo {
                        c.timestamp_value(0) // Delayed original, not the retransmission.
                    } else {
                        c.timestamp_value(selected)
                            .wrapping_add(u32::from(!valid_echo))
                    };
                    let next = c.receive.next();
                    timestamp_input(
                        &mut c,
                        2_100_000,
                        if passive { next } else { Seq(0) },
                        Seq(1),
                        ACK | if passive { 0 } else { SYN },
                        timestamps.then_some((3000, echo)),
                        b"",
                    );
                    assert_eq!(c.state(), State::Established);
                    let eligible = !retry && (!timestamps || valid_echo);
                    assert_eq!(
                        c.rtt.srtt(),
                        eligible.then_some(100_000),
                        "passive={passive}, timestamps={timestamps}, retry={retry}, valid_echo={valid_echo}"
                    );
                    assert_eq!(c.rtt.updates, usize::from(eligible));
                    assert_eq!(
                        c.rto(),
                        if retry {
                            3_000_000
                        } else if eligible {
                            300_000
                        } else {
                            1_000_000
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn reserved_fin_eligibility_older_sample_and_subsequent_scalar_clock() {
    for timestamps in [false, true] {
        let (_, mut b) = handshake(true, timestamps, 0, 100_000);
        b.shutdown().unwrap();
        output(&mut b, 200_000, 2_000_000, true);
        let updates = b.rtt.updates;
        let next = b.receive.next();
        let end = b.snd_nxt;
        let echo = b.timestamp_value(200_000);
        timestamp_input(
            &mut b,
            2_100_000,
            next,
            end,
            ACK,
            timestamps.then_some((3000, echo)),
            b"",
        );
        assert_eq!(b.rtt.updates, updates + 1);
        assert_eq!(b.rtt.srtt(), Some(100_000));

        let (_, mut b) = handshake(true, timestamps, 0, 100_000);
        b.write(&[0; 1000]).unwrap();
        output(&mut b, 200_000, 200_000, false);
        let sample = (b.sample, b.sample_departure);
        assert_eq!(b.sample_departure, None); // Fresh scalar sample resets the override.
        b.immediate_ack();
        output(&mut b, 205_000, 205_000, true);
        assert_eq!((b.sample, b.sample_departure), sample); // Pure ACK owns no sample.
        b.shutdown().unwrap();
        output(&mut b, 210_000, 250_000, true);
        assert_eq!((b.sample, b.sample_departure), sample);
        let next = b.receive.next();
        let end = b.snd_nxt;
        let echo = b.timestamp_value(200_000);
        timestamp_input(
            &mut b,
            300_000,
            next,
            end,
            ACK,
            timestamps.then_some((400, echo)),
            b"",
        );
        assert_eq!(b.rtt.srtt(), Some(100_000));
    }
}

#[test]
fn reserved_handshake_retains_nanosecond_local_clock_precision() {
    for reserved in [false, true] {
        let cfg = ConnectionConfig {
            timebase: CallerTimebase {
                units_per_second: 1_000_000_000,
                ..CallerTimebase::default()
            },
            ..script_config()
        };
        let (_, b) = handshake_with_config(reserved, true, 2_000_000_000, 100_000_123, cfg);
        assert_eq!(b.rtt.srtt(), Some(100_000_123));
        assert_eq!(b.rto(), 300_000_367); // RFC6298 integer RTTVAR = floor(R/2).
    }
}

#[test]
fn reserved_fin_options_fragment_waits_for_sequence_and_retry_cannot_sample() {
    let (_, mut b) = handshake(true, true, 0, 100_000);
    b.config.tlp = false;
    b.shutdown().unwrap();
    b.transmit_selected(200_000, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    let mut d = b.last_departure.unwrap();
    let sample = (b.sample, b.sample_departure);
    b.accept_reserved_output(250_000, &mut d, 0, 0, false)
        .unwrap();
    assert_eq!((b.sample, b.sample_departure), sample);
    b.accept_reserved_output(300_000, &mut d, 0, 0, true)
        .unwrap();
    assert_eq!(b.sample_departure, Some(300_000));
    b.timeout(600_000).unwrap();
    let updates = b.rtt.updates;
    output(&mut b, 600_000, 2_000_000, true);
    assert!(b.sample.is_none());
    let next = b.receive.next();
    let end = b.snd_nxt;
    let echo = b.timestamp_value(200_000); // Delayed ACK of the original FIN.
    timestamp_input(&mut b, 2_100_000, next, end, ACK, Some((3000, echo)), b"");
    assert_eq!(b.rtt.updates, updates);
    assert_eq!(b.rto(), 600_000); // Ambiguous ACK cannot collapse the backoff.
}
