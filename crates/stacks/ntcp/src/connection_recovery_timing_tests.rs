// Deterministic recovery timing regression: no adapter code or synthetic delivery.
extern crate std;
use super::*;
use alloc::{format, string::String};

fn profile(algorithm: PrrAlgorithm) -> ConnectionConfig {
    // Manually audited against packet_profile::config(Upstream(default)); peer
    // omits TS, so negotiation must disable it, not this configuration.
    ConnectionConfig {
        receive_capacity: 8 * 1024 * 1024,
        mss: 1460,
        initial_window: InitialWindow::Iw10,
        congestion_algorithm: CongestionAlgorithm::Cubic,
        cubic_hystart: true,
        cubic_fast_convergence: true,
        timestamps: true,
        sack: true,
        rack: true,
        tlp: true,
        prr: true,
        prr_algorithm: algorithm,
        prr_pacing: false,
        pacing: None,
        rto_min_us: 200_000,
        adaptive_ack: true,
        delayed_ack_us: 200_000,
        coalesce_read_window_updates: false,
        receive_ip_payload_limit: 65515,
        send_ip_payload_limit: 65515,
        ..ConnectionConfig::default()
    }
}

fn state(a: &Connection, observed_at: u64, label: &str, rows: &mut Vec<String>) {
    let counts = a.rack.counts();
    let (fs, delivered, out, credit) = a.prr.map_or((0, 0, 0, 0), |p| {
        let (fs, delivered, out) = p.counters();
        (fs, delivered, out, p.credit())
    });
    rows.push(format!(concat!(
        "{{\"event\":\"{}\",\"now_us\":{},\"observed_at_us\":{},\"snd_una\":{},\"snd_nxt\":{},",
        "\"flight\":{},\"rack_pipe\":{},\"recovery_pipe\":\"{:?}\",",
        "\"lost\":{},\"sacked\":{},\"cwnd\":{},\"ssthresh\":{},\"recovery_target\":{},",
        "\"prr_active\":{},\"recover_fs\":{},\"prr_delivered\":{},\"prr_out\":{},\"prr_credit\":{},",
        "\"entry_pending\":{},\"retx_pending\":{},\"loss_timer\":\"{:?}\",",
        "\"rack_deadline\":\"{:?}\",\"deadline\":\"{:?}\",\"rto_deadline\":\"{:?}\",",
        "\"snd_wnd\":{},\"peer_scale\":{},\"recovery\":{},\"duplicate_acks\":{}}}"),
        label, a.now, observed_at, a.snd_una.0, a.snd_nxt.0, a.flight(), a.rack.pipe(),
        a.sack_recovery.map(|r| r.pipe), counts.lost, counts.sacked,
        a.congestion.cwnd(), a.congestion.ssthresh(), a.congestion.recovery_target(),
        a.prr.is_some(), fs, delivered, out, credit,
        a.sack_recovery.is_some_and(|r| r.entry_pending), a.retx_pending,
        a.loss_timer, a.rack.deadline, a.next_deadline(), a.rto_deadline,
        a.snd_wnd, a.peer_scale, a.congestion.in_recovery(), a.duplicate_acks));
}

fn output(a: &mut Connection, now: u64, rows: &mut Vec<String>) -> Vec<(u64, u32, usize)> {
    let mut sent = Vec::new();
    for _ in 0..32 {
        state(a, now, "before_output_selection", rows);
        let mut bytes = vec![0; 65535];
        let Some(n) = a.transmit(now, &mut bytes).unwrap() else {
            state(a, now, "output_none", rows);
            return sent;
        };
        let seg = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
        rows.push(format!("{{\"event\":\"wire_commit\",\"now_us\":{},\"seq\":{},\"ack\":{},\"bytes\":{},\"flags\":{}}}",
            now, seg.header.sequence, seg.header.acknowledgment, seg.payload.len(), seg.header.flags));
        sent.push((now, seg.header.sequence, seg.payload.len()));
        state(a, now, "after_wire_commit", rows);
    }
    panic!("output did not quiesce");
}

fn advance(a: &mut Connection, now: u64, rows: &mut Vec<String>) -> Vec<(u64, u32, usize)> {
    let mut sent = Vec::new();
    for _ in 0..32 {
        let Some(deadline) = a.next_deadline().filter(|d| *d <= now) else {
            break;
        };
        assert!(deadline >= a.now);
        state(a, deadline, "before_due_timeout", rows);
        a.timeout(deadline).unwrap();
        state(a, deadline, "after_due_timeout", rows);
        sent.extend(output(a, deadline, rows));
        assert!(
            a.next_deadline().is_none_or(|d| d > deadline),
            "stuck deadline"
        );
    }
    // A poll at a supplied observation point also exercises output admission.
    sent.extend(output(a, now, rows));
    sent
}

#[test]
fn retransmit_delay_characterization() {
    for case in [
        "fr-4pkt",
        "fr-4pkt-fack-last-mss",
        "sack-shift-sacked-7-3-4-8-9-fack",
        "sack-shift-sacked-7-5-6-8-9-fack",
    ] {
        {
            let algorithm = crate::PrrAlgorithm::Rfc9937;
            for continue_peer_script in [false, true] {
                if continue_peer_script && !case.starts_with("sack-shift") {
                    continue;
                }
                let sack = case != "fr-4pkt";
                let shift = case.starts_with("sack-shift");
                let syn_at = if sack { 0 } else { 100_000 };
                let write_at = syn_at + 100_000;
                let ack_at = write_at + 100_000;
                let window = if shift {
                    1024
                } else if sack {
                    320
                } else {
                    257
                };
                let mut options = vec![2, 4];
                options.extend_from_slice(&(if sack { 1000u16 } else { 1460 }).to_be_bytes());
                if sack {
                    options.extend_from_slice(&[4, 2, 1, 1]);
                }
                options.extend_from_slice(&[1, 3, 3, 7]);
                let metadata = ip(reverse(tuple()));
                let mut bytes = [0; 60];
                let n = wire::encode(
                    metadata,
                    Header {
                        source_port: tuple().remote.port(),
                        destination_port: tuple().local.port(),
                        sequence: 0,
                        acknowledgment: 0,
                        flags: SYN,
                        window: 32792,
                        urgent_pointer: 0,
                    },
                    &options,
                    &[],
                    &mut bytes,
                )
                .unwrap();
                let syn = wire::parse(metadata, &bytes[..n]).unwrap();
                let mut a =
                    Connection::passive(tuple(), profile(algorithm), 0, syn_at, &syn).unwrap();
                let mut rows = Vec::new();
                output(&mut a, syn_at, &mut rows);
                inject(&mut a, write_at, Seq(1), Seq(1), ACK, window, &[]);
                assert_eq!(a.state(), State::Established);
                assert_eq!(a.sack_send, sack);
                assert!(!a.timestamps);
                assert_eq!(a.peer_scale, 7);
                assert_eq!(a.local_scale, 8);
                assert_eq!(a.mss, if sack { 1000 } else { 1460 });
                assert_eq!(a.rtt.srtt(), Some(100_000));
                assert_eq!(a.config.timebase.units_per_second, 1_000_000);
                state(&a, write_at, "handshake_ack", &mut rows);
                let len = if shift {
                    10000
                } else if sack {
                    4000
                } else {
                    5840
                };
                a.write(&vec![0x55; len]).unwrap();
                let initial = output(&mut a, write_at, &mut rows);
                assert_eq!(initial.iter().map(|(_, _, n)| n).sum::<usize>(), len);
                assert_eq!(a.snd_nxt, Seq(1 + len as u32));
                // All ACK/SACK edges below are for successfully committed data.
                let first = if shift {
                    vec![(7001, 8001)]
                } else if sack {
                    vec![(3001, 4001)]
                } else {
                    vec![]
                };
                let mut early_emissions = Vec::new();
                for duplicate in 1..=if sack { 1 } else { 3 } {
                    inject_sack(
                        &mut a,
                        ack_at,
                        Seq(1),
                        Seq(1),
                        ACK,
                        if shift { 257 } else { window },
                        &[],
                        &first,
                    );
                    state(&a, ack_at, "peer_ack", &mut rows);
                    let sent = output(&mut a, ack_at, &mut rows);
                    if sack || duplicate < 3 {
                        assert!(sent.is_empty());
                    } else {
                        assert_eq!(sent, vec![(ack_at, 1, 1460)]);
                    }
                    early_emissions.extend(sent);
                }
                if !sack {
                    assert_eq!(a.duplicate_acks, 3);
                    assert!(a.congestion.in_fast_recovery());
                    if algorithm == PrrAlgorithm::Rfc9937 {
                        assert_eq!(a.prr.unwrap().counters(), (5840, 1460, 1460));
                    } else {
                        assert!(a.prr.is_none());
                    }
                }
                let mut events: Vec<(u64, Vec<(u32, u32)>)> =
                    [25_000, 27_000, 30_000, 40_000, 100_000, 200_000]
                        .into_iter()
                        .map(|d| (ack_at + d, vec![]))
                        .collect();
                // Continuation is counterfactual after the missing first output;
                // all SACK blocks still describe actually committed original data.
                if shift && continue_peer_script {
                    let lo = if case.contains("7-3-4") { 3001 } else { 5001 };
                    let hi = lo + 1000;
                    for (i, blocks) in [
                        vec![(lo, hi), (7001, 8001)],
                        if lo == 3001 {
                            vec![(3001, 5001), (7001, 8001)]
                        } else {
                            vec![(5001, 8001)]
                        },
                        if lo == 3001 {
                            vec![(3001, 5001), (7001, 9001)]
                        } else {
                            vec![(5001, 9001)]
                        },
                        if lo == 3001 {
                            vec![(3001, 5001), (7001, 10001)]
                        } else {
                            vec![(5001, 10001)]
                        },
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        events.push((
                            ack_at + 27_000 + if lo == 3001 { (i as u64 + 1) * 2000 } else { 0 },
                            blocks,
                        ));
                    }
                }
                events.sort_by_key(|e| e.0);
                let mut emissions = early_emissions;
                for (now, blocks) in events {
                    emissions.extend(advance(&mut a, now, &mut rows));
                    if sack && now == ack_at + 25_000 {
                        assert!(a.congestion.in_recovery());
                        assert_eq!(a.rack.counts().lost, if shift { 7 } else { 3 });
                        let p = a.prr.unwrap();
                        if algorithm == PrrAlgorithm::Rfc9937 {
                            assert_eq!(p.counters(), (if shift { 9000 } else { 3000 }, 0, 1000));
                            assert_eq!(p.credit(), 0);
                            assert!(!a.sack_recovery.unwrap().entry_pending);
                        } else {
                            assert_eq!(
                                p.counters(),
                                (if shift { 10000 } else { 4000 }, 1000, 1000)
                            );
                            assert!(!a.sack_recovery.unwrap().entry_pending);
                        }
                    }
                    if !blocks.is_empty() {
                        inject_sack(&mut a, now, Seq(1), Seq(1), ACK, 257, &[], &blocks);
                        state(&a, now, "peer_ack", &mut rows);
                        emissions.extend(output(&mut a, now, &mut rows));
                    }
                }
                let expected_delay = if sack { 25_000 } else { 0 };
                // Check every committed data emission, including timeout-driven output.
                let first_data = emissions.iter().find(|(_, _, len)| *len != 0).unwrap();
                assert_eq!(
                    *first_data,
                    (
                        ack_at + expected_delay,
                        1,
                        if !sack && algorithm == PrrAlgorithm::Rfc9937 {
                            1460
                        } else {
                            a.mss as usize
                        }
                    ),
                    "{case} {algorithm:?} continued={continue_peer_script}"
                );
                assert!(
                    emissions
                        .iter()
                        .all(|(at, _, len)| *len == 0 || *at >= first_data.0)
                );
                let directory = std::env::var("NTCP_DELAY_STUDY_DIR").ok();
                if let Some(directory) = directory {
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(
                        format!(
                            "{directory}/{case}-{algorithm:?}-{}.json",
                            if continue_peer_script {
                                "continued"
                            } else {
                                "prefix-only"
                            }
                        ),
                        format!("[\n{}\n]\n", rows.join(",\n")),
                    )
                    .unwrap();
                }
            }
        }
    }
}

fn timer_sender(scale: u64, iss: u32) -> Connection {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        prr: true,
        initial_window: InitialWindow::Iw10,
        timebase: CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        },
        ..config(65_536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let syn = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &syn).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
    deliver(&mut b, &mut a, 100_000 * scale);
    deliver(&mut a, &mut b, 100_000 * scale);
    a.write(&[0x55; 10_000]).unwrap();
    for _ in 0..10 {
        packet(&mut a, 100_000 * scale);
    }
    rack_sack(&mut a, 200_000 * scale, 0, &[(7000, 8000)]);
    assert_eq!(a.next_deadline(), Some(225_000 * scale));
    a.timeout(225_000 * scale - 1).unwrap();
    assert!(a.prr.is_none());
    a.timeout(225_000 * scale).unwrap();
    assert_eq!(a.rack.counts().lost, 7);
    assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
    assert_eq!(a.prr.unwrap().credit(), 1000);
    assert_eq!(a.rack.pipe(), 2000);
    assert_eq!(a.congestion.cwnd(), 3000);
    assert_eq!(a.congestion.recovery_target(), 5000);
    a
}

#[test]
fn timer_repair_failed_selection_short_commit_and_episode_end() {
    for scale in [1, 1000] {
        for iss in [0, u32::MAX - 4999] {
            let mut a = timer_sender(scale, iss);
            let now = 225_000 * scale;
            let before = a.prr.unwrap();
            let recovery = a.sack_recovery.unwrap();
            assert_eq!(a.transmit(now, &mut [0; 20]), Err(Error::OutputTooSmall));
            // No selectable in-window lost bytes: the allowance remains owned.
            a.snd_wnd = 0;
            assert_eq!(a.transmit(now, &mut [0; 1500]), Ok(None));
            a.snd_wnd = 65_535;
            assert_eq!(a.prr.unwrap().counters(), before.counters());
            assert_eq!(a.prr.unwrap().credit(), 1000);
            assert_eq!(a.sack_recovery.unwrap().high_rxt, recovery.high_rxt);
            assert!(a.sack_recovery.unwrap().entry_pending);
            strict_ack(&mut a, now + scale, 0, &[(7000, 8000)]);
            assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
            assert_eq!(a.prr.unwrap().credit(), 1000); // Zero ACK preserves, not mints.
            a.config.send_ip_payload_limit = 270;
            let bytes = packet(&mut a, now + scale);
            let segment = wire::parse(ip(tuple()), &bytes).unwrap();
            assert_eq!(
                (segment.header.sequence, segment.payload.len()),
                (iss.wrapping_add(1), 250)
            );
            assert_eq!(a.prr.unwrap().counters(), (9000, 0, 250));
            assert_eq!(a.prr.unwrap().credit(), 0); // A short repair consumes admission.
            assert!(!a.sack_recovery.unwrap().entry_pending);
            assert_eq!(a.congestion.cwnd(), 3000);
            assert_eq!(a.congestion.recovery_target(), 5000);
            a.write(&[0x66; 1000]).unwrap();
            for i in 2..5 {
                a.timeout(now + i * scale).unwrap();
                strict_ack(&mut a, now + i * scale, 0, &[(7000, 8000)]);
                assert_eq!(a.transmit(now + i * scale, &mut [0; 1500]), Ok(None));
                assert_eq!(a.prr.unwrap().counters(), (9000, 0, 250));
                assert_eq!(a.prr.unwrap().credit(), 0);
            }
            strict_ack(&mut a, now + 5 * scale, 10_000, &[]);
            assert!(a.prr.is_none() && a.sack_recovery.is_none());
            assert_eq!(a.prr_exit_trace.unwrap().counters(), (9000, 0, 250));
            assert_eq!(a.congestion.cwnd(), 5000);

            let mut a = timer_sender(scale, iss);
            a.terminal(CloseReason::Reset);
            assert!(a.prr.is_none() && a.sack_recovery.is_none());
            let mut a = timer_sender(scale, iss);
            let rto = a.rto_deadline.unwrap();
            a.timeout(rto).unwrap();
            assert!(a.prr.is_none() && a.sack_recovery.is_none());
        }
    }
}

#[test]
fn timer_repair_reservation_charges_only_accepted_fragments() {
    for scale in [1, 1000] {
        let mut a = timer_sender(scale, 0);
        let now = 225_000 * scale;
        let mut bytes = [0; 1500];
        assert_eq!(
            a.transmit_selected(now, &mut [0; 20], true),
            Err(Error::OutputTooSmall)
        );
        let n = a.transmit_selected(now, &mut bytes, true).unwrap().unwrap();
        let segment = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
        assert_eq!((segment.header.sequence, segment.payload.len()), (1, 1000));
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        assert_eq!(a.prr.unwrap().credit(), 1000);
        a.reject_reserved_output(); // Immutable selection remains owned for retry.
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        assert_eq!(a.prr.unwrap().credit(), 1000);
        let mut d = a.last_departure.unwrap();
        assert_eq!(
            a.accept_reserved_output(now - 1, &mut d, 0, 250, false),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
        a.accept_reserved_output(now + scale, &mut d, 0, 250, false)
            .unwrap();
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 250));
        assert_eq!(a.prr.unwrap().credit(), 750);
        a.reject_reserved_output();
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 250));
        a.accept_reserved_output(now + 2 * scale, &mut d, 250, 750, true)
            .unwrap();
        assert_eq!(a.prr.unwrap().counters(), (9000, 0, 1000));
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.transmit(now + 2 * scale, &mut bytes), Ok(None));
        strict_ack(&mut a, now + 3 * scale, 0, &[(7000, 8000)]);
        assert_eq!(a.prr.unwrap().credit(), 0);
    }
}

#[test]
fn timer_repair_respects_pipe_and_pacing_and_cannot_repeat_on_active_timer() {
    let mut a = strict_flight(0);
    rack_sack(&mut a, 200_000, 0, &[(1000, 2000)]);
    a.timeout(225_000).unwrap();
    assert_eq!(a.rack.counts().lost, 1);
    assert!(a.rack.pipe() >= a.congestion.cwnd());
    assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
    assert_eq!(a.prr.unwrap().credit(), 0);
    assert_eq!(a.transmit(225_000, &mut [0; 1500]), Ok(None));

    let mut a = timer_sender(1, 0);
    a.config.prr_pacing = true;
    a.pacing_deadline = Some(226_000);
    assert_eq!(a.transmit(225_000, &mut [0; 1500]), Ok(None));
    assert_eq!(a.prr.unwrap().counters(), (9000, 0, 0));
    assert_eq!(a.prr.unwrap().credit(), 1000);
    assert_eq!(prr_packet(&mut a, 226_000), (1, 1000));
    assert_eq!(a.prr.unwrap().counters(), (9000, 0, 1000));
    // Inject a second timer event without ACK delivery, independently of when
    // the detector would arm it. Active recovery must never re-admit a repair.
    a.rack.deadline = Some(227_000);
    a.loss_timer = Some((LossTimer::Rack, 227_000));
    a.timeout(227_000).unwrap();
    assert_eq!(a.prr.unwrap().counters(), (9000, 0, 1000));
    assert_eq!(a.prr.unwrap().credit(), 0);
    assert!(!a.start_sack_recovery());
    assert_eq!(a.transmit(227_000, &mut [0; 1500]), Ok(None));
}

// The actual NewReno heuristic and a separate Reno policy control now both
// enter immediately. Keep their downstream byte-credit assertions independent.
// Historical pre-fix traces in workbench/newreno-entry-study stay unchanged.
#[test]
fn no_sack_first_flight_heuristic_and_reno_policy_control() {
    for iss in [0u32, u32::MAX] {
        {
            let algorithm = crate::PrrAlgorithm::Rfc9937;
            for policy in [RecoveryAlgorithm::NewReno, RecoveryAlgorithm::Reno] {
                let mut cfg = profile(algorithm);
                cfg.recovery_algorithm = policy; // Separate control; profile() remains unchanged.
                let metadata = ip(reverse(tuple()));
                let mut bytes = [0; 60];
                let n = wire::encode(
                    metadata,
                    Header {
                        source_port: tuple().remote.port(),
                        destination_port: tuple().local.port(),
                        sequence: 0,
                        acknowledgment: 0,
                        flags: SYN,
                        window: 32792,
                        urgent_pointer: 0,
                    },
                    &[2, 4, 5, 180, 1, 3, 3, 7], // MSS1460, WS7, no SACK/TS.
                    &[],
                    &mut bytes,
                )
                .unwrap();
                let syn = wire::parse(metadata, &bytes[..n]).unwrap();
                let mut a = Connection::passive(tuple(), cfg, iss, 100_000, &syn).unwrap();
                let mut rows = Vec::new();
                output(&mut a, 100_000, &mut rows);
                let base = Seq(iss).wrapping_add(1);
                inject(&mut a, 200_000, Seq(1), base, ACK, 257, &[]);
                assert_eq!(a.state(), State::Established);
                assert!(!a.sack_send && !a.timestamps);
                assert_eq!((a.mss, a.peer_scale, a.local_scale), (1460, 7, 8));
                assert_eq!(a.rtt.srtt(), Some(100_000));
                a.write(&vec![0x55; 4 * 1460]).unwrap();
                let initial = output(&mut a, 200_000, &mut rows);
                assert_eq!(
                    initial,
                    (0..4)
                        .map(|i| (200_000, base.wrapping_add(i * 1460).0, 1460))
                        .collect::<Vec<_>>()
                );
                for duplicate in 1..=3 {
                    inject(&mut a, 300_000, Seq(1), base, ACK, 257, &[]);
                    assert_eq!(a.duplicate_acks, duplicate);
                    assert_eq!(a.snd_una, base); // No application bytes cumulatively ACKed.
                    state(&a, 300_000, "qualified_duplicate_ack", &mut rows);
                    if duplicate < 3 {
                        assert!(!a.congestion.in_recovery() && !a.retx_pending);
                        assert!(a.prr.is_none());
                        assert!(output(&mut a, 300_000, &mut rows).is_empty());
                    }
                }
                assert!(a.congestion.in_fast_recovery());
                assert!(a.retx_pending);
                assert!(a.sack_recovery.is_none());
                if algorithm == PrrAlgorithm::Rfc9937 {
                    let p = a.prr.unwrap();
                    assert_eq!(p.counters(), (5840, 1460, 0));
                    assert_eq!(p.credit(), 1460);
                    assert_eq!(a.rack.counts().lost, 1);
                } else {
                    assert!(a.prr.is_none()); // No-SACK delivery is accounted by PRR.
                }
                state(
                    &a,
                    300_000,
                    "after_third_duplicate_before_output",
                    &mut rows,
                );
                let emitted = output(&mut a, 300_000, &mut rows);
                let first = emitted.iter().find(|(_, _, len)| *len != 0).unwrap();
                assert_eq!(first.0, 300_000);
                assert_eq!(first.1, base.0);
                assert_eq!(first.2, 1460);

                if algorithm == PrrAlgorithm::Rfc9937 {
                    assert_eq!(a.prr.unwrap().counters().2, first.2 as u64);
                    assert_eq!(a.prr.unwrap().credit(), 0);
                }
                if let Ok(directory) = std::env::var("NTCP_NEWRENO_ENTRY_STUDY_DIR") {
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(
                        format!("{directory}/{policy:?}-{algorithm:?}-iss{iss}.json"),
                        format!("[\n{}\n]\n", rows.join(",\n")),
                    )
                    .unwrap();
                }
            }
        }
    }
}

#[test]
fn initial_heuristic_wire_ack_validation_and_both_handshake_roles() {
    for iss in [0, u32::MAX] {
        let cfg = ConnectionConfig {
            sack: false,
            rack: false,
            tlp: false,
            prr: true,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            initial_window: InitialWindow::Iw10,
            ..config(32_000, 1000)
        };
        let (a, b) = pair(cfg, iss);
        for mut a in [a, b] {
            let base = a.snd_una;
            let seq = a.receive.next();
            let history = Some((a.iss, a.iss.wrapping_add(1)));
            assert_eq!(a.congestion.ack_history(), history);
            a.write(&[1; 4000]).unwrap();
            let mut rows = Vec::new();
            assert_eq!(output(&mut a, 40, &mut rows).len(), 4);
            // Invalid old/future ACKs and valid window-only changes cannot
            // supply cumulative history or qualifying duplicate evidence.
            for (edge, window) in [
                (base.wrapping_add(u32::MAX), 32_000),
                (a.snd_nxt.wrapping_add(1), 32_000),
                (base, 31_999),
                (base, 32_000),
            ] {
                inject(&mut a, 50, seq, edge, ACK, window, &[]);
                assert_eq!(a.congestion.ack_history(), history);
                assert_eq!(a.duplicate_acks, 0);
                assert!(!a.congestion.in_recovery());
                output(&mut a, 50, &mut rows); // Any invalid-ACK reply.
            }
            for duplicate in 1..=3 {
                inject(&mut a, 60, seq, base, ACK, 32_000, &[]);
                assert_eq!(a.congestion.ack_history(), history);
                assert_eq!(a.congestion.in_fast_recovery(), duplicate == 3);
            }
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
            assert_eq!(a.prr.unwrap().credit(), 1000);
            // Failed encoding cannot consume PRR credit. Endpoint reservation
            // rejection is separately exercised at its transactional boundary.
            assert_eq!(a.transmit(60, &mut [0; 20]), Err(Error::OutputTooSmall));
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 0));
            assert_eq!(a.prr.unwrap().credit(), 1000);
            assert_eq!(output(&mut a, 60, &mut rows), vec![(60, base.0, 1000)]);
            assert_eq!(a.prr.unwrap().counters(), (4000, 1000, 1000));
            assert_eq!(a.prr.unwrap().credit(), 0);
            let boundary = a.snd_nxt;
            inject(&mut a, 70, seq, boundary, ACK, 32_000, &[]);
            assert!(!a.congestion.in_fast_recovery());
            a.write(&[2; 4000]).unwrap();
            output(&mut a, 80, &mut rows);
            let threshold = a.congestion.ssthresh();
            for _ in 0..3 {
                inject(&mut a, 90, seq, boundary, ACK, 32_000, &[]);
            }
            assert!(!a.congestion.in_fast_recovery() && !a.retx_pending);
            assert_eq!(a.congestion.ssthresh(), threshold);
        }
    }
}

#[test]
fn initial_heuristic_rto_before_application_ack_keeps_epoch_guard() {
    for iss in [0, u32::MAX] {
        let cfg = ConnectionConfig {
            sack: false,
            tlp: false,
            initial_window: InitialWindow::Iw10,
            ..config(32_000, 1000)
        };
        let (mut a, _) = pair(cfg, iss);
        let base = a.snd_una;
        let seq = a.receive.next();
        a.write(&[1; 4000]).unwrap();
        let mut rows = Vec::new();
        output(&mut a, 40, &mut rows);
        let boundary = a.snd_nxt;
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        output(&mut a, deadline, &mut rows);
        a.congestion.prr_window(10_000); // Deliberately test beyond the one-MSS check.
        for _ in 0..3 {
            inject(&mut a, deadline + 1, seq, base, ACK, 32_000, &[]);
        }
        assert!(!a.congestion.in_fast_recovery() && !a.retx_pending);
        assert_eq!(a.congestion.ack_history(), Some((a.iss, base)));
        inject(&mut a, deadline + 2, seq, boundary, ACK, 32_000, &[]);
        a.write(&[2; 4000]).unwrap();
        a.congestion.prr_window(10_000);
        output(&mut a, deadline + 3, &mut rows);
        for _ in 0..3 {
            inject(&mut a, deadline + 4, seq, boundary, ACK, 32_000, &[]);
        }
        assert!(!a.congestion.in_fast_recovery() && !a.retx_pending);
    }
}

#[test]
fn initial_heuristic_syn_rto_disarms_even_when_iw10_is_retained() {
    for iss in [0, u32::MAX] {
        for passive in [false, true] {
            let cfg = ConnectionConfig {
                sack: false,
                tlp: false,
                initial_window: InitialWindow::Iw10,
                ..config(32_000, 1000)
            };
            let mut a = if passive {
                let mut peer = Connection::active(reverse(tuple()), cfg.clone(), 900, 0).unwrap();
                let bytes = packet(&mut peer, 0);
                let syn = wire::parse(ip(reverse(tuple())), &bytes).unwrap();
                Connection::passive(tuple(), cfg, iss, 0, &syn).unwrap()
            } else {
                Connection::active(tuple(), cfg, iss, 0).unwrap()
            };
            packet(&mut a, 0);
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            assert!(!a.syn_loss_detected); // IW10's first timeout keeps its policy.
            packet(&mut a, deadline);
            let base = Seq(iss).wrapping_add(1);
            inject(
                &mut a,
                deadline + 1,
                Seq(if passive { 901 } else { 900 }),
                base,
                if passive { ACK } else { SYN | ACK },
                32_000,
                &[],
            );
            assert_eq!(a.state(), State::Established);
            assert_eq!(a.congestion.ack_history(), Some((Seq(iss), base)));
            assert!(a.congestion.cwnd() > a.mss as u32);
            if !passive {
                packet(&mut a, deadline + 1);
            }
            let mss = a.mss as usize;
            a.write(&vec![1; 4 * mss]).unwrap();
            let mut rows = Vec::new();
            output(&mut a, deadline + 2, &mut rows);
            let seq = a.receive.next();
            for _ in 0..3 {
                inject(&mut a, deadline + 3, seq, base, ACK, 32_000, &[]);
            }
            assert!(!a.congestion.in_fast_recovery() && !a.retx_pending);
            assert!(output(&mut a, deadline + 3, &mut rows).is_empty());
        }
    }
}

// Original prefix stops at the missing third repair. Continuations deliberately
// inject later peer inputs despite that mismatch; they are not whole-script runs.
fn stale_ack_state(a: &Connection, now: u64, label: &str, rows: &mut Vec<String>) {
    state(a, now, label, rows);
    rows.push(format!(
        concat!(
            "{{\"event\":\"scoreboard_detail\",\"observed_at_us\":{},",
            "\"label\":\"{}\",\"scoreboard_sacked_bytes\":{},",
            "\"high_rxt\":{},\"effective_recovery_pipe\":{},\"lowest_lost\":\"{:?}\",",
            "\"wl1\":{},\"wl2\":{},\"scoreboard\":\"{:?}\"}}"
        ),
        now,
        label,
        a.flight() - a.scoreboard.unsacked_bytes(a.snd_una, a.data_high()),
        a.sack_recovery.map_or(a.snd_una.0, |r| r.high_rxt.0),
        a.sack_recovery.map_or(a.rack.pipe(), |r| r.pipe),
        a.rack.lowest_lost(a.mss as u32),
        a.wl1.0,
        a.wl2.0,
        a.scoreboard.ranges(),
    ));
}

#[test]
fn stale_ack_prr_prefix_and_counterfactual_delivery() {
    {
        let algorithm = crate::PrrAlgorithm::Rfc9937;
        for continuation in ["prefix-only", "with-old-ack", "without-old-ack"] {
            let metadata = ip(reverse(tuple()));
            let mut bytes = [0; 60];
            let n = wire::encode(
                metadata,
                Header {
                    source_port: tuple().remote.port(),
                    destination_port: tuple().local.port(),
                    sequence: 0,
                    acknowledgment: 0,
                    flags: SYN,
                    window: 32792,
                    urgent_pointer: 0,
                },
                &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 8],
                &[],
                &mut bytes,
            )
            .unwrap();
            let syn = wire::parse(metadata, &bytes[..n]).unwrap();
            let mut a = Connection::passive(tuple(), profile(algorithm), 0, 0, &syn).unwrap();
            let mut rows = Vec::new();
            output(&mut a, 0, &mut rows);
            inject(&mut a, 10_000, Seq(1), Seq(1), ACK, 320, &[]);
            assert_eq!(a.state(), State::Established);
            assert!(a.sack_send && a.sack_receive && !a.timestamps);
            assert_eq!((a.mss, a.peer_scale, a.local_scale), (1000, 8, 8));
            assert_eq!(a.snd_wnd, 320 << 8);
            assert_eq!(a.rtt.srtt(), Some(10_000));
            assert_eq!(a.config.timebase.units_per_second, 1_000_000);
            assert!(a.config.pacing.is_none() && !a.config.prr_pacing);
            assert!(a.config.cubic_hystart && a.config.adaptive_ack);
            assert_eq!(a.congestion.cwnd(), 10_000);
            assert_eq!(a.write(&[0x55; 10_000]).unwrap(), 10_000);
            let initial = output(&mut a, 10_000, &mut rows);
            assert_eq!(
                initial,
                (0..10)
                    .map(|i| (10_000, 1 + i * 1000, 1000))
                    .collect::<Vec<_>>()
            );
            assert!(advance(&mut a, 20_000, &mut rows).is_empty());
            let mut repairs = Vec::new();
            for (label, blocks) in [
                ("first_sack", vec![(1001, 2001)]),
                ("second_sack", vec![(1001, 3001)]),
                ("third_sack", vec![(1001, 3001), (8001, 9001)]),
            ] {
                stale_ack_state(&a, 20_000, "before_sack", &mut rows);
                inject_sack(&mut a, 20_000, Seq(1), Seq(1), ACK, 320, &[], &blocks);
                stale_ack_state(&a, 20_000, label, &mut rows);
                repairs.extend(output(&mut a, 20_000, &mut rows));
            }
            assert_eq!(repairs, vec![(20_000, 1, 1000)]);
            // Service *all* deadlines in order, including any RACK deadline
            // between the three SACKs and the next scripted cumulative ACK.
            let recover_fs = if algorithm == PrrAlgorithm::Rfc9937 {
                8000
            } else {
                10000
            };
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, 1000, 1000));
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert_eq!((a.rack.counts().lost, a.rack.counts().sacked), (6, 3));
            assert_eq!(a.sack_recovery.unwrap().high_rxt, Seq(1001));
            assert!(!a.sack_recovery.unwrap().entry_pending && !a.retx_pending);
            let between = advance(&mut a, 32_000, &mut rows);
            assert!(between.is_empty());
            stale_ack_state(&a, 32_000, "before_ack4001", &mut rows);
            // A test-only ledger copy separates ACK removal from loss detection;
            // actual production input below remains the authoritative state.
            let mut rack_before = a.rack.grown(10_000).unwrap();
            inject_sack(
                &mut a,
                32_000,
                Seq(1),
                Seq(4001),
                ACK,
                320,
                &[],
                &[(8001, 9001)],
            );
            stale_ack_state(&a, 32_000, "after_ack4001_before_output", &mut rows);
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, 3000, 1000));
            assert_eq!(a.prr.unwrap().credit(), 2000);
            assert_eq!(a.congestion.recovery_target(), 7000);
            let ledger_delivery = rack_before.acknowledge(
                Seq(4001),
                a.data_high(),
                &a.scoreboard,
                32_000,
                None,
                None,
                1000,
                false,
            );
            assert_eq!(ledger_delivery, 2000); // 4000 deltaUNA minus 2000 old SACK.
            assert_eq!(rack_before.pipe(), 1000);
            assert_eq!(rack_before.counts().lost, 4);
            let mut tail_before = rack_before.grown(10_000).unwrap();
            tail_before.trim_cumulative(Seq(9001));
            assert_eq!(tail_before.pipe(), 1000);
            assert_eq!(tail_before.lowest_lost(1000), None);
            assert!(!rack_before.detect(32_000, true, a.rtt.srtt()));
            assert_eq!(rack_before.pipe(), 0);
            assert_eq!(rack_before.counts().lost, 5);
            assert_eq!(a.rack.pipe(), rack_before.pipe());
            assert_eq!(a.rack.counts().lost, rack_before.counts().lost);
            rack_before.trim_cumulative(Seq(9001));
            assert_eq!(rack_before.lowest_lost(1000), Some((Seq(9001), Seq(10001))));
            assert_eq!(rack_before.pipe(), 0);
            // RACK detection reduced pipe: further_loss=true, hence SafeACK=false.
            // RFC9937: min(7000-0, max(3000-1000,2000)+0) = 2000.
            rows.push(String::from(concat!(
                "{\"event\":\"ack4001_loss_detector_oracle\",\"observed_at_us\":32000,",
                "\"delivered_bytes\":2000,\"pipe_before_detect\":1000,\"pipe_after_detect\":0,",
                "\"lost_before_detect\":4,\"lost_after_detect\":5,\"further_loss\":true,",
                "\"new_loss_start\":9001,\"new_loss_end\":10001,",
                "\"safe_ack_derived\":false,\"rfc9937_credit\":2000,\"hypothetical_safe_credit\":3000}"
            )));
            let after_ack = output(&mut a, 32_000, &mut rows);
            assert_eq!(after_ack, vec![(32_000, 4001, 1000), (32_000, 5001, 1000)]);
            stale_ack_state(&a, 32_000, "after_ack4001_output", &mut rows);
            assert_eq!(a.prr.unwrap().counters(), (recover_fs, 3000, 3000));
            assert_eq!(a.prr.unwrap().credit(), 0);
            assert_eq!(a.rack.lowest_lost(1000), Some((Seq(6001), Seq(7001))));
            if continuation != "prefix-only" {
                // Counterfactual: upstream would still be waiting for 6001:7001.
                // The new SACK is valid: 5001:7001 was originally sent at 10 ms.
                assert_eq!(a.write(&[0x66; 10_000]).unwrap(), 10_000);
                stale_ack_state(&a, 32_000, "counterfactual_write", &mut rows);
                assert!(output(&mut a, 32_000, &mut rows).is_empty());
                assert!(advance(&mut a, 34_000, &mut rows).is_empty());
                if continuation == "with-old-ack" {
                    let una = a.snd_una;
                    let window = (a.snd_wnd, a.wl1, a.wl2);
                    let p = a.prr.unwrap().counters();
                    inject_sack(
                        &mut a,
                        34_000,
                        Seq(1),
                        Seq(3001),
                        ACK,
                        320,
                        &[],
                        &[(5001, 7001)],
                    );
                    stale_ack_state(&a, 34_000, "after_old_ack_before_output", &mut rows);
                    assert_eq!(a.snd_una, una);
                    assert_eq!((a.snd_wnd, a.wl1, a.wl2), window);
                    assert_eq!(a.prr.unwrap().counters().1, p.1 + 2000);
                    assert_eq!(a.prr.unwrap().credit(), 2000);
                    assert_eq!(a.rack.counts().sacked, 3);
                    assert_eq!(
                        output(&mut a, 34_000, &mut rows),
                        vec![(34_000, 7001, 1000), (34_000, 9001, 1000)]
                    );
                    assert_eq!(a.snd_nxt, Seq(10001));
                    assert_eq!(a.prr.unwrap().counters(), (recover_fs, 5000, 5000));
                    let before = a.prr.unwrap().counters();
                    inject_sack(
                        &mut a,
                        34_000,
                        Seq(1),
                        Seq(3001),
                        ACK,
                        320,
                        &[],
                        &[(5001, 7001)],
                    );
                    stale_ack_state(&a, 34_000, "after_identical_old_ack", &mut rows);
                    assert_eq!(a.prr.unwrap().counters(), before);
                    assert!(output(&mut a, 34_000, &mut rows).is_empty());
                }
            }
            // No further receiver feedback: characterize the next timeout,
            // without calling it a failure of old-ACK processing.
            let rto = a.rto_deadline.unwrap();
            assert_eq!(
                rto,
                if continuation == "with-old-ack" {
                    234_000
                } else {
                    232_000
                }
            );
            assert!(advance(&mut a, rto - 1, &mut rows).is_empty());
            stale_ack_state(&a, rto, "before_no_feedback_rto", &mut rows);
            assert_eq!(advance(&mut a, rto, &mut rows), vec![(rto, 4001, 1000)]);
            assert!(a.prr.is_none());
            stale_ack_state(&a, rto, "after_no_feedback_rto", &mut rows);
            if let Ok(directory) = std::env::var("NTCP_STALE_ACK_STUDY_DIR") {
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    format!("{directory}/{algorithm:?}-{continuation}.json"),
                    format!("[\n{}\n]\n", rows.join(",\n")),
                )
                .unwrap();
            }
        }
    }
}

#[test]
fn unsupported_bulk_prefix_enters_rfc9406_css_before_legacy_hystart_exit() {
    for paced in [false, true] {
        let mut cfg = profile(PrrAlgorithm::Rfc9937);
        cfg.send_capacity = 100_000; // Enough queued data for the entire30KB ACK prefix.
        cfg.coalesce_read_window_updates = true;
        cfg.output_group_flush = true;
        cfg.tlp = false; // Original script explicitly disables TLP.
        cfg.pacing = paced.then(PacingConfig::default);
        let metadata = ip(reverse(tuple()));
        let mut bytes = [0; 64];
        let n = wire::encode(
            metadata,
            Header {
                source_port: tuple().remote.port(),
                destination_port: tuple().local.port(),
                sequence: 0,
                acknowledgment: 0,
                flags: SYN,
                window: 32792,
                urgent_pointer: 0,
            },
            &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 10],
            &[],
            &mut bytes,
        )
        .unwrap();
        let syn = wire::parse(metadata, &bytes[..n]).unwrap();
        let mut a = Connection::passive(tuple(), cfg, 0, 0, &syn).unwrap();
        let mut rows = Vec::new();
        output(&mut a, 0, &mut rows);
        inject(&mut a, 100_000, Seq(1), Seq(1), ACK, 514, &[]);
        a.write(&vec![7; 100_000]).unwrap();
        output(&mut a, 100_000, &mut rows);
        for step in 1..=15 {
            let now = 100_000 + step * 100_000;
            advance(&mut a, now - 1, &mut rows);
            let ack = Seq(1 + step as u32 * 2000);
            assert!(!after(ack, a.snd_nxt));
            inject(&mut a, now, Seq(1), ack, ACK, 514, &[]);
            let startup = a.congestion.startup_state().unwrap();
            rows.push(format!("{{\"event\":\"startup_observation\",\"at_us\":{now},\"ack\":{},\"cwnd\":{},\"samples\":{},\"css_baseline\":{},\"css_rounds\":{},\"paced\":{paced}}}",
                ack.0, a.congestion.cwnd(), startup.0, startup.1.map_or("null".into(), |v|format!("{v}")), startup.2));
            assert!(a.prr.is_none() && !a.congestion.in_recovery());
            if step == 13 {
                assert_eq!(a.congestion.cwnd(), 36_000);
                assert!(startup.1.is_some());
            }
            if step >= 14 {
                assert_eq!(a.congestion.cwnd(), 36_000 + (step as u32 - 13) * 500);
            }
            output(&mut a, now, &mut rows);
        }
        assert_eq!(a.congestion.cwnd(), 37_000);
        if let Ok(directory) = std::env::var("NTCP_UNSUPPORTED13_STUDY_DIR") {
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                format!("{directory}/bulk-css-paced-{paced}.json"),
                format!("[\n{}\n]\n", rows.join(",\n")),
            )
            .unwrap();
        }
    }
}

#[path = "connection_idle_restart_phase_tests.rs"]
mod idle_restart_phase;
