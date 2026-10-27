use super::*;
use crate::connection::test_support::drain_wire;

fn startup_paced_pair(mut cfg: ConnectionConfig, iss: u32) -> (Connection, Connection) {
    cfg.pacing = Some(PacingConfig::default());
    cfg.prr = false;
    cfg.prr_pacing = false;
    cfg.nagle = false;
    let scale = cfg.timebase.units_per_second / 1_000_000;
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let syn = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &syn).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 50_000 * scale, &syn).unwrap();
    deliver(&mut b, &mut a, 100_000 * scale);
    deliver(&mut a, &mut b, 100_001 * scale);
    assert_eq!(a.state(), State::Established);
    assert!(a.initial_pacing_open);
    (a, b)
}

fn startup_packets(a: &mut Connection, now: u64) -> Vec<(u32, usize)> {
    drain_wire(a, now, 65535, 100)
        .into_iter()
        .filter(|&(_, len, _)| len != 0)
        .map(|(sequence, len, _)| (sequence, len))
        .collect()
}

#[test]
fn initial_pacing_burst_uses_negotiated_iw_and_never_grants_extra_window() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
            for mss in [500, 1000, 1460, 9000] {
                for scale in [1, 1000] {
                    let (mut a, _) = startup_paced_pair(
                        ConnectionConfig {
                            congestion_algorithm: algorithm,
                            initial_window: policy,
                            timebase: CallerTimebase {
                                units_per_second: 1_000_000 * scale,
                                ..Default::default()
                            },
                            ..config(131072, mss)
                        },
                        u32::MAX - 4999,
                    );
                    let start = 100_001 * scale;
                    let iw = a.initial_window();
                    let base = a.snd_nxt;
                    a.write(&vec![7; (iw * 2) as usize]).unwrap();
                    let before = (a.snd_nxt, a.pacer, a.initial_pacing_open);
                    assert_eq!(a.transmit(start, &mut [0; 19]), Err(Error::OutputTooSmall));
                    assert_eq!((a.snd_nxt, a.pacer, a.initial_pacing_open), before);
                    let sent = startup_packets(&mut a, start);
                    assert_eq!(sent.iter().map(|p| p.1).sum::<usize>(), iw as usize);
                    let mut end = base;
                    for (seq, bytes) in sent {
                        assert_eq!(seq, end.0);
                        end = end.wrapping_add(bytes as u32);
                    }
                    assert_eq!(end, base.wrapping_add(iw));
                    assert!(startup_packets(&mut a, start).is_empty());
                    assert_eq!(a.congestion.cwnd(), iw);
                    assert!(a.general_pacing_deadline(start).is_some());
                }
            }
        }
    }
}

#[test]
fn initial_pacing_burst_ack_closes_allowance_and_preserves_hystart_provenance() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            congestion_algorithm: CongestionAlgorithm::Cubic,
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    let base = a.snd_una;
    let start = 100_001;
    a.write(&[7; 30000]).unwrap();
    assert_eq!(startup_packets(&mut a, start).len(), 10);
    let next = a.receive.next();
    let window = (a.snd_wnd >> a.peer_scale) as u16;
    inject(
        &mut a,
        start + 100000,
        next,
        base.wrapping_add(10000),
        ACK,
        window,
        &[],
    );
    assert!(!a.initial_pacing_open);
    // A bypassed flight uses the finite tuned L16; ten MSS fit within it.
    assert_eq!(a.congestion.cwnd(), 20000);
    assert_eq!(startup_packets(&mut a, start + 100000).len(), 2);
    assert!(startup_packets(&mut a, start + 100000).is_empty());
    let high = a.snd_nxt;
    inject(&mut a, start + 200000, next, high, ACK, window, &[]);
    assert!(!a.initial_pacing_open);
    assert_eq!(startup_packets(&mut a, start + 200000).len(), 2);
}

#[test]
fn initial_pacing_burst_partial_writes_window_reopen_and_explicit_caps() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    let start = 100001;
    let seq = a.receive.next();
    let base = a.snd_una;
    let small = (3000u32 >> a.peer_scale) as u16;
    inject(&mut a, start, seq, base, ACK, small, &[]);
    a.write(&[7; 2000]).unwrap();
    assert_eq!(startup_packets(&mut a, start).len(), 2);
    a.write(&[8; 18000]).unwrap();
    assert_eq!(startup_packets(&mut a, start).len(), 1);
    let middle = (6000u32 >> a.peer_scale) as u16;
    inject(&mut a, start + 1, seq, base, ACK, middle, &[]);
    assert_eq!(startup_packets(&mut a, start + 1).len(), 3);
    let large = (60000u32 >> a.peer_scale) as u16;
    inject(&mut a, start + 2, seq, base, ACK, large, &[]);
    assert_eq!(startup_packets(&mut a, start + 2).len(), 4);
    assert!(startup_packets(&mut a, start + 2).is_empty());
    assert_eq!(a.snd_nxt.distance_from(base), 10000);

    for capped in [false, true] {
        let (mut a, _) = startup_paced_pair(
            ConnectionConfig {
                initial_window: InitialWindow::Iw10,
                ..config(65536, 1000)
            },
            100,
        );
        if capped {
            a.config.pacing.as_mut().unwrap().max_bytes_per_second = Some(10000);
        } else {
            a.config.pacing.as_mut().unwrap().initial_window_burst = false;
        }
        a.write(&[7; 20000]).unwrap();
        assert_eq!(startup_packets(&mut a, start).len(), 2);
        assert!(a.general_pacing_deadline(start).is_some());
    }
}

#[test]
fn initial_pacing_burst_is_not_refilled_after_idle_or_rto() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    let start = 100001;
    let seq = a.receive.next();
    let window = (a.snd_wnd >> a.peer_scale) as u16;
    a.write(&[7; 2000]).unwrap();
    startup_packets(&mut a, start);
    let end = a.snd_nxt;
    inject(&mut a, start + 100000, seq, end, ACK, window, &[]);
    a.write(&[7; 20000]).unwrap();
    assert_eq!(startup_packets(&mut a, start + 2000000).len(), 2);
    assert!(!a.initial_pacing_open);

    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    a.write(&[7; 20000]).unwrap();
    startup_packets(&mut a, start);
    let due = a.rto_deadline.unwrap();
    a.timeout(due).unwrap();
    assert!(!a.initial_pacing_open);
    let old = a.snd_nxt;
    let repaired = startup_packets(&mut a, due);
    assert_eq!(repaired.len(), 1);
    assert_eq!(a.snd_nxt, old);
}

#[test]
fn initial_pacing_burst_reserved_output_uses_physical_time_and_no_new_credit() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        u32::MAX - 4999,
    );
    a.write(&[7; 20000]).unwrap();
    let mut bytes = [0; 1500];
    let now = 100001;
    let base = a.snd_nxt;
    for i in 0..10 {
        let n = a
            .transmit_selected(if i == 0 { now } else { now + 500000 }, &mut bytes, true)
            .unwrap()
            .unwrap();
        let p = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
        assert_eq!(p.header.sequence, base.wrapping_add(i * 1000).0);
        let mut d = a.last_departure.unwrap();
        assert!(d.initial_burst);
        let before = a.pacer;
        assert_eq!(a.reserved_pacing_deadline(now + 500000, &d), None);
        assert_eq!(a.pacer, before); // selection and checking consume no physical rate debt
        a.accept_reserved_output(now + 500000, &mut d, 0, 1000, true)
            .unwrap();
    }
    assert_eq!(a.snd_nxt.distance_from(base), 10000);
    assert!(a.general_pacing_deadline(now + 500000).is_some());
    assert_eq!(a.last_sent, now + 500000);
}

#[test]
fn initial_pacing_burst_path_mss_change_does_not_add_an_ordinary_burst() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    let now = 100001;
    a.write(&[7; 4000]).unwrap();
    assert_eq!(startup_packets(&mut a, now).len(), 4);
    a.lower_mss(500).unwrap();
    a.write(&[7; 16000]).unwrap();
    // A reduction schedules repacketization of outstanding data. That repair
    // must use ordinary rate credit rather than the initial-flight exemption.
    assert!(a.retx_pending);
    assert_eq!(a.initial_pacing_room(), 0);
    assert!(startup_packets(&mut a, now).is_empty());
    let due = a.general_pacing_deadline(now).unwrap();
    assert!(due > now);
    assert!(startup_packets(&mut a, due - 1).is_empty());
    let repair = startup_packets(&mut a, due);
    assert_eq!(repair.len(), 1);
    assert_eq!(repair[0].1, 500);
    assert!(!a.initial_pacing_open);
}

#[test]
fn initial_pacing_burst_syn_timeout_and_persist_probe_do_not_rearm_it() {
    let cfg = ConnectionConfig {
        pacing: Some(PacingConfig::default()),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        ..config(65536, 1000)
    };
    let mut a = Connection::active(tuple(), cfg.clone(), 100, 0).unwrap();
    packet(&mut a, 0);
    let due = a.rto_deadline.unwrap();
    a.timeout(due).unwrap();
    assert!(!a.initial_pacing_open);
    let syn = packet(&mut a, due);
    let syn = wire::parse(ip(tuple()), &syn).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, due + 1, &syn).unwrap();
    deliver(&mut b, &mut a, due + 100000);
    deliver(&mut a, &mut b, due + 100001);
    a.write(&[7; 20000]).unwrap();
    assert_eq!(startup_packets(&mut a, due + 100002).len(), 2);

    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            initial_window: InitialWindow::Iw10,
            ..config(65536, 1000)
        },
        100,
    );
    let seq = a.receive.next();
    let base = a.snd_una;
    inject(&mut a, 100001, seq, base, ACK, 0, &[]);
    a.write(&[7; 20000]).unwrap();
    let due = a.persist_deadline.unwrap();
    a.timeout(due).unwrap();
    let probe = startup_packets(&mut a, due);
    assert_eq!(probe.iter().map(|p| p.1).sum::<usize>(), 0);
    assert!(a.initial_pacing_open);
    inject(&mut a, due + 100000, seq, base, ACK, 60000, &[]);
    assert_eq!(startup_packets(&mut a, due + 100000).len(), 10);
}

#[test]
fn initial_pacing_burst_ecn_feedback_reinstates_ordinary_rate_without_prr() {
    let (mut a, _) = startup_paced_pair(
        ConnectionConfig {
            congestion_algorithm: CongestionAlgorithm::Cubic,
            initial_window: InitialWindow::Iw10,
            ecn: true,
            ..config(65536, 1000)
        },
        100,
    );
    assert!(a.transport_info().ecn_negotiated);
    let now = 100001;
    a.write(&[7; 2000]).unwrap();
    assert_eq!(startup_packets(&mut a, now).len(), 2);
    a.write(&[7; 18000]).unwrap();
    let seq = a.receive.next();
    let ack = a.snd_una;
    let window = (a.snd_wnd >> a.peer_scale) as u16;
    inject(&mut a, now, seq, ack, ACK | ECE, window, &[]);
    assert!(a.congestion.in_ecn_response(a.snd_una));
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.cwnd(), 7000);
    assert_eq!(a.initial_pacing_room(), 0);
    assert!(startup_packets(&mut a, now).is_empty());
    let due = a.general_pacing_deadline(now).unwrap();
    assert_eq!(startup_packets(&mut a, due).len(), 1);
}
