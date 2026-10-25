// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Diagnostic controls for common upstream PUSH admission, no fixture exceptions.
extern crate std;
use super::*;
use alloc::{format, string::String};

fn profile() -> ConnectionConfig {
    ConnectionConfig {
        receive_capacity: 8 * 1024 * 1024,
        receive_ip_payload_limit: 65515,
        send_ip_payload_limit: 65515,
        mss: 1460,
        initial_window: InitialWindow::Iw10,
        congestion_algorithm: CongestionAlgorithm::Cubic,
        cubic_hystart: true,
        cubic_fast_convergence: true,
        ecn: false,
        timestamps: true,
        sack: true,
        rack: true,
        tlp: true,
        prr: true,
        prr_algorithm: PrrAlgorithm::Rfc9937,
        prr_pacing: false,
        pacing: None,
        rto_min_us: 200000,
        adaptive_ack: true,
        delayed_ack_us: 200000,
        coalesce_read_window_updates: true,
        ..ConnectionConfig::default()
    }
}

fn setup(mss: u16, sack: bool, syn_at: u64, ack_at: u64) -> Connection {
    setup_config(mss, sack, syn_at, ack_at, profile())
}

fn setup_config(
    mss: u16,
    sack: bool,
    syn_at: u64,
    ack_at: u64,
    config: ConnectionConfig,
) -> Connection {
    setup_sequence(mss, sack, syn_at, ack_at, config, 0)
}

fn setup_sequence(
    mss: u16,
    sack: bool,
    syn_at: u64,
    ack_at: u64,
    config: ConnectionConfig,
    iss: u32,
) -> Connection {
    let mut options = vec![2, 4];
    options.extend_from_slice(&mss.to_be_bytes());
    if sack {
        options.extend_from_slice(&[4, 2, 1, 1]);
    }
    options.extend_from_slice(&[1, 3, 3, 7]);
    let incoming = ip(reverse(tuple()));
    let mut bytes = [0; 64];
    let n = wire::encode(
        incoming,
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
    let syn = wire::parse(incoming, &bytes[..n]).unwrap();
    let mut a = Connection::passive(tuple(), config, iss, syn_at, &syn).unwrap();
    packet(&mut a, syn_at);
    inject(
        &mut a,
        ack_at,
        Seq(1),
        Seq(iss.wrapping_add(1)),
        ACK,
        if mss == 1460 { 257 } else { 320 },
        &[],
    );
    assert_eq!(a.state(), State::Established);
    assert_eq!(a.mss, usize::from(mss));
    assert!(!a.timestamps);
    assert_eq!(a.sack_send, sack);
    a
}

fn state(a: &Connection, now: u64, label: &str, rows: &mut Vec<String>) {
    let (fs, d, out) = a.prr.map_or((0, 0, 0), |p| p.counters());
    let pipe = a.prr.map_or(a.rack.pipe(), |p| {
        a.sack_recovery
            .map_or_else(|| p.non_sack_pipe(a.rack.pipe()), |r| r.pipe)
    });
    rows.push(format!("{{\"event\":\"{label}\",\"at_us\":{now},\"cwnd\":{},\"ssthresh\":{},\"target\":{},\"flight\":{},\"pipe\":{pipe},\"snd_una\":{},\"snd_nxt\":{},\"send_base\":{},\"queued\":{},\"prr_fs\":{fs},\"prr_delivered\":{d},\"prr_out\":{out},\"credit\":{},\"limited_pending\":{},\"limited_sent\":{}}}", a.congestion.cwnd(),a.congestion.ssthresh(),a.congestion.recovery_target(),a.flight(),a.snd_una.0,a.snd_nxt.0,a.send_base.0,a.send.len(),a.prr.map_or(0,|p|p.credit()),a.limited_pending,a.limited_sent));
}

fn drain(a: &mut Connection, now: u64, rows: &mut Vec<String>) -> Vec<(u32, usize, bool)> {
    let mut packets = Vec::new();
    for _ in 0..64 {
        state(a, now, "before_output", rows);
        let mut out = [0; 2048];
        let Some(n) = a.transmit(now, &mut out).unwrap() else {
            state(a, now, "output_none", rows);
            return packets;
        };
        let seg = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
        if !seg.payload.is_empty() {
            packets.push((
                seg.header.sequence,
                seg.payload.len(),
                seg.header.flags & PSH != 0,
            ));
        }
        rows.push(format!(
            "{{\"event\":\"wire\",\"at_us\":{now},\"seq\":{},\"len\":{},\"flags\":{}}}",
            seg.header.sequence,
            seg.payload.len(),
            seg.header.flags
        ));
    }
    panic!("output did not quiesce");
}
fn ack(
    a: &mut Connection,
    now: u64,
    cumulative: u32,
    sacks: &[(u32, u32)],
    rows: &mut Vec<String>,
) -> Vec<(u32, usize, bool)> {
    let mut ready = Vec::new();
    for _ in 0..64 {
        let Some(deadline) = a.next_deadline().filter(|&d| d <= now) else {
            break;
        };
        assert!(deadline >= a.now);
        a.timeout(deadline).unwrap();
        ready.extend(drain(a, deadline, rows));
        assert!(a.next_deadline().is_none_or(|d| d > deadline));
    }
    inject_sack(
        a,
        now,
        Seq(1),
        Seq(cumulative),
        ACK,
        if a.mss == 1460 { 257 } else { 320 },
        &[],
        sacks,
    );
    state(a, now, "after_ack", rows);
    ready.extend(drain(a, now, rows));
    ready
}
fn save(name: &str, rows: &[String]) {
    if let Ok(dir) = std::env::var("NTCP_REMAINING17_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            format!("{dir}/{name}.json"),
            format!("[{}]\n", rows.join(",")),
        )
        .unwrap();
    }
}

#[test]
fn no_sack_cubic_first_repair_keeps_byte_prr() {
    let mut a = setup(1460, false, 100000, 200000);
    let mut rows = Vec::new();
    a.write(&vec![0x55; 5840]).unwrap();
    drain(&mut a, 200000, &mut rows);
    for _ in 0..2 {
        assert!(ack(&mut a, 300000, 1, &[], &mut rows).is_empty());
    }
    inject(&mut a, 300000, Seq(1), Seq(1), ACK, 257, &[]);
    state(&a, 300000, "entry_credit", &mut rows);
    let prr = a.prr.unwrap();
    assert_eq!(prr.counters(), (5840, 1460, 0));
    assert_eq!(a.congestion.recovery_target(), 10220);
    assert_eq!(prr.non_sack_pipe(a.rack.pipe()), 2920);
    assert_eq!(prr.credit(), 1460);
    assert_eq!(drain(&mut a, 300000, &mut rows), [(1, 1460, false)]);
    save("core-fr4-first-credit", &rows);
}

#[test]
fn limited_transmit_growth_separates_retirement_and_fresh_credit() {
    let mut results = Vec::new();
    for sack in [false, true] {
        for hystart in [false, true] {
            for queued in [10000, 15000] {
                for duplicates in 0..=2u32 {
                    let mut config = profile();
                    config.cubic_hystart = hystart;
                    let mut a = setup_config(1000, sack, 100000, 200000, config);
                    let mut rows = Vec::new();
                    a.write(&vec![0x55; queued]).unwrap();
                    assert_eq!(drain(&mut a, 200000, &mut rows).len(), 10);
                    assert_eq!(a.congestion.cwnd(), 10000);
                    for i in 0..duplicates {
                        let hi = 2001 + i * 1000;
                        let sacks = [(1001, hi)];
                        let sent = ack(
                            &mut a,
                            310000 + u64::from(i) * 10000,
                            1,
                            if sack { &sacks } else { &[] },
                            &mut rows,
                        );
                        assert_eq!(sent.len(), usize::from(queued > 10000));
                        assert_eq!(a.congestion.cwnd(), 10000);
                        assert_eq!(a.snd_una, Seq(1));
                        assert!(a.prr.is_none());
                    }
                    let prior_sacked = 3000 - a.scoreboard.unsacked_bytes(Seq(1), Seq(3001));
                    assert_eq!(prior_sacked, if sack { duplicates * 1000 } else { 0 });
                    let limited_sent = a.limited_sent;
                    let sent = ack(&mut a, 330000, 3001, &[], &mut rows);
                    assert_eq!(a.snd_una, Seq(3001));
                    assert_eq!(a.send.len(), queued - 3000);
                    assert_eq!(
                        a.congestion.cwnd(),
                        if hystart {
                            13000 - duplicates * 1000
                        } else {
                            11000
                        }
                    );
                    let growth_cwnd = a.congestion.cwnd();
                    assert!(a.prr.is_none());
                    assert!(sent.iter().all(|p| p.0 >= 10001 + duplicates * 1000));
                    if queued == 10000 {
                        assert!(sent.is_empty());
                        assert_eq!(limited_sent, 0);
                    }
                    if queued == 15000 && duplicates == 2 {
                        assert_eq!(limited_sent, 2000);
                        assert_eq!(sent, [(12001, 1000, false), (13001, 1000, true)]);
                        assert_eq!(
                            ack(&mut a, 350000, 5001, &[], &mut rows),
                            [(14001, 1000, true)]
                        );
                    }
                    results.push(format!(
                        "{{\"sack\":{sack},\"hystart\":{hystart},\"queued\":{queued},\"duplicates\":{duplicates},\"prior_sacked\":{prior_sacked},\"limited_sent\":{limited_sent},\"cwnd_after\":{},\"bytes_sent_after\":{}}}",
                        growth_cwnd, sent.iter().map(|p| p.1).sum::<usize>()
                    ));
                }
            }
        }
    }
    save("growth-matrix", &results);
}

#[test]
fn limited_transmit_repeated_sack_grants_no_extra_output_or_growth() {
    let mut a = setup(1000, true, 100000, 200000);
    let mut rows = Vec::new();
    a.write(&vec![0x55; 15000]).unwrap();
    assert_eq!(drain(&mut a, 200000, &mut rows).len(), 10);
    assert_eq!(
        ack(&mut a, 310000, 1, &[(1001, 2001)], &mut rows),
        [(10001, 1000, false)]
    );
    assert_eq!(a.congestion.cwnd(), 10000);
    assert!(ack(&mut a, 320000, 1, &[(1001, 2001)], &mut rows).is_empty());
    assert_eq!(a.congestion.cwnd(), 10000);
    assert_eq!(a.limited_sent, 1000);
    assert_eq!(a.scoreboard.unsacked_bytes(Seq(1), Seq(3001)), 2000);
    let sent = ack(&mut a, 330000, 3001, &[], &mut rows);
    assert_eq!(a.congestion.cwnd(), 12000);
    assert_eq!(sent.iter().map(|p| p.1).sum::<usize>(), 4000);
    assert_eq!(a.snd_nxt, Seq(15001));
    assert!(a.prr.is_none());
    save("growth-repeated-sack", &rows);
}

#[test]
fn limited_transmit_fresh_growth_exact_wire_and_sequence_wrap() {
    for sack in [false, true] {
        for iss in [0, u32::MAX - 499] {
            let mut a = setup_sequence(1000, sack, 100000, 200000, profile(), iss);
            let base = a.snd_una;
            let mut rows = Vec::new();
            a.write(&vec![0x55; 15000]).unwrap();
            assert_eq!(drain(&mut a, 200000, &mut rows).len(), 10);
            for i in 0..2u32 {
                let blocks = [(
                    base.wrapping_add(1000).0,
                    base.wrapping_add(2000 + i * 1000).0,
                )];
                assert_eq!(
                    ack(
                        &mut a,
                        310000 + u64::from(i) * 10000,
                        base.0,
                        if sack { &blocks } else { &[] },
                        &mut rows
                    ),
                    [(base.wrapping_add(10000 + i * 1000).0, 1000, false)]
                );
                assert_eq!(a.congestion.cwnd(), 10000);
                assert!(a.prr.is_none());
            }
            assert_eq!(a.growth_dupack_bytes, if sack { 0 } else { 2000 });
            assert_eq!(
                ack(&mut a, 330000, base.wrapping_add(3000).0, &[], &mut rows),
                [
                    (base.wrapping_add(12000).0, 1000, false),
                    (base.wrapping_add(13000).0, 1000, true)
                ]
            );
            assert_eq!(a.congestion.cwnd(), 11000);
            assert_eq!(a.send.len(), 12000);
            assert_eq!(a.acknowledged, 3000);
            assert_eq!(a.growth_dupack_bytes, 0);
            assert_eq!(
                ack(&mut a, 350000, base.wrapping_add(5000).0, &[], &mut rows),
                [(base.wrapping_add(14000).0, 1000, true)]
            );
            assert_eq!(a.congestion.cwnd(), 13000);
        }
    }
}

#[test]
fn limited_transmit_growth_estimate_consumes_bytes_under_ack_division() {
    for divided in [false, true] {
        let mut a = setup(1000, false, 100000, 200000);
        let mut rows = Vec::new();
        a.write(&vec![0x55; 10000]).unwrap();
        assert_eq!(drain(&mut a, 200000, &mut rows).len(), 10);
        assert!(ack(&mut a, 310000, 1, &[], &mut rows).is_empty());
        assert!(ack(&mut a, 320000, 1, &[], &mut rows).is_empty());
        assert_eq!(a.growth_dupack_bytes, 2000);
        let step = if divided { 1 } else { 3000 };
        for bytes in (step..=3000).step_by(step as usize) {
            assert!(ack(&mut a, 330000, 1 + bytes, &[], &mut rows).is_empty());
            assert_eq!(a.growth_dupack_bytes, 2000u32.saturating_sub(bytes));
            assert_eq!(a.congestion.cwnd(), 10000 + bytes.saturating_sub(2000));
        }
        assert_eq!(a.send.len(), 7000);
        assert_eq!(a.acknowledged, 3000);
        assert!(a.prr.is_none());
    }
}

#[test]
fn limited_transmit_sacked_tail_cannot_discount_historical_eligible_prefix() {
    let mut config = profile();
    config.rack = false;
    config.prr = false;
    config.tlp = false;
    let mut a = setup_config(1000, true, 100000, 200000, config);
    let mut rows = Vec::new();
    a.write(&vec![0x55; 10000]).unwrap();
    drain(&mut a, 200000, &mut rows);
    assert!(ack(&mut a, 330000, 9001, &[], &mut rows).is_empty());
    assert_eq!(a.congestion.cwnd(), 18000); // Fresh delayed ACK retains L=8.
    a.write(&vec![0x66; 2000]).unwrap();
    assert_eq!(drain(&mut a, 330000, &mut rows).len(), 2);
    assert_eq!(a.congestion.growth_prefix(Seq(9001), 3000), 1000);
    assert!(ack(&mut a, 340000, 9001, &[(10001, 12001)], &mut rows).is_empty());
    assert_eq!(a.congestion.cwnd(), 18000);
    assert!(ack(&mut a, 350000, 12001, &[], &mut rows).is_empty());
    assert_eq!(a.congestion.cwnd(), 19000);
    assert_eq!(a.send.len(), 0);
}

#[test]
fn limited_transmit_delivery_estimates_ignore_window_and_payload_acks() {
    let mut a = setup(1000, false, 100000, 200000);
    let mut rows = Vec::new();
    a.write(&vec![0x55; 10000]).unwrap();
    drain(&mut a, 200000, &mut rows);
    inject(&mut a, 310000, Seq(1), Seq(1), ACK, 319, &[]);
    assert_eq!(a.growth_dupack_bytes, 0);
    inject(&mut a, 320000, Seq(1), Seq(1), ACK, 319, b"x");
    assert_eq!(a.growth_dupack_bytes, 0);
    assert_eq!(a.congestion.cwnd(), 10000);
    let next = a.receive.next();
    inject(&mut a, 330000, next, Seq(3001), ACK, 319, &[]);
    assert_eq!(a.congestion.cwnd(), 13000);
    assert_eq!(a.acknowledged, 3000);
}

#[test]
fn limited_transmit_growth_estimates_end_on_rto_recovery_and_terminal() {
    for end in 0..3 {
        let mut a = setup(1000, false, 100000, 200000);
        let mut rows = Vec::new();
        a.write(&vec![0x55; 15000]).unwrap();
        drain(&mut a, 200000, &mut rows);
        ack(&mut a, 310000, 1, &[], &mut rows);
        ack(&mut a, 320000, 1, &[], &mut rows);
        assert_eq!(a.growth_dupack_bytes, 2000);
        match end {
            0 => {
                for _ in 0..8 {
                    let deadline = a.next_deadline().unwrap();
                    a.timeout(deadline).unwrap();
                    drain(&mut a, deadline, &mut rows);
                    if a.consecutive_timeouts != 0 {
                        break;
                    }
                }
                assert_ne!(a.consecutive_timeouts, 0);
            }
            1 => {
                ack(&mut a, 330000, 1, &[], &mut rows);
                assert!(a.prr.is_some());
            }
            _ => a.terminal(CloseReason::Reset),
        }
        assert_eq!(a.growth_dupack_bytes, 0);
    }
}

#[test]
fn no_sack_cubic_cwnd_basis_repair_and_recovery_completion() {
    let mut a = setup(1460, false, 100000, 200000);
    let mut rows = Vec::new();
    a.write(&vec![0x55; 5840]).unwrap();
    assert_eq!(drain(&mut a, 200000, &mut rows).len(), 4);
    for _ in 0..2 {
        assert!(ack(&mut a, 300000, 1, &[], &mut rows).is_empty());
    }
    inject(&mut a, 300000, Seq(1), Seq(1), ACK, 257, &[]);
    state(&a, 300000, "entry_credit", &mut rows);
    let prr = a.prr.unwrap();
    assert_eq!(prr.counters(), (5840, 1460, 0));
    assert_eq!(a.congestion.recovery_target(), 10220);
    assert_eq!(prr.non_sack_pipe(a.rack.pipe()), 2920);
    assert_eq!(prr.credit(), 1460);
    assert_eq!(drain(&mut a, 300000, &mut rows), [(1, 1460, false)]);
    assert_eq!(a.prr.unwrap().counters(), (5840, 1460, 1460));
    assert!(ack(&mut a, 400000, 5841, &[], &mut rows).is_empty());
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.cwnd(), 10220);
    assert_eq!(a.send.len(), 0);
    save("core-fr4-cwnd-basis", &rows);
}

#[test]
fn prr_fractional_headroom_stays_byte_exact() {
    let mut p = Prr::new(5840, 1460, PrrAlgorithm::Rfc9937);
    let delivered = p.non_sack_delivery(0, true);
    assert_eq!(delivered, 1460);
    p.acknowledge(delivered, 2920, 4088, false);
    assert_eq!(p.credit(), 1168);
}
