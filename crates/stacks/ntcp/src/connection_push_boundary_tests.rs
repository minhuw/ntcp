// SPDX-License-Identifier: MIT
// Test-only PUSH grouping controls. No fixture or production policy changes.
use super::*;

fn push_sender() -> Connection {
    let cfg = profile(2);
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
            window: 65535,
            urgent_pointer: 0,
        },
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 7],
        &[],
        &mut bytes,
    )
    .unwrap();
    let syn = wire::parse(incoming, &bytes[..n]).unwrap();
    let mut a = Connection::passive(tuple(), cfg, 0, 0, &syn).unwrap();
    packet(&mut a, 0);
    inject(&mut a, 100_000, Seq(1), Seq(1), ACK, 511, &[]);
    assert_eq!(a.congestion.cwnd(), 10000);
    assert_eq!(a.rtt.srtt(), Some(100_000));
    assert!(!a.timestamps);
    a
}

fn push_snapshot(a: &Connection, at: u64, label: &str, rows: &mut Vec<String>) {
    state(a, at, label, rows);
    rows.push(format!("{{\"event\":\"{label}_clocks\",\"at_us\":{at},\"last_sent_us\":{},\"rto_us\":{},\"cwnd\":{},\"flight\":{},\"snd_wnd\":{},\"restart_window\":{}}}",a.last_sent,a.rto(),a.congestion.cwnd(),a.flight(),a.snd_wnd,a.restart_window()));
}

fn push_output(
    a: &mut Connection,
    at: u64,
    policy: &str,
    rows: &mut Vec<String>,
) -> Vec<(u32, usize, bool)> {
    let mut result = Vec::new();
    for _ in 0..64 {
        if a.output_push_batch.is_none() {
            let limit = match policy {
                "fixed2" => 2,
                "fixed5" => 5,
                "half_window" | "capped2" | "capped10" => {
                    let idle = a.flight() == 0 && at.saturating_sub(a.last_sent) >= a.rto();
                    let effective = if idle {
                        a.congestion.cwnd().min(a.restart_window())
                    } else {
                        a.congestion.cwnd()
                    };
                    let quota = (effective / a.mss as u32 / 2)
                        .max(1)
                        .min(effective.saturating_sub(a.flight()) / a.mss as u32);
                    let cap = match policy {
                        "capped2" => 2,
                        "capped10" => 10,
                        _ => u32::MAX,
                    };
                    quota.max(1).min(cap) as u16
                }
                _ => unreachable!(),
            };
            a.config.output_push_batch_segments = limit;
        }
        let mut bytes = [0; 2048];
        let Some(n) = a.transmit(at, &mut bytes).unwrap() else {
            return result;
        };
        let seg = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
        if !seg.payload.is_empty() {
            result.push((
                seg.header.sequence,
                seg.payload.len(),
                seg.header.flags & PSH != 0,
            ));
        }
        rows.push(format!("{{\"event\":\"wire\",\"at_us\":{at},\"seq\":{},\"ack\":{},\"bytes\":{},\"flags\":{},\"batch_limit\":{}}}",seg.header.sequence,seg.header.acknowledgment,seg.payload.len(),seg.header.flags,a.config.output_push_batch_segments));
    }
    panic!("push output did not quiesce");
}

#[test]
fn push_boundary_idle_and_window_reopen_shared_controls() {
    let mut reference = [None, None];
    for policy in ["fixed2", "fixed5", "half_window", "capped2", "capped10"] {
        for reopen in [false, true] {
            let mut a = push_sender();
            let mut rows = Vec::new();
            let mut ranges = Vec::new();
            a.write(&[7; 26000]).unwrap();
            let initial = push_output(&mut a, 100_000, policy, &mut rows);
            assert_eq!(initial.iter().map(|p| p.1).sum::<usize>(), 10000);
            let pushes: Vec<_> = initial
                .iter()
                .filter(|p| p.2)
                .map(|p| p.0 + p.1 as u32)
                .collect();
            assert_eq!(
                pushes,
                match policy {
                    "fixed2" | "capped2" => vec![2001, 4001, 6001, 8001, 10001],
                    _ => vec![5001, 10001],
                }
            );
            ranges.extend(initial.iter().map(|p| (p.0, p.1)));
            inject(&mut a, 200_000, Seq(1), Seq(10001), ACK, 511, &[]);
            push_snapshot(&a, 200_000, "first_data_ack", &mut rows);
            let tail = push_output(&mut a, 200_000, policy, &mut rows);
            assert_eq!(tail.iter().map(|p| p.1).sum::<usize>(), 16000);
            assert!(tail.last().unwrap().2); // Original application's final PUSH.
            ranges.extend(tail.iter().map(|p| (p.0, p.1)));
            inject(
                &mut a,
                300_000,
                Seq(1),
                Seq(26001),
                ACK,
                if reopen { 0 } else { 511 },
                &[],
            );
            push_snapshot(&a, 300_000, "second_data_ack", &mut rows);
            let grown = a.congestion.cwnd();
            if reopen {
                a.write(&[8; 20000]).unwrap();
                push_output(&mut a, 300_000, policy, &mut rows);
                for _ in 0..32 {
                    let Some(deadline) = a.next_deadline().filter(|d| *d < 3_300_000) else {
                        break;
                    };
                    a.timeout(deadline).unwrap();
                    push_snapshot(&a, deadline, "persist_due", &mut rows);
                    push_output(&mut a, deadline, policy, &mut rows);
                    assert!(a.next_deadline().is_none_or(|d| d > deadline));
                }
                push_snapshot(&a, 3_300_000, "before_window_reopen", &mut rows);
                inject(&mut a, 3_300_000, Seq(1), Seq(26001), ACK, 511, &[]);
            } else {
                assert_eq!(a.transmit(2_300_000, &mut [0; 19]), Ok(None));
                a.write(&[8; 20000]).unwrap();
                let before = (a.congestion.cwnd(), a.snd_nxt, a.now, a.last_sent);
                assert_eq!(
                    a.transmit(2_300_000, &mut [0; 19]),
                    Err(Error::OutputTooSmall)
                );
                assert_eq!((a.congestion.cwnd(), a.snd_nxt, a.now, a.last_sent), before);
            }
            let at = if reopen { 3_300_000 } else { 2_300_000 };
            push_snapshot(&a, at, "before_restart_output", &mut rows);
            let sent = push_output(&mut a, at, policy, &mut rows);
            push_snapshot(&a, at, "after_restart_output", &mut rows);
            if !reopen {
                assert_eq!(a.congestion.cwnd(), 10000);
                assert_eq!(sent.iter().map(|p| p.1).sum::<usize>(), 10000);
                assert!(grown > 10000);
            }
            // All controls change only optional PUSH placement in this replay.
            let key = (
                ranges,
                a.congestion.cwnd(),
                sent.iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(),
            );
            let index = usize::from(reopen);
            if let Some(expected) = &reference[index] {
                assert_eq!(&key, expected);
            } else {
                reference[index] = Some(key);
            }
            if let Ok(directory) = std::env::var("NTCP_PUSH_STUDY_DIR") {
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    format!(
                        "{directory}/{policy}-{}.json",
                        if reopen { "reopen" } else { "idle" }
                    ),
                    format!("[{}]\n", rows.join(",")),
                )
                .unwrap();
            }
        }
    }
}

#[test]
fn push_boundary_half_window_control_changes_https_second_segment_flag() {
    for policy in ["fixed2", "fixed5", "half_window", "capped2", "capped10"] {
        let mut cfg = profile(2);
        cfg.nagle = false;
        let mut a = Connection::active(tuple(), cfg, 0, 0).unwrap();
        packet(&mut a, 0);
        let incoming = ip(reverse(tuple()));
        let mut bytes = [0; 64];
        let n = wire::encode(
            incoming,
            Header {
                source_port: tuple().remote.port(),
                destination_port: tuple().local.port(),
                sequence: 0,
                acknowledgment: 1,
                flags: SYN | ACK,
                window: 5792,
                urgent_pointer: 0,
            },
            &[2, 4, 3, 206, 4, 2, 1, 1, 1, 3, 3, 7],
            &[],
            &mut bytes,
        )
        .unwrap();
        let synack = wire::parse(incoming, &bytes[..n]).unwrap();
        a.input(100_000, &synack).unwrap();
        let mut rows = Vec::new();
        push_output(&mut a, 100_000, policy, &mut rows);
        assert_eq!(a.mss, 974);
        a.write(&[1; 517]).unwrap();
        push_output(&mut a, 100_000, policy, &mut rows);
        inject(&mut a, 200_000, Seq(1), Seq(518), ACK, 229, &[]);
        inject(&mut a, 200_000, Seq(1), Seq(1), ACK | PSH, 229, &[2; 143]);
        push_output(&mut a, 200_000, policy, &mut rows);
        assert_eq!(a.read(&mut [0; 1000]).unwrap(), 143);
        a.write(&[3; 51]).unwrap();
        push_output(&mut a, 200_000, policy, &mut rows);
        a.write(&[4; 2002]).unwrap();
        let body = push_output(&mut a, 230_000, policy, &mut rows);
        assert_eq!(
            body.iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(),
            vec![(569, 974), (1543, 974), (2517, 54)]
        );
        assert_eq!(
            body.iter().map(|p| p.2).collect::<Vec<_>>(),
            if matches!(policy, "fixed2" | "capped2") {
                vec![false, true, true]
            } else {
                vec![false, false, true]
            }
        );
        if let Ok(directory) = std::env::var("NTCP_PUSH_STUDY_DIR") {
            std::fs::write(
                format!("{directory}/{policy}-https.json"),
                format!("[{}]\n", rows.join(",")),
            )
            .unwrap();
        }
    }
}
