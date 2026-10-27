use super::*;
use alloc::format;

fn warmed(
    algorithm: CongestionAlgorithm,
    ecn: bool,
    iss: u32,
    policy: InitialWindow,
) -> Connection {
    let mut cfg = config(131_072, 1000);
    cfg.initial_window = policy;
    cfg.congestion_algorithm = algorithm;
    cfg.rto_min_us = 200_000;
    cfg.ecn = ecn;
    cfg.nagle = false;
    let (mut a, mut b) = pair(cfg, iss);
    assert_eq!(a.transport_info().ecn_negotiated, ecn);
    let initial = a.initial_window() as usize;
    a.write(&vec![1; initial]).unwrap();
    let mut sent = 0;
    let mut out = [0; 65535];
    while let Some(n) = a.transmit(100_000, &mut out).unwrap() {
        let segment = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
        sent += segment.payload.len();
        b.input(100_000, &segment).unwrap();
    }
    assert_eq!(sent, initial);
    b.immediate_ack();
    deliver(&mut b, &mut a, 200_000);
    assert_eq!(a.flight(), 0);
    assert!(a.congestion.cwnd() > a.restart_window());
    a
}

fn input_ack(a: &mut Connection, now: Instant, ack: Seq, window: u16) {
    let next = a.receive.next();
    inject(a, now, next, ack, ACK, window, &[]);
}

fn queue_closed(a: &mut Connection, bytes: usize) -> Instant {
    input_ack(a, 200_001, a.snd_una, 0);
    a.write(&vec![2; bytes]).unwrap();
    a.persist_deadline.unwrap()
}

fn emit(a: &mut Connection, now: Instant, reserved: bool) -> Option<(Header, usize, u8)> {
    let mut out = [0; 65535];
    let n = if reserved {
        a.transmit_selected(now, &mut out, true).unwrap()?
    } else {
        a.transmit(now, &mut out).unwrap()?
    };
    let segment = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
    let result = (segment.header, segment.payload.len(), a.last_output_ecn);
    if reserved {
        let mut departure = a.last_departure.unwrap();
        a.accept_reserved_output(now, &mut departure, 0, result.1, true)
            .unwrap();
    }
    Some(result)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Reno/CUBIC and both restart-window policies, with/without ECN, wrap and scalar/reserved output: empty persist controls preserve the prior cwnd/epoch; the first actual new-data departure performs idle reduction and carries CWR. Failed encoding cannot consume it.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
//= type=test
//= reason=Empty persist control and repeated closed-window feedback remain Not-ECT and CWR-free; the first actual data after reopening has independently checked ECN signaling.
//# Therefore, the TCP data sender MUST NOT set either an ECT codepoint or the CWR bit on window probe packets.
fn persist_restart_feedback_survives_probe_ack_and_failed_output() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        for ecn in [false, true] {
            for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
                for reserved in [false, true] {
                    for iss in [100, u32::MAX - 5000] {
                        let mut a = warmed(algorithm, ecn, iss, policy);
                        let deadline = queue_closed(&mut a, 20_000);
                        a.timeout(deadline).unwrap();
                        let before = (
                            a.congestion.cwnd(),
                            a.ecn_cwr_pending,
                            format!("{:?}", a.iw_epoch),
                            a.last_sent,
                        );
                        assert_eq!(
                            a.transmit(deadline, &mut [0; 19]),
                            Err(Error::OutputTooSmall)
                        );
                        let probe = emit(&mut a, deadline, reserved).unwrap();
                        assert_eq!((probe.1, probe.0.flags & CWR, probe.2), (0, 0, 0));
                        assert_eq!(Seq(probe.0.sequence), a.snd_una.wrapping_add(u32::MAX));
                        assert_eq!(
                            (
                                a.congestion.cwnd(),
                                a.ecn_cwr_pending,
                                format!("{:?}", a.iw_epoch),
                                a.last_sent
                            ),
                            before
                        );
                        let ack = a.snd_una;
                        input_ack(&mut a, deadline + 1, ack, 0);
                        assert_eq!(a.flight(), 0);
                        let ack = a.snd_una;
                        input_ack(&mut a, deadline + 2, ack, 32768);
                        assert_eq!(a.persist_deadline, None);
                        assert_eq!(
                            a.transmit(deadline + 2, &mut [0; 19]),
                            Err(Error::OutputTooSmall)
                        );
                        assert_eq!(
                            (
                                a.congestion.cwnd(),
                                a.ecn_cwr_pending,
                                format!("{:?}", a.iw_epoch),
                                a.last_sent
                            ),
                            before
                        );
                        let base = a.snd_nxt;
                        let first = emit(&mut a, deadline + 2, reserved).unwrap();
                        assert_eq!(a.congestion.cwnd(), a.restart_window());
                        assert_eq!(
                            (first.0.flags & CWR != 0, first.2),
                            (ecn, if ecn { 2 } else { 0 })
                        );
                        assert!(!a.ecn_cwr_pending);
                        let mut bytes = first.1;
                        while let Some((header, count, _)) = emit(&mut a, deadline + 2, reserved) {
                            assert_eq!(header.flags & CWR, 0);
                            bytes += count;
                        }
                        if policy == InitialWindow::Iw10 {
                            let epoch = a.iw_epoch.unwrap();
                            assert_eq!(
                                (epoch.start, epoch.fresh_start, epoch.bytes),
                                (base, Some(base), bytes as u32)
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn persist_restart_loss_threshold_counts_only_fresh_data() {
    for size in [4096, 4097] {
        for reserved in [false, true] {
            let mut a = warmed(
                CongestionAlgorithm::Cubic,
                true,
                u32::MAX - 5000,
                InitialWindow::Iw10,
            );
            let deadline = queue_closed(&mut a, size);
            let prior = format!("{:?}", a.iw_epoch);
            a.timeout(deadline).unwrap();
            assert_eq!(emit(&mut a, deadline, reserved).unwrap().1, 0);
            assert_eq!(format!("{:?}", a.iw_epoch), prior);
            let ack = a.snd_una;
            input_ack(&mut a, deadline + 1, ack, 32768);
            let mut sent = 0;
            while let Some((_, count, _)) = emit(&mut a, deadline + 1, reserved) {
                sent += count;
            }
            assert_eq!(sent, size);
            assert_eq!(a.iw_epoch.unwrap().bytes, size as u32);
            let rto = a.rto_deadline.unwrap();
            a.timeout(rto).unwrap();
            assert_eq!(a.iw_fallback, size > 4096);
        }
    }
}

#[test]
fn repeated_empty_probe_feedback_preserves_idle_epoch() {
    for reserved in [false, true] {
        let mut a = warmed(CongestionAlgorithm::Cubic, true, 100, InitialWindow::Iw10);
        let mut deadline = queue_closed(&mut a, 20_000);
        let before = (
            a.congestion.cwnd(),
            a.snd_nxt,
            a.last_sent,
            format!("{:?}", a.iw_epoch),
        );
        for _ in 0..3 {
            a.timeout(deadline).unwrap();
            let probe = emit(&mut a, deadline, reserved).unwrap();
            assert_eq!((probe.1, probe.2, probe.0.flags & CWR), (0, 0, 0));
            let ack = a.snd_una;
            input_ack(&mut a, deadline + 1, ack, 0);
            assert_eq!(
                (
                    a.congestion.cwnd(),
                    a.snd_nxt,
                    a.last_sent,
                    format!("{:?}", a.iw_epoch)
                ),
                before
            );
            assert!(!a.ecn_cwr_pending);
            deadline = a.persist_deadline.unwrap();
        }
    }
}
