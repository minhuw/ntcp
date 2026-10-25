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

// Probe ACK progress is independent of the ordinary restart ACK clock.
#[test]
// Primarily validates a shared ECN transition, independent of Linux packet grouping.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Reno/CUBIC and both selected restart windows, with/without ECN, wrap and scalar/reserved output: a successful probe-led idle reduction retains CWR until the first new data. Probe ACK progress and failed output cannot discard it.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.6
//= type=test
//= reason=The first idle persist probe and its retry remain Not-ECT and without CWR while the deferred CWR notification survives.
//# Therefore, the TCP data sender MUST NOT set either an ECT codepoint or the CWR bit on window probe packets.
fn persist_restart_feedback_survives_probe_ack_and_failed_output() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        for ecn in [false, true] {
            for policy in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
                for ack_probe in [false, true] {
                    for reserved in [false, true] {
                        for iss in [100, u32::MAX - 5000] {
                            let mut a = warmed(algorithm, ecn, iss, policy);
                            let deadline = queue_closed(&mut a, 20_000);
                            a.timeout(deadline).unwrap();
                            let before = (
                                a.congestion.cwnd(),
                                a.ecn_cwr_pending,
                                format!("{:?}", a.iw_epoch),
                            );
                            assert_eq!(
                                a.transmit(deadline, &mut [0; 19]),
                                Err(Error::OutputTooSmall)
                            );
                            assert_eq!(
                                (
                                    a.congestion.cwnd(),
                                    a.ecn_cwr_pending,
                                    format!("{:?}", a.iw_epoch)
                                ),
                                before
                            );
                            let probe = emit(&mut a, deadline, reserved).unwrap();
                            assert_eq!(probe.1, 1);
                            assert_eq!(probe.0.flags & CWR, 0);
                            assert_eq!(probe.2, 0);
                            assert_eq!(a.congestion.cwnd(), a.restart_window());
                            assert_eq!(a.ecn_cwr_pending, ecn);
                            if policy == InitialWindow::Iw10 {
                                let epoch = a.iw_epoch.unwrap();
                                assert_eq!(epoch.start, Seq(probe.0.sequence));
                                assert_eq!(epoch.bytes, 1);
                                assert!(epoch.open && epoch.fresh_start.is_none());
                            }
                            let ack = if ack_probe { a.snd_nxt } else { a.snd_una };
                            input_ack(&mut a, deadline + 1, ack, 0);
                            if policy == InitialWindow::Iw10 {
                                assert!(a.iw_epoch.unwrap().open);
                                assert!(a.iw_epoch.unwrap().fresh_start.is_none());
                            }
                            let ack = a.snd_una;
                            input_ack(&mut a, deadline + 2, ack, 32768);
                            let state = (a.ecn_cwr_pending, format!("{:?}", a.iw_epoch));
                            assert_eq!(
                                a.transmit(deadline + 2, &mut [0; 19]),
                                Err(Error::OutputTooSmall)
                            );
                            assert_eq!((a.ecn_cwr_pending, format!("{:?}", a.iw_epoch)), state);
                            let first = emit(&mut a, deadline + 2, reserved).unwrap();
                            assert!(first.1 != 0);
                            assert_eq!(first.0.flags & CWR != 0, ecn);
                            assert_eq!(first.2, if ecn { 2 } else { 0 });
                            assert!(!a.ecn_cwr_pending);
                            let mut fresh_bytes = first.1;
                            while let Some((header, count, _)) =
                                emit(&mut a, deadline + 2, reserved)
                            {
                                assert_eq!(header.flags & CWR, 0);
                                fresh_bytes += count;
                            }
                            if policy == InitialWindow::Iw10 {
                                let epoch = a.iw_epoch.unwrap();
                                assert_eq!(epoch.bytes, fresh_bytes as u32 + 1);
                                assert_eq!(epoch.fresh_start, Some(Seq(first.0.sequence)));
                                assert!(epoch.open);
                                let rto = a.rto_deadline.unwrap();
                                a.timeout(rto).unwrap();
                                assert!(a.iw_fallback);
                                assert_eq!(a.restart_window(), 4000);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn persist_restart_probe_only_ack_does_not_close_started_bulk_epoch() {
    for iss in [100, u32::MAX - 5000] {
        let mut a = warmed(CongestionAlgorithm::Cubic, true, iss, InitialWindow::Iw10);
        let deadline = queue_closed(&mut a, 20_000);
        a.timeout(deadline).unwrap();
        emit(&mut a, deadline, false).unwrap();
        let probe_end = a.snd_nxt;
        let ack = a.snd_una;
        input_ack(&mut a, deadline + 1, ack, 32768);
        let first = emit(&mut a, deadline + 1, false).unwrap();
        assert_eq!(first.0.sequence, probe_end.0);
        input_ack(&mut a, deadline + 2, probe_end, 32768);
        assert!(a.iw_epoch.unwrap().open);
        while emit(&mut a, deadline + 2, false).is_some() {}
        assert!(a.iw_epoch.unwrap().bytes > 4096);
        let fresh_end = probe_end.wrapping_add(1);
        input_ack(&mut a, deadline + 3, fresh_end, 32768);
        assert!(!a.iw_epoch.unwrap().open);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc6928#section-2
//= type=test
//= reason=The real initiating probe byte is counted once, repeated copies are not double-counted, and ordinary payload fills the same restart range through wrap. Exactly4096 and4097 transmitted bytes distinguish future restart fallback after actual RTO.
//# Furthermore, to limit any negative effect that a larger initial window may have on links with limited bandwidth or buffer space, implementations SHOULD fall back to RFC 3390 for the restart window (RW) if any packet loss is detected during either the initial window or a restart window, and more than 4 KB of data is sent.
fn persist_restart_loss_threshold_counts_unique_probe_byte() {
    for bytes in [4096, 4097] {
        for iss in [100, u32::MAX - 5000] {
            let mut a = warmed(CongestionAlgorithm::Cubic, false, iss, InitialWindow::Iw10);
            let deadline = queue_closed(&mut a, bytes);
            a.timeout(deadline).unwrap();
            let probe = emit(&mut a, deadline, false).unwrap();
            let ack = a.snd_una;
            input_ack(&mut a, deadline + 1, ack, 0);
            let retry = a.rto_deadline.unwrap();
            a.timeout(retry).unwrap();
            let repeated = emit(&mut a, retry, false).unwrap();
            assert_eq!(
                (probe.0.sequence, probe.1),
                (repeated.0.sequence, repeated.1)
            );
            assert_eq!(a.iw_epoch.unwrap().bytes, 1);
            let ack = a.snd_una;
            input_ack(&mut a, retry + 1, ack, 32768);
            let mut sent = 0;
            while let Some((_, count, _)) = emit(&mut a, retry + 1, false) {
                sent += count;
            }
            assert_eq!(sent, bytes - 1);
            assert_eq!(a.iw_epoch.unwrap().bytes as usize, bytes);
            let rto = a.rto_deadline.unwrap();
            a.timeout(rto).unwrap();
            assert_eq!(a.iw_fallback, bytes > 4096);
        }
    }
}

#[test]
fn persist_restart_fresh_reservation_cancel_restores_pending_epoch() {
    let mut a = warmed(CongestionAlgorithm::Cubic, false, 100, InitialWindow::Iw10);
    let deadline = queue_closed(&mut a, 20_000);
    a.timeout(deadline).unwrap();
    emit(&mut a, deadline, false).unwrap();
    let high = a.snd_nxt;
    input_ack(&mut a, deadline + 1, high, 0);
    input_ack(&mut a, deadline + 2, high, 32768);
    let epoch = format!("{:?}", a.iw_epoch);
    let mut out = [0; 65535];
    a.transmit_selected(deadline + 2, &mut out, true)
        .unwrap()
        .unwrap();
    assert!(a.iw_epoch.unwrap().fresh_start.is_some());
    assert!(a.cancel_reserved_resource(deadline + 3).unwrap());
    assert_eq!(a.snd_nxt, high);
    assert_eq!(format!("{:?}", a.iw_epoch), epoch);
    let retry = a.local_resource.unwrap().retry_at.unwrap();
    a.timeout(retry).unwrap();
    emit(&mut a, retry, false).unwrap();
    assert!(a.iw_epoch.unwrap().fresh_start.is_some());
}

#[test]
fn persist_restart_probe_and_cwr_reservations_remain_immutable() {
    let mut a = warmed(CongestionAlgorithm::Cubic, true, 100, InitialWindow::Iw10);
    let deadline = queue_closed(&mut a, 20_000);
    a.timeout(deadline).unwrap();
    let mut out = [0; 65535];
    a.transmit_selected(deadline, &mut out, true)
        .unwrap()
        .unwrap();
    assert!(a.ecn_cwr_pending);
    let epoch = format!("{:?}", a.iw_epoch);
    assert!(!a.cancel_reserved_resource(deadline).unwrap());
    assert_eq!(format!("{:?}", a.iw_epoch), epoch);
    let mut d = a.last_departure.unwrap();
    a.accept_reserved_output(deadline + 1, &mut d, 0, 1, true)
        .unwrap();
    let high = a.snd_nxt;
    input_ack(&mut a, deadline + 2, high, 32768);
    let n = a
        .transmit_selected(deadline + 3, &mut out, true)
        .unwrap()
        .unwrap();
    let data = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
    assert_ne!(data.header.flags & CWR, 0);
    assert!(!a.cancel_reserved_resource(deadline + 3).unwrap());
    let count = data.payload.len();
    let mut d = a.last_departure.unwrap();
    a.accept_reserved_output(deadline + 4, &mut d, 0, count, true)
        .unwrap();
    assert!(!a.ecn_cwr_pending);
}

#[test]
fn persist_restart_repeated_probe_ack_progress_keeps_feedback_and_bulk_boundary() {
    for ack_probe in [false, true] {
        let mut a = warmed(
            CongestionAlgorithm::Cubic,
            true,
            u32::MAX - 5000,
            InitialWindow::Iw10,
        );
        let mut deadline = queue_closed(&mut a, 20_000);
        for round in 0..3 {
            a.timeout(deadline).unwrap();
            let (header, count, ecn) = emit(&mut a, deadline, true).unwrap();
            assert_eq!((header.flags & CWR, count, ecn), (0, 1, 0));
            assert!(a.ecn_cwr_pending);
            assert!(a.iw_epoch.unwrap().fresh_start.is_none());
            assert_eq!(a.iw_epoch.unwrap().bytes, 1);
            let ack = if ack_probe { a.snd_nxt } else { a.snd_una };
            input_ack(&mut a, deadline + 1, ack, 0);
            assert!(a.iw_epoch.unwrap().open);
            if round != 2 {
                deadline = a.persist_deadline.or(a.rto_deadline).unwrap();
            }
        }
        let ack = a.snd_una;
        input_ack(&mut a, deadline + 2, ack, 32768);
        let first = emit(&mut a, deadline + 2, true).unwrap();
        assert_ne!(first.0.flags & CWR, 0);
        assert!(!a.ecn_cwr_pending);
        assert_eq!(a.iw_epoch.unwrap().fresh_start, Some(Seq(first.0.sequence)));
        while emit(&mut a, deadline + 2, true).is_some() {}
        let rto = a.rto_deadline.unwrap();
        a.timeout(rto).unwrap();
        assert!(a.iw_fallback);
    }
}

#[test]
fn persist_restart_gso_fragmentation_carries_cwr_on_first_physical_segment() {
    let mut a = warmed(
        CongestionAlgorithm::Cubic,
        true,
        u32::MAX - 5000,
        InitialWindow::Iw10,
    );
    let deadline = queue_closed(&mut a, 20_000);
    a.timeout(deadline).unwrap();
    emit(&mut a, deadline, true).unwrap();
    let high = a.snd_nxt;
    input_ack(&mut a, deadline + 1, high, 32768);
    let mut payload = [0; 65535];
    let mut bytes = [0; 65535];
    let n = a
        .transmit_selected_with_gso(
            deadline + 2,
            &mut bytes,
            true,
            Some(crate::output_reservation::GsoBuffer {
                limits: crate::GsoLimits {
                    max_bytes: 4000,
                    max_segments: 4,
                },
                payload: &mut payload,
            }),
        )
        .unwrap()
        .unwrap();
    let mut d = a.last_departure.unwrap();
    assert_eq!(d.segmentation.unwrap().payload_len, 4000);
    assert_eq!(a.iw_epoch.unwrap().bytes, 4001);
    let mut reservation = crate::output_reservation::OutputReservation::new();
    reservation.bytes.resize(65535, 0);
    reservation.payload.extend_from_slice(&payload[..4000]);
    let token = reservation.token(None).unwrap();
    reservation.capture(
        crate::Transmit {
            connection: None,
            tx_timestamp: None,
            ipv4_options: Default::default(),
            ecn: a.last_output_ecn,
            ip: ip(tuple()),
            len: n,
            hop_limit: 64,
            dscp: 0,
        },
        &bytes,
        token,
    );
    reservation.current.as_mut().unwrap().departure = Some(d);
    let mut count = 0;
    crate::allocation_tests::fail_after(0, || {
        while reservation.current.as_ref().unwrap().offset < 4000 {
            let p = reservation.fragment(1020, &mut bytes).unwrap();
            let segment = wire::parse(p.ip, &bytes[..p.len]).unwrap();
            assert_eq!(segment.header.flags & CWR != 0, count == 0);
            assert_eq!(segment.payload.len(), 1000);
            let r = reservation.current.as_mut().unwrap();
            a.accept_reserved_output(deadline + 2, &mut d, r.offset, r.emitted_bytes, r.finished)
                .unwrap();
            r.offset += r.emitted_bytes;
            r.sacks += r.emitted_sacks;
            count += 1;
        }
    });
    assert_eq!(count, 4);
    assert!(!a.ecn_cwr_pending);
}
