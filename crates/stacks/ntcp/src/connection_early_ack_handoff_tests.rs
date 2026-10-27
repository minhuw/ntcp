use super::*;

fn cfg(units: u64, timestamps: bool, rack: bool) -> ConnectionConfig {
    let mut cfg = ConnectionConfig {
        nagle: false,
        timestamps,
        sack: true,
        rack,
        prr: true,
        prr_algorithm: PrrAlgorithm::Rfc9937,
        rto_min_us: 1,
        pmtud: Some(crate::PmtudConfig::new(1500)),
        ..config(8192, if timestamps { 1012 } else { 1000 })
    };
    cfg.timebase.units_per_second = units;
    cfg
}

fn ticks(a: &Connection, us: u64) -> u64 {
    a.config.timebase.ticks_from_us(us)
}

fn ack(a: &mut Connection, us: u64, offset: u32, blocks: &[(u32, u32)]) {
    let now = ticks(a, us);
    let base = a.iss.wrapping_add(1);
    let mut options = wire::Options::default();
    if a.timestamps {
        options.timestamps = Some((a.timestamp_value(now), a.timestamp_value(ticks(a, 20_000))));
    }
    for (slot, &(l, r)) in options.sack_blocks.iter_mut().zip(blocks) {
        *slot = Some((base.wrapping_add(l).0, base.wrapping_add(r).0));
    }
    let segment = Segment {
        header: Header {
            source_port: a.tuple.remote.port(),
            destination_port: a.tuple.local.port(),
            sequence: a.receive.next().0,
            acknowledgment: base.wrapping_add(offset).0,
            flags: ACK,
            window: 8192,
            urgent_pointer: 0,
        },
        options,
        raw_options: &[],
        payload: &[],
    };
    a.input(now, &segment).unwrap();
}

// Early output remains disabled. Model its proposed state using real scalar
// output/physical ledger entries, restoring the unacknowledged SYN afterward.
fn response(mut cfg: ConnectionConfig, iss: u32, pending: bool, fin: bool) -> Connection {
    if fin {
        cfg.initial_window = InitialWindow::Iw10;
    }
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
        options: wire::Options {
            mss: Some(cfg.mss),
            sack_permitted: cfg.sack,
            timestamps: cfg.timestamps.then_some((0, 0)),
            ..Default::default()
        },
        raw_options: &[],
        payload: b"request",
    };
    let mut a = Connection::passive_with_receive(
        tuple(),
        cfg,
        iss,
        0,
        &syn,
        true,
        &mut None,
        RxTimestamps::default(),
        RxPacketTimestamps::default(),
    )
    .unwrap();
    let now = ticks(&a, 20_000);
    packet(&mut a, now);
    assert!(a.syn_committed && a.fast_open_early);
    assert!(!a.syn_delivered);
    assert_eq!(a.mss, 1000);
    if pending {
        a.state = State::Established;
        a.handshake_complete = true;
        a.snd_una = a.iss.wrapping_add(1);
    } else {
        ack(&mut a, 30_000, 0, &[]);
    }
    for (n, us) in [
        (500, 40_000),
        (500, 50_000),
        (1000, 60_000),
        (1000, 70_000),
        (1000, 80_000),
    ] {
        a.write(&vec![42; n]).unwrap();
        if fin && us == 80_000 {
            a.shutdown().unwrap();
        }
        let now = ticks(&a, us);
        let bytes = packet(&mut a, now);
        let segment = wire::parse(ip(a.tuple()), &bytes).unwrap();
        assert_eq!(segment.payload.len(), n);
        assert_eq!(segment.header.flags & FIN != 0, fin && us == 80_000);
    }
    if pending {
        a.handshake_complete = false;
        a.state = if fin {
            State::FinWait1
        } else {
            State::SynReceived
        };
        a.snd_una = a.iss;
    }
    assert_eq!(a.data_flight(), 4000);
    a.take_events();
    a
}

#[test]
fn early_ack_handoff_entry_delivery_matches_established_including_wrap() {
    for units in [1_000_000, 1_000_000_000] {
        for iss in [100, u32::MAX - 1000] {
            for timestamps in [false, true] {
                for pending in [false, true] {
                    let mut a = response(cfg(units, timestamps, false), iss, pending, false);
                    ack(&mut a, 200_000, 500, &[(1000, 4000)]);
                    assert_eq!(a.state(), State::Established);
                    assert!(a.syn_delivered);
                    assert_eq!(a.acknowledged, 500);
                    assert_eq!(a.send.len(), 3500);
                    assert!(a.sack_recovery.is_some());
                    assert_eq!(a.prr.unwrap().counters(), (4000, 3500, 0));
                    assert_eq!(a.rack.delivered_segments, 4);
                    assert_eq!(a.transport_info().delivered_segments, 5); // Plus SYN, once.
                    assert_eq!(a.take_events().acknowledged, Some(500));
                    let counters = a.prr.unwrap().counters();
                    ack(&mut a, 210_000, 500, &[(1000, 4000)]);
                    assert_eq!(a.prr.unwrap().counters(), counters);
                    assert_eq!(a.rack.delivered_segments, 4);
                    assert_eq!(a.take_events().acknowledged, None);
                    ack(&mut a, 220_000, 4000, &[]);
                    assert!(a.prr.is_none());
                    assert_eq!(a.acknowledged, 4000);
                    assert_eq!(a.rack.delivered_segments, 5);
                    assert_eq!(a.send.len(), 0);
                }
            }
        }
    }
}

#[test]
fn early_ack_handoff_syn_only_partial_full_and_sack_once() {
    for units in [1_000_000, 1_000_000_000] {
        for iss in [100, u32::MAX - 1000] {
            for rack in [false, true] {
                for offset in [0, 250, 500, 4000] {
                    let mut a = response(cfg(units, true, rack), iss, true, false);
                    let cwnd = a.congestion.cwnd();
                    ack(&mut a, 200_000, offset, &[(3000, 4000)]);
                    assert_eq!(a.state(), State::Established);
                    assert!(a.syn_delivered);
                    assert_eq!(a.snd_una, a.iss.wrapping_add(1 + offset));
                    assert_eq!(a.acknowledged, u64::from(offset));
                    assert_eq!(a.data_flight(), 4000 - offset);
                    assert_eq!(a.send.len(), 4000 - offset as usize);
                    assert_eq!(
                        a.rack.delivered_segments,
                        if offset == 4000 {
                            5
                        } else {
                            1 + u64::from(offset == 500)
                        }
                    );
                    assert_eq!(a.rtt.srtt(), Some(ticks(&a, 180_000))); // SYN departure, not response.
                    assert_eq!(a.rtt.variance(), ticks(&a, 90_000)); // RTTVAR = R/2: one sample.
                    if offset < 500 {
                        assert_eq!(
                            a.rack.head_transmission(a.snd_una),
                            Some((a.iss.wrapping_add(501), ticks(&a, 40_000)))
                        );
                    }
                    if offset == 4000 {
                        assert_eq!(a.pmtud.as_ref().unwrap().info.search_low, 1052);
                    }
                    if offset == 0 {
                        assert!(a.congestion.cwnd() <= cwnd); // SACK may detect loss, never SYN growth.
                        assert_eq!(a.take_events().acknowledged, None);
                    } else {
                        assert_eq!(a.take_events().acknowledged, Some(u64::from(offset)));
                    }
                    let delivered = a.rack.delivered_segments;
                    let deadline = a.rto_deadline;
                    let path = a.pmtud.as_ref().unwrap().info;
                    ack(&mut a, 210_000, offset, &[(3000, 4000)]);
                    assert_eq!(a.acknowledged, u64::from(offset));
                    assert_eq!(a.rack.delivered_segments, delivered);
                    assert_eq!(
                        (a.rtt.srtt(), a.rtt.variance()),
                        (Some(ticks(&a, 180_000)), ticks(&a, 90_000))
                    );
                    assert_eq!(a.rto_deadline, deadline);
                    assert_eq!(a.pmtud.as_ref().unwrap().info, path);
                    assert_eq!(a.take_events().acknowledged, None);
                }
            }
        }
    }
}

#[test]
fn early_ack_handoff_rejects_full_ack_before_mutation_and_ignores_invalid_sack() {
    for iss in [100, u32::MAX - 1000] {
        for offset in [4001, u32::MAX - 8193] {
            let mut a = response(cfg(1_000_000, true, true), iss, true, false);
            let before = (
                a.snd_una,
                a.snd_nxt,
                a.send_base,
                a.send.len(),
                a.rto_deadline,
                a.sample,
                a.ts_recent,
                a.ts_latest,
            );
            ack(&mut a, 200_000, offset, &[(1000, 4000)]);
            assert!(a.handshake_pending());
            assert!(!a.syn_delivered);
            assert_eq!(
                (
                    a.snd_una,
                    a.snd_nxt,
                    a.send_base,
                    a.send.len(),
                    a.rto_deadline,
                    a.sample,
                    a.ts_recent,
                    a.ts_latest
                ),
                before
            );
            assert_eq!(a.acknowledged, 0);
            assert_eq!(a.rtt.srtt(), None);
            assert_eq!(a.rack.delivered_segments, 0);
            assert!(a.scoreboard.ranges().is_empty());
            assert!(a.prr.is_none());
        }
        for block in [(4000, 5000), (3000, 3000), (3000, 2000)] {
            let mut a = response(cfg(1_000_000, false, false), iss, true, false);
            ack(&mut a, 200_000, 500, &[block]);
            assert_eq!(a.acknowledged, 500); // Valid cumulative ACK still applies.
            assert!(a.scoreboard.ranges().is_empty());
            assert_eq!(a.rack.delivered_segments, 1);
            assert!(a.prr.is_none());
        }
    }
}

#[test]
fn early_ack_handoff_fin_data_and_empty_control_are_separate() {
    for iss in [100, u32::MAX - 1000] {
        for offset in [0, 500, 4000, 4001] {
            let mut a = response(cfg(1_000_000, false, false), iss, true, true);
            ack(&mut a, 200_000, offset, &[]);
            assert!(a.handshake_complete());
            assert_eq!(
                a.state(),
                if offset == 4001 {
                    State::FinWait2
                } else {
                    State::FinWait1
                }
            );
            assert_eq!(a.acknowledged, u64::from(offset.min(4000)));
            assert_eq!(a.send.len(), 4000 - offset.min(4000) as usize);
            assert_eq!(
                a.rack.delivered_segments,
                if offset >= 4000 {
                    5
                } else {
                    u64::from(offset == 500)
                }
            );
            assert!(!a.fin_delivered); // FIN is counted with its payload packet, not twice.
            assert_eq!(a.fin_sequence, Some(a.iss.wrapping_add(4001)));
        }
        let (mut a, _) = opening_for_close(config(8192, 1000), iss, false);
        a.passive_fast_open(None, true);
        a.shutdown().unwrap();
        packet(&mut a, 20);
        packet(&mut a, 30);
        assert_eq!(a.data_flight(), 0);
        let cwnd = a.congestion.cwnd();
        ack(&mut a, 200_000, 1, &[]);
        assert_eq!(a.state(), State::FinWait2);
        assert!(a.syn_delivered && a.fin_delivered);
        assert_eq!(a.acknowledged, 0);
        assert_eq!(a.congestion.cwnd(), cwnd);
    }
}

#[test]
fn early_ack_handoff_synack_retry_preserves_karn_and_three_second_floor() {
    for units in [1_000_000, 1_000_000_000] {
        for rack in [false, true] {
            for offset in [0, 500, 4000] {
                let mut a = response(cfg(units, true, rack), u32::MAX - 1000, true, false);
                let deadline = a.rto_deadline.unwrap();
                a.timeout(deadline).unwrap();
                let bytes = packet(&mut a, deadline);
                let retry = wire::parse(ip(a.tuple()), &bytes).unwrap();
                assert_eq!(retry.header.flags & (SYN | ACK), SYN | ACK);
                assert!(retry.payload.is_empty());
                assert!(a.sample.is_none());
                assert!(a.syn_timed_out);
                ack(&mut a, 1_200_000, offset, &[(3000, 4000)]);
                assert!(a.syn_delivered && a.syn_timed_out);
                assert_eq!(a.rtt.srtt(), None);
                assert!(a.rto() >= ticks(&a, 3_000_000));
                assert_eq!(a.rto_deadline, (offset < 4000).then(|| a.now + a.rto()));
                assert_eq!(a.acknowledged, u64::from(offset));
            }
        }
    }
}

#[test]
fn early_ack_handoff_bare_syn_credit_and_non_sack_payload_growth() {
    for iss in [100, u32::MAX - 1000] {
        for sack in [false, true] {
            for offset in [0, 500, 4000] {
                let mut cfg = cfg(1_000_000, false, false);
                cfg.sack = sack;
                let mut a = response(cfg, iss, true, false);
                let cwnd = a.congestion.cwnd();
                ack(&mut a, 200_000, offset, &[]);
                assert_eq!(a.congestion.cwnd(), cwnd + offset.min(1000));
                assert_eq!(a.acknowledged, u64::from(offset));
                assert_eq!(
                    a.rack.delivered_segments,
                    if offset == 4000 {
                        5
                    } else {
                        u64::from(offset == 500)
                    }
                );
                assert_eq!((a.rtt.srtt(), a.rtt.variance()), (Some(180_000), 90_000));
                assert!(a.prr.is_none());
            }
        }
    }
}

#[test]
fn early_ack_handoff_ack_timestamp_reports_once_and_bad_echo_cannot_resample() {
    for units in [1_000_000, 1_000_000_000] {
        for bad_echo in [false, true] {
            let mut a = response(cfg(units, true, true), u32::MAX - 1000, true, false);
            // Model a rejected SYN echo while retaining valid response ledger timing.
            if bad_echo {
                a.sample = Some((a.iss.wrapping_add(1), ticks(&a, 21_000)));
            }
            a.tx_timestamps.resize(2, usize::MAX).unwrap();
            for (cookie, target) in [(1, 499), (2, 3999)] {
                a.tx_timestamps.insert(
                    TxTimestampRequest {
                        cookie,
                        acknowledged: true,
                        ..Default::default()
                    },
                    target,
                );
            }
            ack(&mut a, 200_000, 500, &[(3000, 4000)]);
            assert_eq!(
                (a.rtt.srtt(), a.rtt.variance()),
                if bad_echo {
                    (None, 0)
                } else {
                    (Some(ticks(&a, 180_000)), ticks(&a, 90_000))
                }
            );
            let event = a.tx_timestamps.next().unwrap();
            assert_eq!(
                (event.cookie, event.target, event.stage),
                (1, 499, TxTimestampStage::Acknowledged)
            );
            assert_eq!(
                event.outcome,
                crate::TxTimestampOutcome::Recorded {
                    value: ticks(&a, 200_000),
                    clock: TxTimestampClock::CallerTicks(a.config.timebase),
                }
            );
            assert_eq!(a.tx_timestamps.next(), None);
            ack(&mut a, 210_000, 500, &[(3000, 4000)]);
            assert_eq!(a.tx_timestamps.next(), None);
            ack(&mut a, 220_000, 4000, &[]);
            let event = a.tx_timestamps.next().unwrap();
            assert_eq!(
                (event.cookie, event.target, event.stage),
                (2, 3999, TxTimestampStage::Acknowledged)
            );
            assert_eq!(a.tx_timestamps.next(), None);
            ack(&mut a, 230_000, 4000, &[]);
            assert_eq!(a.tx_timestamps.next(), None);
        }
    }
}

#[test]
fn early_ack_handoff_syn_only_sack_keeps_rejected_syn_echo_out_of_rto() {
    for units in [1_000_000, 1_000_000_000] {
        let mut a = response(cfg(units, true, true), u32::MAX - 1000, true, false);
        a.sample = Some((a.iss.wrapping_add(1), ticks(&a, 21_000)));
        ack(&mut a, 200_000, 0, &[(3000, 4000)]);
        assert_eq!(a.rtt.srtt(), None);
        assert!(a.syn_delivered);
        assert_eq!(a.acknowledged, 0);
        assert_eq!(a.send.len(), 4000);
        assert_eq!(a.rack.delivered_segments, 1);
        assert!(a.sample.is_none());
    }
}
