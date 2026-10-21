// SPDX-License-Identifier: MIT
// Deterministic diagnostic: local rejection is distinct from network loss.
use super::*;

fn local_state(a: &Connection, now: u64, label: &str, rows: &mut Vec<String>) {
    state(a, now, label, rows);
    let info = a.transport_info();
    rows.push(format!(
        "{{\"event\":\"{label}_statistics\",\"at_us\":{now},\"retransmitted\":{},\"reordering\":{},\"receive_used\":{},\"rtt_us\":{},\"state\":\"{:?}\"}}",
        info.retransmitted, info.reordering, info.receive_used, info.rtt_us.unwrap_or(0), info.state
    ));
}

fn local_sender(rows: &mut Vec<String>) -> Connection {
    local_sender_with_algorithm(rows, PrrAlgorithm::Rfc9937)
}

fn local_sender_with_algorithm(rows: &mut Vec<String>, algorithm: PrrAlgorithm) -> Connection {
    let mut cfg = profile(algorithm);
    // Remaining common upstream options, audited against packet_profile::config.
    cfg.coalesce_read_window_updates = true;
    cfg.abort_with_ack = true;
    cfg.output_push_batch_segments = 0;
    cfg.output_group_flush = true;
    cfg.output_push_batch_retransmissions = false;
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
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 7],
        &[],
        &mut bytes,
    )
    .unwrap();
    let syn = wire::parse(incoming, &bytes[..n]).unwrap();
    let mut a = Connection::passive(tuple(), cfg, 0, 0, &syn).unwrap();
    output(&mut a, 0, rows);
    inject(&mut a, 20_000, Seq(1), Seq(1), ACK, 320, &[]);
    assert_eq!(a.rtt.srtt(), Some(20_000));
    a.write(&[7; 10_000]).unwrap();
    assert_eq!(
        output(&mut a, 20_000, rows)
            .iter()
            .map(|p| p.2)
            .sum::<usize>(),
        10_000
    );
    for blocks in [&[(9001, 10001)][..], &[(3001, 4001), (9001, 10001)][..]] {
        inject_sack(&mut a, 40_000, Seq(1), Seq(1), ACK, 320, &[], blocks);
        local_state(&a, 40_000, "prefix_sack", rows);
        assert!(output(&mut a, 40_000, rows).is_empty());
    }
    assert_eq!(a.rack.counts().sacked, 2);
    inject(&mut a, 40_000, Seq(1), Seq(10001), ACK, 320, &[]);
    local_state(&a, 40_000, "prefix_cumulative_ack", rows);
    assert_eq!(a.rack.counts().sacked, 0);
    // Record actual growth. Do not change pacing provenance or fabricate cwnd19.
    assert!(advance(&mut a, 60_000, rows).is_empty());
    a.write(&[8; 2000]).unwrap();
    let sent = output(&mut a, 65_000, rows);
    assert_eq!(sent.iter().map(|p| p.2).sum::<usize>(), 2000);
    inject_sack(
        &mut a,
        85_000,
        Seq(1),
        Seq(10001),
        ACK,
        320,
        &[],
        &[(11001, 12001)],
    );
    local_state(&a, 85_000, "second_flight_sack", rows);
    assert!(output(&mut a, 85_000, rows).is_empty());
    let deadline = a.next_deadline().unwrap();
    assert!(deadline > 85_000 && deadline <= 105_000);
    a.timeout(deadline).unwrap();
    local_state(&a, deadline, "rack_timeout_before_selection", rows);
    assert!(a.congestion.in_recovery());
    assert_eq!(a.rack.counts().lost, 1);
    assert_eq!(a.rack.counts().retransmitted, 0);
    a
}

#[test]
fn local_rack_failure_selection_rejection_acceptance_and_encoding_controls() {
    for mode in [
        "rejected_then_accepted",
        "encode_failure_then_input",
        "abandoned",
    ] {
        let mut rows = Vec::new();
        let mut a = local_sender(&mut rows);
        let now = a.now;
        let before = a.prr.unwrap().counters();
        if mode == "encode_failure_then_input" {
            assert_eq!(
                a.transmit_selected(now, &mut [0; 20], true),
                Err(Error::OutputTooSmall)
            );
            assert_eq!(a.prr.unwrap().counters(), before);
            assert_eq!(a.rack.counts().retransmitted, 0);
            local_state(&a, now, "encoding_failed", &mut rows);
            // No selection/reservation exists, so input is legal immediately.
            inject_sack(
                &mut a,
                115_000,
                Seq(1),
                Seq(10001),
                ACK,
                320,
                &[9; 1000],
                &[(11001, 12001)],
            );
            assert_eq!(a.receive_used, 1000);
            assert!(a.congestion.in_recovery());
            assert_eq!(a.prr.unwrap().counters(), before);
            assert_eq!(a.rack.counts().retransmitted, 0);
            local_state(&a, 115_000, "input_after_encoding_failure", &mut rows);
        } else {
            let mut bytes = [0; 2048];
            let n = a.transmit_selected(now, &mut bytes, true).unwrap().unwrap();
            let seg = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
            assert_eq!((seg.header.sequence, seg.payload.len()), (10001, 1000));
            let mut departure = a.last_departure.unwrap();
            local_state(&a, now, "reserved_selection_not_submitted", &mut rows);
            let selected = a.prr.unwrap().counters();
            assert_eq!(selected, before);
            // The timer-entry repair charges PRR only at physical acceptance.
            // Logical RACK selection is retained while ownership is reserved.
            assert!(a.prr.unwrap().timer_repair());
            assert_eq!(a.rack.counts().retransmitted, 1);
            if mode == "abandoned" {
                a.abandon_reserved_output();
                assert_eq!(a.state(), State::Closed);
                local_state(&a, now, "abandon_aborts_owner", &mut rows);
            } else {
                a.reject_reserved_output();
                assert_eq!(a.prr.unwrap().counters(), selected);
                assert_eq!(a.rack.counts().retransmitted, 1);
                local_state(&a, now, "certified_rejection_keeps_admission", &mut rows);
                // Real owner retains reservation across rejection. Never inject
                // into the core until the immutable selected repair is accepted.
                a.accept_reserved_output(110_000, &mut departure, 0, 1000, true)
                    .unwrap();
                let accepted = a.prr.unwrap().counters();
                assert_eq!(accepted.2, selected.2 + 1000);
                assert!(!a.prr.unwrap().timer_repair());
                local_state(&a, 110_000, "repair_physically_accepted", &mut rows);
                inject_sack(
                    &mut a,
                    115_000,
                    Seq(1),
                    Seq(10001),
                    ACK,
                    320,
                    &[9; 1000],
                    &[(11001, 12001)],
                );
                assert_eq!(a.receive_used, 1000);
                assert!(a.congestion.in_recovery());
                assert_eq!(a.prr.unwrap().counters(), accepted);
                local_state(&a, 115_000, "input_after_acceptance", &mut rows);
            }
        }
        if let Ok(directory) = std::env::var("NTCP_LOCAL_TX_STUDY_DIR") {
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                format!("{directory}/core-{mode}.json"),
                format!("[\n{}\n]\n", rows.join(",\n")),
            )
            .unwrap();
        }
    }
}

#[test]
fn local_repair_accepted_prefix_cannot_be_cancelled_or_refund_prr() {
    let mut rows = Vec::new();
    let mut a = local_sender(&mut rows);
    let mut bytes = [0; 2048];
    a.transmit_selected(a.now, &mut bytes, true)
        .unwrap()
        .unwrap();
    let mut departure = a.last_departure.unwrap();
    assert_eq!(a.transport_info().retransmitted, 0);
    a.accept_reserved_output(100_000, &mut departure, 0, 500, false)
        .unwrap();
    assert!(!a.cancel_reserved_repair());
    assert_eq!(a.prr.unwrap().counters().2, 500);
    assert_eq!(a.transport_info().retransmitted, 1);
    a.accept_reserved_output(110_000, &mut departure, 500, 500, true)
        .unwrap();
    assert!(!a.cancel_reserved_repair());
    assert_eq!(a.prr.unwrap().counters().2, 1000);
    assert!(!a.prr.unwrap().timer_repair());
}

#[test]
fn local_repair_cancel_restores_receive_sack_debt_and_partial_retry_history() {
    let mut rows = Vec::new();
    let mut a = local_sender(&mut rows);
    // Out-of-order inbound data needs a SACK on the failed outbound repair.
    inject_sack(
        &mut a,
        91_000,
        Seq(1001),
        Seq(10001),
        ACK,
        320,
        &[9; 1000],
        &[(11001, 12001)],
    );
    // The duplicate requires the two-block above-ACK D-SACK form; neither
    // report may be consumed by a sequence of locally rejected attempts.
    inject_sack(
        &mut a,
        91_000,
        Seq(1001),
        Seq(10001),
        ACK,
        320,
        &[9; 1000],
        &[(11001, 12001)],
    );
    let mut expected = None;
    for at in [91_000, 92_000, 93_000] {
        let prior = (
            a.rack.pipe(),
            a.rack.counts().retransmitted,
            a.prr.unwrap().counters(),
        );
        let mut bytes = [0; 2048];
        let n = a.transmit_selected(at, &mut bytes, true).unwrap().unwrap();
        let seg = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
        assert!(!seg.raw_options.is_empty());
        let view = (
            seg.header.sequence,
            seg.header.acknowledgment,
            seg.raw_options.to_vec(),
            seg.payload.to_vec(),
        );
        if let Some(expected) = &expected {
            assert_eq!(&view, expected);
        } else {
            expected = Some(view);
        }
        assert!(a.cancel_reserved_repair());
        assert_eq!(
            (
                a.rack.pipe(),
                a.rack.counts().retransmitted,
                a.prr.unwrap().counters()
            ),
            prior
        );
        assert!(a.receive.has_pending_report());
        assert_eq!(
            a.rack
                .original_retry_span(Seq(10001), Seq(11001))
                .unwrap()
                .successful_retries,
            0
        );
    }
    inject_sack(
        &mut a,
        94_000,
        Seq(1),
        Seq(10001),
        ACK,
        320,
        &[8; 1000],
        &[(11001, 12001)],
    );
    assert_eq!(a.receive.next(), Seq(2001));
    let mut bytes = [0; 2048];
    let n = a
        .transmit_selected(95_000, &mut bytes, true)
        .unwrap()
        .unwrap();
    let seg = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
    assert_eq!(seg.header.acknowledgment, 2001);
    let count = seg.payload.len();
    let mut d = a.last_departure.unwrap();
    a.accept_reserved_output(96_000, &mut d, 0, count, true)
        .unwrap();
    assert_eq!(a.prr.unwrap().counters().2, count as u64);
}

#[test]
fn rack_timer_prr_window_survives_rejection_and_zero_delivery() {
    let mut rows = Vec::new();
    let mut a = local_sender(&mut rows);
    let before = a.prr.unwrap().counters();
    let target = a.congestion.recovery_target();
    assert_eq!(before, (1000, 0, 0));
    assert_eq!(a.rack.pipe(), 0);
    assert_eq!(a.prr.unwrap().credit(), 1000);
    assert_eq!((a.congestion.cwnd(), target), (1000, 2000));
    let admission = 1000;
    local_state(&a, 90_000, "synchronized_timer_entry", &mut rows);
    for at in [90_000, 91_000] {
        let mut bytes = [0; 2048];
        let n = a.transmit_selected(at, &mut bytes, true).unwrap().unwrap();
        let packet = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
        assert_eq!(
            (packet.header.sequence, packet.payload.len()),
            (10001, 1000)
        );
        assert_eq!(a.transport_info().retransmitted, 0);
        assert!(a.cancel_reserved_repair());
        assert_eq!(a.prr.unwrap().counters(), before);
        assert_eq!(a.prr.unwrap().credit(), 1000);
        assert_eq!(a.congestion.cwnd(), admission);
        assert_eq!(a.congestion.recovery_target(), target);
    }
    local_state(&a, 91_000, "twice_rejected", &mut rows);
    inject_sack(
        &mut a,
        95_000,
        Seq(1),
        Seq(10001),
        ACK,
        320,
        &[9; 1000],
        &[(11001, 12001)],
    );
    assert_eq!(a.receive_used, 1000);
    assert_eq!(a.prr.unwrap().counters(), before);
    assert_eq!(a.prr.unwrap().credit(), 1000);
    assert_eq!(a.congestion.cwnd(), admission);
    local_state(&a, 95_000, "input_without_new_delivery", &mut rows);
    let mut bytes = [0; 2048];
    let n = a
        .transmit_selected(96_000, &mut bytes, true)
        .unwrap()
        .unwrap();
    let packet = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
    assert_eq!(
        (packet.header.sequence, packet.payload.len()),
        (10001, 1000)
    );
    assert_eq!(packet.header.acknowledgment, 1001);
    let mut departure = a.last_departure.unwrap();
    a.accept_reserved_output(96_000, &mut departure, 0, 1000, true)
        .unwrap();
    assert_eq!(a.prr.unwrap().counters(), (1000, 0, 1000));
    assert_eq!(a.prr.unwrap().credit(), 0);
    assert_eq!(a.transport_info().retransmitted, 1);
    assert_eq!(a.congestion.recovery_target(), target);
    assert!(output(&mut a, 96_000, &mut rows).iter().all(|p| p.2 == 0));
    local_state(&a, 96_000, "repair_accepted_credit_exhausted", &mut rows);
    inject(&mut a, 100_000, Seq(1001), Seq(12001), ACK, 320, &[]);
    assert!(!a.congestion.in_recovery());
    assert!(a.prr.is_none());
    assert_eq!(a.congestion.cwnd(), target);
    local_state(
        &a,
        100_000,
        "recovery_completed_at_original_target",
        &mut rows,
    );
    if let Ok(directory) = std::env::var("NTCP_RACK_WINDOW_FIX_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            format!("{directory}/core-window-regression.json"),
            format!("[\n{}\n]\n", rows.join(",\n")),
        )
        .unwrap();
    }
}

#[test]
fn rack_timer_prr_window_keeps_legacy_entry_policy() {
    let mut rows = Vec::new();
    let a = local_sender_with_algorithm(&mut rows, PrrAlgorithm::LegacyInitialCredit);
    assert_eq!(a.congestion.cwnd(), 2000);
    assert_eq!(a.congestion.recovery_target(), 2000);
    assert_eq!(a.prr.unwrap().credit(), 1000);
}
