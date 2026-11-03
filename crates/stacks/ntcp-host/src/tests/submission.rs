use super::*;

type Side = (Host, Endpoint, IngressContext);

fn quote(frame: &[u8]) -> QuoteKey {
    let (ip, header, total, protocol) = if frame[0] >> 4 == 4 {
        ntcp_ip::quote_header(frame).unwrap()
    } else {
        ntcp_ip6::quote_header(frame).unwrap()
    };
    let t = &frame[header..];
    QuoteKey {
        source: ip.source,
        destination: ip.destination,
        header_len: header as u16,
        packet_len: total as u32,
        protocol,
        transport: QuotedSelector::Tcp {
            source_port: u16::from_be_bytes([t[0], t[1]]),
            destination_port: u16::from_be_bytes([t[2], t[3]]),
            sequence: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        },
    }
}
fn sequence(frame: &[u8]) -> u32 {
    let q = quote(frame);
    match q.transport {
        QuotedSelector::Tcp { sequence, .. } => sequence,
        _ => unreachable!(),
    }
}

// One physical call through the transaction with the given backend outcome.
fn attempt_with(
    side: &mut Side,
    now: u64,
    outcome: BackendOutcome,
) -> Option<(TransmitAttempt, Vec<u8>, Submission)> {
    let (attempt, _, frame) = selected(&mut side.1, now)?;
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let mut calls = 0;
    let result = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| {
            calls += 1;
            outcome
        })
        .unwrap();
    assert_eq!(calls, 1);
    Some((attempt, frame, result))
}
fn send(side: &mut Side, now: u64) -> Option<Vec<u8>> {
    let (_, frame, result) = attempt_with(side, now, BackendOutcome::Submitted)?;
    assert!(result == Submission::Submitted);
    Some(frame)
}
fn connected(
    v6: bool,
    cfg: &EndpointConfig,
    identity: u128,
) -> (Side, Side, ConnectionId, ConnectionId) {
    let (local, remote) = addresses(v6);
    let mut a = managed(local, identity, cfg.clone());
    let mut b = managed(remote, identity + 1, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    for side in [&mut a, &mut b] {
        settle(side);
        assert_eq!(side.0.ledger.records().count(), 0);
    }
    let child = b.1.accept(listener).unwrap();
    (a, b, id, child)
}
// `pump` submits through the transaction, sealing handshake evidence.
// Retire delivered data and drop the remaining (never retiring) control
// evidence, so a test counts only its own submissions.
fn settle(side: &mut Side) {
    side.0.collect(&side.1).unwrap();
    side.0.ledger.expire(u64::MAX);
}
fn records(host: &Host) -> Vec<Record> {
    host.ledger.records().collect()
}

#[test]
fn blocked_retry_revalidates_idempotently_and_seals_once() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, mut b, id, child) = connected(v6, &cfg, 1000);
        a.1.write(id, &[5; 1000]).unwrap();
        let (attempt, _, frame) = selected(&mut a.1, 100).unwrap();
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        // Repeated authority and validation reserve exactly one slot.
        for _ in 0..3 {
            a.0.egress_context(&mut a.1, attempt).unwrap();
            a.0.validate_egress(&mut a.1, context, &frame, 0).unwrap();
        }
        assert_eq!(a.0.ledger.pending_count(), 1);
        let mut ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        assert_eq!(
            a.0.submission_ticket(&mut a.1, context),
            Err(Error::InvalidContext)
        );
        let mut calls = 0;
        for retry in 0..3 {
            match a
                .0
                .submit(&mut a.1, 101 + retry, ticket, context, &frame, 0, |_| {
                    calls += 1;
                    BackendOutcome::WouldBlock
                })
                .unwrap()
            {
                Submission::Blocked(t) => ticket = t,
                other => panic!("{other:?}"),
            }
            assert_eq!(a.0.ledger.pending_count(), 1);
            assert!(records(&a.0).is_empty());
            assert!(a.1.transmit_attempt_packet(attempt).is_some());
        }
        let result =
            a.0.submit(&mut a.1, 110, ticket, context, &frame, 0, |_| {
                calls += 1;
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(result == Submission::Submitted);
        assert_eq!(calls, 4);
        assert_eq!(a.0.ledger.pending_count(), 0);
        assert!(a.1.transmit_attempt_packet(attempt).is_none());
        let sealed = records(&a.0);
        assert_eq!(sealed.len(), 1);
        let start = sequence(&frame);
        assert_eq!(
            sealed[0].evidence.transport,
            Selector::Tcp {
                source_port: 1000,
                destination_port: 8080,
                start,
                end: start.wrapping_add(1000),
            }
        );
        assert_eq!(sealed[0].committed_at, 110);
        assert!(!sealed[0].possibly_submitted);
        assert_eq!(sealed[0].evidence.owner, Owner::Tcp(id));
        assert_eq!(sealed[0].evidence.packet_len as usize, frame.len());
        let correlation = a.0.correlate(111, &quote(&frame));
        assert_eq!(correlation.unique, Some(sealed[0]));
        assert_eq!(
            correlation.path,
            Some(a.0.binding(id).unwrap().snapshot.path())
        );
        input(&mut b.0, &mut b.1, b.2, 112, &frame, 0);
        let mut bytes = [0; 2000];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), 1000);
        // A path change before a retry is refused before any backend call.
        a.1.write(id, &[6; 1400]).unwrap();
        let (next, _, frame) = selected(&mut a.1, 120).unwrap();
        let context = a.0.egress_context(&mut a.1, next).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.trusted_decrease(121, path, if v6 { 1280 } else { 1100 })
            .unwrap();
        let refused =
            a.0.submit(&mut a.1, 122, ticket, context, &frame, 0, |_| {
                panic!("obsolete attempt reached the backend")
            })
            .unwrap_err();
        assert_eq!(refused.error, Error::Obsolete);
        assert!(a.1.reject_unsubmitted(next).unwrap());
        a.0.cancel_submission(refused.ticket);
        assert_eq!(a.0.ledger.pending_count(), 0);
        assert_eq!(records(&a.0).len(), 1);
        std::println!(
            "v6={v6}: 3 WouldBlock retries, 1 seal, refused stale retry recorded nothing"
        );
    }
}

#[test]
fn unknown_outcome_seals_possibly_submitted_and_keeps_quarantine() {
    let cfg = config(2);
    let (mut a, _b, id, _) = connected(false, &cfg, 1010);
    a.1.write(id, &[1; 500]).unwrap();
    let (attempt, frame, result) = attempt_with(&mut a, 100, BackendOutcome::Unknown).unwrap();
    assert_eq!(result, Submission::PossiblySubmitted);
    let sealed = records(&a.0);
    assert_eq!(sealed.len(), 1);
    assert!(sealed[0].possibly_submitted);
    // Not accepted as success and not cancelled as unsent: the Endpoint still
    // holds the attempt for the caller's quarantine.
    assert!(a.1.transmit_attempt_packet(attempt).is_some());
    assert!(a.1.is_output_reserved(id));
    assert_eq!(a.0.ledger.pending_count(), 0);
    // Its ticket is gone; the evidence can still correlate.
    assert!(
        a.0.correlate(101, &quote(&frame))
            .unique
            .is_some_and(|r| r.possibly_submitted)
    );
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    // The quarantine resolves the attempt itself; the new reservation is
    // reclaimed, never sealed.
    assert!(a.1.abandon_transmit(attempt).unwrap());
    a.0.cancel_submission(ticket);
    a.0.collect(&a.1).unwrap();
    assert_eq!(records(&a.0).len(), 1);
    assert_eq!(a.0.ledger.pending_count(), 0);
}

#[test]
fn partial_software_gso_records_each_physical_segment_once() {
    for v6 in [false, true] {
        let mut cfg = config(4);
        cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
        let (local, remote) = addresses(v6);
        let mut a = managed_configured(local, 1020, cfg.clone(), true, None);
        let mut b = managed(remote, 1021, cfg.clone());
        let listener = b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        settle(&mut a);
        let child = b.1.accept(listener).unwrap();
        let payload: Vec<u8> = (0..6000).map(|i| i as u8).collect();
        a.1.write(id, &payload).unwrap();
        now += 10;
        let first = send(&mut a, now).unwrap();
        assert!(
            a.1.is_output_reserved(id),
            "aggregate continues after one segment"
        );
        input(&mut b.0, &mut b.1, b.2, now + 1, &first, 0);
        // The second physical segment gets its own ticket; a decrease makes it
        // obsolete before the call, so only the first segment is evidence.
        let (held, _, frame) = selected(&mut a.1, now + 2).unwrap();
        let context = a.0.egress_context(&mut a.1, held).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let mtu = if v6 { 1280 } else { 1100 };
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.trusted_decrease(now + 3, path, mtu).unwrap();
        let refused =
            a.0.submit(&mut a.1, now + 4, ticket, context, &frame, 0, |_| {
                panic!("obsolete segment submitted")
            })
            .unwrap_err();
        a.1.reject_unsubmitted(held).unwrap();
        a.0.cancel_submission(refused.ticket);
        assert_eq!(records(&a.0).len(), 1);
        now += 20;
        let mut segments = 1;
        while a.1.is_output_reserved(id) {
            let frame = send(&mut a, now).unwrap();
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            segments += 1;
        }
        let sealed = records(&a.0);
        assert_eq!(sealed.len(), segments);
        let mut spans: Vec<(u32, u32)> = sealed
            .iter()
            .map(|r| match r.evidence.transport {
                Selector::Tcp { start, end, .. } => (start, end),
                _ => unreachable!(),
            })
            .collect();
        spans.sort_by_key(|(s, _)| s.wrapping_sub(sequence(&first)));
        for pair in spans.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "one record per physical segment");
        }
        now += 10;
        pump(&mut a, &mut b, &mut now);
        let mut bytes = vec![0; payload.len()];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
        assert_eq!(bytes, payload);
        std::println!("v6={v6}: {segments} physical segments, {segments} sealed records");
    }
}

#[test]
fn retained_rejection_reuses_its_ticket_for_the_replacement_attempt() {
    let cfg = config(2);
    let (mut a, mut b, id, child) = connected(false, &cfg, 1030);
    a.1.write(id, &[3; 1200]).unwrap();
    let (attempt, _, result) = attempt_with(&mut a, 100, BackendOutcome::Rejected).unwrap();
    let Submission::Rejected(ticket) = result else {
        panic!("{result:?}")
    };
    assert!(records(&a.0).is_empty());
    assert!(a.1.reject_unsubmitted(attempt).unwrap());
    let (next, _, frame) = selected(&mut a.1, 101).unwrap();
    assert_ne!(next, attempt);
    let context = a.0.egress_context(&mut a.1, next).unwrap();
    assert_eq!(a.0.ledger.pending_count(), 1, "re-keyed, not a second slot");
    assert_eq!(
        a.0.submission_ticket(&mut a.1, context),
        Err(Error::InvalidContext)
    );
    let result =
        a.0.submit(&mut a.1, 102, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(result == Submission::Submitted);
    assert_eq!(records(&a.0).len(), 1);
    assert_eq!(a.0.ledger.pending_count(), 0);
    input(&mut b.0, &mut b.1, b.2, 103, &frame, 0);
    let mut now = 110;
    pump(&mut a, &mut b, &mut now);
    assert_eq!(b.1.read(child, &mut [0; 2000]).unwrap(), 1200);
}

#[test]
fn certified_nonsubmission_cancels_without_evidence_and_stateless_lane_records() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = managed(local, 1040, cfg.clone());
    let mut b = managed(remote, 1041, cfg.clone());
    a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let syn = send(&mut a, 1).unwrap();
    input(&mut b.0, &mut b.1, b.2, 2, &syn, 0);
    // No listener: a stateless reset.
    let (attempt, frame, result) = attempt_with(&mut b, 3, BackendOutcome::NotSubmitted).unwrap();
    assert_eq!(result, Submission::Cancelled);
    assert!(records(&b.0).is_empty());
    assert_eq!(b.0.ledger.pending_count(), 0);
    assert!(b.1.reject_unsubmitted(attempt).unwrap());
    b.0.collect(&b.1).unwrap();
    assert_eq!(b.0.correlate(4, &quote(&frame)).matches, 0);
    input(&mut b.0, &mut b.1, b.2, 5, &syn, 0);
    let frame = send(&mut b, 6).unwrap();
    let sealed = records(&b.0);
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].evidence.owner, Owner::Stateless);
    assert!(b.0.correlate(7, &quote(&frame)).unique.is_some());
    // Stateless and ACK-only evidence has no delivery signal: it expires.
    let horizon = b.0.ledger.limits().feedback_horizon;
    assert_eq!(horizon, 2 * cfg.connection.timebase.max_segment_lifetime_us);
    assert!(
        b.0.correlate(6 + horizon - 1, &quote(&frame))
            .unique
            .is_some()
    );
    assert_eq!(b.0.correlate(6 + horizon, &quote(&frame)).matches, 0);
    b.0.expire_submissions(6 + horizon);
    assert!(records(&b.0).is_empty());
}

#[test]
fn ack_only_entries_expire_while_outstanding_data_waits_for_delivery() {
    let cfg = config(2);
    let (mut a, mut b, id, child) = connected(false, &cfg, 1050);
    b.1.write(child, &[9; 300]).unwrap();
    let data = send(&mut b, 100).unwrap();
    input(&mut a.0, &mut a.1, a.2, 101, &data, 0);
    let ack = send(&mut a, 102).unwrap();
    a.1.write(id, &[8; 300]).unwrap();
    let outstanding = send(&mut a, 103).unwrap();
    let sealed = records(&a.0);
    assert_eq!(sealed.len(), 2);
    let horizon = a.0.ledger.limits().feedback_horizon;
    a.0.expire_submissions(102 + horizon);
    let left = records(&a.0);
    assert_eq!(left.len(), 1, "pure ACK expired, unacknowledged data kept");
    assert_eq!(a.0.correlate(102 + horizon, &quote(&ack)).matches, 0);
    assert!(
        a.0.correlate(102 + horizon, &quote(&outstanding))
            .unique
            .is_some()
    );
    input(&mut b.0, &mut b.1, b.2, 104 + horizon, &outstanding, 0);
    let ack = send(&mut b, 105 + horizon).unwrap();
    input(&mut a.0, &mut a.1, a.2, 106 + horizon, &ack, 0);
    a.0.collect(&a.1).unwrap();
    assert!(records(&a.0).is_empty(), "delivered data retired");
}

#[test]
fn same_owner_eviction_keeps_identical_retransmission_ambiguous() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        // Two entries, and no extension for this send buffer.
        let ledger = |l: &mut LedgerLimits| {
            l.history_per_owner = 2;
            l.segment_bytes = 65536;
            1
        };
        let mut a = managed_with(local, 1060, cfg.clone(), false, None, None, ledger);
        let mut b = managed(remote, 1061, cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        a.0.collect(&a.1).unwrap();
        a.1.write(id, &[4; 3000]).unwrap();
        let first = send(&mut a, now + 10).unwrap();
        let second = send(&mut a, now + 11).unwrap();
        assert!(a.0.correlate(now + 12, &quote(&first)).unique.is_some());
        let third = send(&mut a, now + 12).unwrap();
        // The owner's own oldest entry made room; it survives as a tombstone.
        assert_eq!(records(&a.0).len(), 2);
        let evicted = a.0.correlate(now + 13, &quote(&first));
        // Lossy history is no positive evidence: no match, path or owner.
        assert_eq!((evicted.matches, evicted.summarized), (0, true));
        assert_eq!((evicted.unique, evicted.path), (None, None));
        assert!(a.0.correlate(now + 13, &quote(&third)).unique.is_some());
        // Nothing was delivered: the RTO retransmits the identical head.
        let mut retransmit = None;
        for step in 1..64 {
            let at = now + step * 1_000_000;
            a.1.on_timeout(at, 32).unwrap();
            if let Some(frame) = send(&mut a, at) {
                retransmit = Some(frame);
                break;
            }
        }
        let retransmit = retransmit.expect("RTO retransmission");
        assert_eq!(quote(&retransmit), quote(&first));
        let identical = a.0.correlate(now + 64_000_000, &quote(&first));
        assert_eq!(
            (identical.matches, identical.summarized),
            (1, true),
            "live retransmission plus tombstone"
        );
        assert_eq!(identical.path, Some(a.0.binding(id).unwrap().snapshot.path()));
        assert_eq!(identical.unique, None, "old quote never names the new copy");
        let _ = second;
    }
}

#[test]
fn tcp_retirement_across_sequence_wrap_and_owner_generation_reuse() {
    let cfg = config(1);
    let (local, remote) = addresses(false);
    // Learn F() for this tuple/secret, then open when the 4 us clock puts
    // the first payload byte just below 2^32.
    let mut probe = managed(local, 1070, cfg.clone());
    probe
        .1
        .connect_with_path_provider(4, local, remote, options(&cfg, 0), &mut probe.0)
        .unwrap();
    let base = sequence(&send(&mut probe, 5).unwrap()).wrapping_sub(1);
    let target = 0u32.wrapping_sub(1500);
    let open = u64::from(target.wrapping_sub(base)) * 4;
    // Reset quarantine below outlives the default 2 MSL horizon; configure a
    // longer one so the ended generation's history is still live when its
    // slot is reused.
    let horizon = |l: &mut LedgerLimits| {
        l.feedback_horizon = 3_600_000_000;
        1
    };
    let mut a = managed_with(local, 1070, cfg.clone(), false, None, None, horizon);
    let mut b = managed(remote, 1071, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(open, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let syn = send(&mut a, open).unwrap();
    assert_eq!(sequence(&syn), target);
    input(&mut b.0, &mut b.1, b.2, open + 1, &syn, 0);
    let mut now = open + 2;
    pump(&mut a, &mut b, &mut now);
    let child = b.1.accept(listener).unwrap();
    settle(&mut a);
    assert!(records(&a.0).is_empty(), "acknowledged SYN retired");
    a.1.write(id, &[2; 4000]).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = send(&mut a, now) {
        frames.push(frame);
        now += 1;
    }
    let spans: Vec<(u32, u32)> = records(&a.0)
        .iter()
        .map(|r| match r.evidence.transport {
            Selector::Tcp { start, end, .. } => (start, end),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(spans.len(), 3);
    assert!(
        spans.iter().any(|(s, e)| s > e),
        "one segment spans the wrap"
    );
    // Deliver one segment at a time; each ACK retires exactly what it covers.
    for (delivered, frame) in frames.iter().enumerate() {
        input(&mut b.0, &mut b.1, b.2, now, frame, 0);
        let ack = send(&mut b, now + 1).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 2, &ack, 0);
        a.0.collect(&a.1).unwrap();
        assert_eq!(records(&a.0).len(), frames.len() - delivered - 1);
        now += 10;
    }
    assert_eq!(b.1.read(child, &mut [0; 5000]).unwrap(), 4000);

    // Unacknowledged history of a generation that ends becomes a tombstone
    // when its slot is reused; it never belongs to the new generation.
    a.1.write(id, &[7; 500]).unwrap();
    let lost = send(&mut a, now).unwrap();
    a.1.abort(id).unwrap();
    while emit(&mut a.0, &mut a.1, now).is_some() {}
    a.1.release(id).unwrap();
    // Bounded reset quarantine retains the old generation until it expires.
    for _ in 0..1000 {
        if !a.1.connection_exists(id) {
            break;
        }
        now += 1_000_000;
        a.1.on_timeout(now, 32).unwrap();
        while emit(&mut a.0, &mut a.1, now).is_some() {}
    }
    assert!(!a.1.connection_exists(id));
    a.0.collect(&a.1).unwrap();
    assert!(records(&a.0).is_empty());
    let replacement =
        a.1.connect_with_path_provider(now + 10, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    assert_ne!(replacement, id);
    send(&mut a, now + 11).unwrap();
    let sealed = records(&a.0);
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].evidence.owner, Owner::Tcp(replacement));
    let old = a.0.correlate(now + 12, &quote(&lost));
    assert_eq!((old.matches, old.summarized, old.unique), (0, true, None));
    a.0.ledger
        .retire_tcp(id, sequence(&lost).wrapping_add(1000));
    assert_eq!(records(&a.0).len(), 1, "stale generation retires nothing");
}

// A long-lived connection evicts continuously when its window exceeds its
// history. Delivery cuts its evicted summary back at SND.UNA, so after far
// more than 2^32 bytes of evicted spans the newest live segments are still
// attributable and only evicted outstanding segments are ambiguous.
#[test]
fn delivery_shrinks_evicted_tcp_history_so_live_segments_stay_attributable() {
    let cfg = config(1);
    let (local, remote) = addresses(false);
    let two = |l: &mut LedgerLimits| {
        l.history_per_owner = 2;
        1
    };
    let (mut host, mut endpoint, ingress) =
        managed_with(local, 1095, cfg.clone(), false, None, None, two);
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
        .unwrap();
    let snapshot = host.binding(id).unwrap().snapshot;
    const SPAN: u32 = 60_000;
    let segment = |k: u32| {
        let start = k.wrapping_mul(SPAN);
        Evidence {
            link: ingress.link(),
            path: snapshot.path(),
            owner: Owner::Tcp(id),
            source: local.ip(),
            destination: remote.ip(),
            dscp: 0,
            header_len: 20,
            packet_len: 40 + SPAN,
            protocol: 6,
            transport: Selector::Tcp {
                source_port: local.port(),
                destination_port: remote.port(),
                start,
                end: start.wrapping_add(SPAN),
            },
        }
    };
    let key = |k: u32| QuoteKey {
        source: local.ip(),
        destination: remote.ip(),
        header_len: 20,
        packet_len: 40 + SPAN,
        protocol: 6,
        transport: QuotedSelector::Tcp {
            source_port: local.port(),
            destination_port: remote.port(),
            sequence: k.wrapping_mul(SPAN),
        },
    };
    let ledger = &mut host.ledger;
    let index = ledger.admit(Owner::Tcp(id)).unwrap();
    // Four segments outstanding, two in history: every seal evicts one
    // outstanding segment.
    let rounds = (1u64 << 32) / u64::from(SPAN) + 100;
    for k in 0..rounds as u32 {
        ledger.retire_tcp(id, k.wrapping_sub(3).wrapping_mul(SPAN));
        let ticket = ledger.reserve_group(index, &[segment(k)]).unwrap();
        assert_eq!(ledger.seal(ticket, 10, false), 1);
        if k % 4096 == 4095 || k + 1 == rounds as u32 {
            let newest = ledger.correlate(11, &key(k));
            assert_eq!(newest.matches, 1, "round {k}");
            assert_eq!(newest.owner.map(|r| r.evidence.owner), Some(Owner::Tcp(id)));
            let evicted = ledger.correlate(11, &key(k - 3));
            assert_eq!(
                (evicted.matches, evicted.summarized, evicted.owner, evicted.path),
                (0, true, None, None),
                "round {k}"
            );
            assert_eq!(ledger.correlate(11, &key(k - 4)).matches, 0, "delivered");
        }
    }
    // The released generation's summary covers only its outstanding window.
    let last = rounds as u32 - 1;
    assert!(ledger.release_owner(index, 12));
    assert!(ledger.correlate(13, &key(last)).summarized);
    assert!(!ledger.correlate(13, &key(last - 4)).summarized);
}

// The base history is sized from the default send buffer; a connection
// configured with its own buffer extends its history before its next
// physical call, so its whole window stays attributable.
#[test]
fn connection_send_buffer_provisions_its_own_history() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let two = |l: &mut LedgerLimits| {
            l.history_per_owner = 2;
            1
        };
        let mut a = managed_with(local, 1096, cfg.clone(), false, None, None, two);
        let mut b = managed(remote, 1097, cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        settle(&mut a);
        a.1.set_buffer_capacities(id, 4 * 1460, 65536).unwrap();
        a.1.write(id, &[3; 4 * 1460]).unwrap();
        let frames: Vec<_> = (0..4).map(|i| send(&mut a, now + i).unwrap()).collect();
        // Room for 4 segments plus one control segment; the base holds 2.
        assert_eq!(records(&a.0).len(), 4);
        for frame in &frames {
            let c = a.0.correlate(now + 5, &quote(frame));
            assert_eq!(
                c.owner.map(|r| r.evidence.owner),
                Some(Owner::Tcp(id)),
                "{v6}"
            );
        }
    }
}

#[test]
fn backpressure_only_at_admission_or_reservation_exhaustion_never_unrecorded() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let ledger = |l: &mut LedgerLimits| {
        l.owners = 1;
        l.concurrent_attempts = 1;
        2
    };
    let mut a = managed_with(local, 1080, cfg.clone(), false, None, None, ledger);
    let first =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let second_local = SocketAddr::new(local.ip(), local.port() + 1);
    let second =
        a.1.connect_with_path_provider(0, second_local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let (one, _, frame_one) = selected(&mut a.1, 1).unwrap();
    let (two, _, frame_two) = selected(&mut a.1, 1).unwrap();
    let context_one = a.0.egress_context(&mut a.1, one).unwrap();
    let packet_two = a.1.transmit_attempt_packet(two).unwrap();
    assert_eq!(packet_two.connection, Some(second));
    // The second owner cannot be admitted: no authority, nothing submitted.
    assert_eq!(a.0.egress_context(&mut a.1, two), Err(Error::Capacity));
    assert_eq!(a.1.transmit_attempt_packet(two), Some(packet_two));
    let ticket = a.0.submission_ticket(&mut a.1, context_one).unwrap();
    a.0.submit(&mut a.1, 2, ticket, context_one, &frame_one, 0, |_| {
        BackendOutcome::Submitted
    })
    .unwrap();
    assert_eq!(records(&a.0).len(), 1);
    // Owner records are guaranteed to live generations: the first one is
    // still alive, so the second keeps waiting.
    assert_eq!(a.0.egress_context(&mut a.1, two), Err(Error::Capacity));
    a.1.abort(first).unwrap();
    while emit(&mut a.0, &mut a.1, 3).is_some() {}
    a.1.release(first).unwrap();
    a.0.collect(&a.1).unwrap();
    let context_two = a.0.egress_context(&mut a.1, two).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context_two).unwrap();
    a.0.submit(&mut a.1, 4, ticket, context_two, &frame_two, 0, |_| {
        BackendOutcome::Submitted
    })
    .unwrap();
    let sealed = records(&a.0);
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].evidence.owner, Owner::Tcp(second));
    // Every physical call above went through a reservation.
    assert_eq!(a.0.ledger.pending_count(), 0);
}

// Non-TCP owners: a datagram flow's aggregated call pre-reserves every
// segment, and identical datagrams from successive flow generations stay
// ambiguous until the configured horizon.
#[test]
fn datagram_owner_group_reservation_identical_quotes_and_horizon() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let (mut host, mut endpoint, ingress) = managed(local, 1090, cfg.clone());
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
        .unwrap();
    let snapshot = host.binding(id).unwrap().snapshot;
    let evidence = |length| Evidence {
        link: ingress.link(),
        path: snapshot.path(),
        owner: Owner::Datagram {
            flow: 0,
            generation: 1,
        },
        source: local.ip(),
        destination: remote.ip(),
        dscp: 0,
        header_len: 40,
        packet_len: 40 + u32::from(length),
        protocol: 17,
        transport: Selector::Udp {
            source_port: 5000,
            destination_port: 7,
            length,
            checksum: 0x1234,
        },
    };
    let datagram = |length| QuoteKey {
        source: local.ip(),
        destination: remote.ip(),
        header_len: 40,
        packet_len: 40 + u32::from(length),
        protocol: 17,
        transport: QuotedSelector::Udp {
            source_port: 5000,
            destination_port: 7,
            length,
            checksum: 0x1234,
        },
    };
    let ledger = &mut host.ledger;
    let owner = ledger.admit(evidence(0).owner).unwrap();
    let group = [evidence(100), evidence(200)];
    let ticket = ledger.reserve_group(owner, &group).unwrap();
    assert_eq!(ledger.pending_count(), 2);
    assert_eq!(ledger.seal(ticket, 10, false), 2);
    assert!(ledger.correlate(11, &datagram(200)).unique.is_some());
    // The generation ends; a new one sends the identical datagram.
    assert!(ledger.release_owner(owner, 11));
    let mut next = evidence(200);
    next.owner = Owner::Datagram {
        flow: 0,
        generation: 2,
    };
    let owner = ledger.admit(next.owner).unwrap();
    let ticket = ledger.reserve_group(owner, &[next]).unwrap();
    ledger.seal(ticket, 20, false);
    let both = ledger.correlate(21, &datagram(200));
    assert_eq!((both.matches, both.summarized, both.unique), (1, true, None));
    assert_eq!(both.path, Some(snapshot.path()));
    let horizon = ledger.limits().feedback_horizon;
    // The old generation's tombstone ends first; then the new copy expires.
    let alone = ledger.correlate(10 + horizon, &datagram(200));
    assert_eq!(alone.unique.map(|r| r.evidence.owner), Some(next.owner));
    assert_eq!(ledger.correlate(20 + horizon, &datagram(200)).matches, 0);
    ledger.expire(20 + horizon);
    assert_eq!(ledger.records().count(), 0);
}

// Evicted history of different owners never merges: two connections from the
// same local port to the same peer, and a stateless lane that sent resets to
// many tuples (one of them byte-identical in every quoted field to a live
// segment of the second connection), all overflow their history. Each
// connection's live, unique quote still names it.
#[test]
fn evictions_of_other_owners_never_shadow_a_unique_live_quote() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let one = |l: &mut LedgerLimits| {
            l.history_per_owner = 1;
            1
        };
        let (mut host, mut endpoint, ingress) =
            managed_with(local, 1100, cfg.clone(), false, None, None, one);
        let second_local = SocketAddr::new(local.ip(), local.port() + 1);
        let c1 = endpoint
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
            .unwrap();
        let c2 = endpoint
            .connect_with_path_provider(0, second_local, remote, options(&cfg, 0), &mut host)
            .unwrap();
        let snapshot = host.binding(c1).unwrap().snapshot;
        let header: u16 = if v6 { 40 } else { 20 };
        let segment = |owner, from: SocketAddr, start: u32, end: u32| Evidence {
            link: ingress.link(),
            path: snapshot.path(),
            owner,
            source: from.ip(),
            destination: remote.ip(),
            dscp: 0,
            header_len: header,
            packet_len: u32::from(header) + 20 + end.wrapping_sub(start),
            protocol: 6,
            transport: Selector::Tcp {
                source_port: from.port(),
                destination_port: remote.port(),
                start,
                end,
            },
        };
        let key = |e: &Evidence| {
            let Selector::Tcp {
                source_port,
                destination_port,
                start,
                ..
            } = e.transport
            else {
                unreachable!()
            };
            QuoteKey {
                source: e.source,
                destination: e.destination,
                header_len: e.header_len,
                packet_len: e.packet_len,
                protocol: 6,
                transport: QuotedSelector::Tcp {
                    source_port,
                    destination_port,
                    sequence: start,
                },
            }
        };
        let ledger = &mut host.ledger;
        let mut commit = |owner, e: Evidence, at| {
            let index = ledger.admit(owner).unwrap();
            let ticket = ledger.reserve_group(index, &[e]).unwrap();
            assert_eq!(ledger.seal(ticket, at, false), 1);
        };
        let old1 = segment(Owner::Tcp(c1), local, 1000, 2000);
        let live1 = segment(Owner::Tcp(c1), local, 2000, 3000);
        let old2 = segment(Owner::Tcp(c2), second_local, 5000, 5100);
        let live2 = segment(Owner::Tcp(c2), second_local, 9000, 9500);
        commit(Owner::Tcp(c1), old1, 10);
        commit(Owner::Tcp(c1), live1, 11);
        commit(Owner::Tcp(c2), old2, 12);
        commit(Owner::Tcp(c2), live2, 13);
        // Resets to arbitrary ports, then one mimicking live2's quoted fields.
        for port in 0..8u16 {
            let mut reset = segment(
                Owner::Stateless,
                SocketAddr::new(local.ip(), 40000 + port),
                7,
                7,
            );
            reset.packet_len = live2.packet_len;
            commit(Owner::Stateless, reset, 14);
        }
        let mut mimic = segment(Owner::Stateless, second_local, 9000, 9000);
        mimic.packet_len = live2.packet_len;
        commit(Owner::Stateless, mimic, 15);
        commit(Owner::Stateless, segment(Owner::Stateless, local, 1, 1), 16);
        for (live, old, owner) in [(live1, old1, c1), (live2, old2, c2)] {
            let correlation = ledger.correlate(20, &key(&live));
            assert_eq!(correlation.matches, 1, "{owner:?}");
            assert_eq!(
                correlation.owner.map(|r| r.evidence.owner),
                Some(Owner::Tcp(owner))
            );
            assert_eq!(correlation.path, Some(snapshot.path()));
            // The owner's own evicted segment is still remembered, but only
            // as ambiguous history.
            let evicted = ledger.correlate(20, &key(&old));
            assert_eq!(
                (evicted.matches, evicted.summarized, evicted.owner),
                (0, true, None)
            );
        }
        // The stateless lane's own evicted resets stay ambiguous for it.
        let reset = segment(Owner::Stateless, SocketAddr::new(local.ip(), 40003), 7, 7);
        let mut quoted = key(&reset);
        quoted.packet_len = live2.packet_len;
        assert_eq!(ledger.correlate(20, &quoted).owner, None);
    }
}

// When every summary slot holds another key's unexpired history, the one
// closest to its horizon is discarded, and every owner that could submit
// under it is denied owner-level attribution until that horizon instead.
#[test]
fn discarded_summary_blinds_owners_that_could_reuse_its_key() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let (mut host, mut endpoint, ingress) = managed(local, 1110, cfg.clone());
    let id = endpoint
        .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
        .unwrap();
    let snapshot = host.binding(id).unwrap().snapshot;
    let datagram = |flow: usize, port: u16| Evidence {
        link: ingress.link(),
        path: snapshot.path(),
        owner: Owner::Datagram {
            flow,
            generation: flow as u64 + 1,
        },
        source: local.ip(),
        destination: remote.ip(),
        dscp: 0,
        header_len: 20,
        packet_len: 128,
        protocol: 17,
        transport: Selector::Udp {
            source_port: port,
            destination_port: 7,
            length: 108,
            checksum: 0x4242,
        },
    };
    let quote = |port: u16| QuoteKey {
        source: local.ip(),
        destination: remote.ip(),
        header_len: 20,
        packet_len: 128,
        protocol: 17,
        transport: QuotedSelector::Udp {
            source_port: port,
            destination_port: 7,
            length: 108,
            checksum: 0x4242,
        },
    };
    let ledger = &mut host.ledger;
    assert_eq!(ledger.limits().datagram_evidence, 0, "summaries only");
    let slots = 2 * ledger.limits().owners;
    // Each closed flow leaves one summary of its own four-tuple.
    for flow in 0..slots {
        let e = datagram(flow, 6000 + flow as u16);
        let index = ledger.admit(e.owner).unwrap();
        let ticket = ledger.reserve_group(index, &[e]).unwrap();
        ledger.seal(ticket, 10 + flow as u64, false);
        assert!(ledger.release_owner(index, 10 + flow as u64));
    }
    assert!(ledger.correlate(100, &quote(6000)).summarized);
    // A new flow on the first flow's binding sends the identical datagram.
    // Its admission came before the discard, with no key yet.
    let reuse = datagram(100, 6000);
    let index = ledger.admit(reuse.owner).unwrap();
    // One more closed flow forces the oldest summary (port 6000) out.
    let last = datagram(101, 7000);
    let other = ledger.admit(last.owner).unwrap();
    let ticket = ledger.reserve_group(other, &[last]).unwrap();
    ledger.seal(ticket, 50, false);
    assert!(ledger.release_owner(other, 50));
    let ticket = ledger.reserve_group(index, &[reuse]).unwrap();
    ledger.seal(ticket, 60, false);
    let horizon = ledger.limits().feedback_horizon;
    let blinded = ledger.correlate(61, &quote(6000));
    assert_eq!(blinded.matches, 1, "the old copy's summary is gone");
    assert!(blinded.summarized, "but its class still shadows the quote");
    assert_eq!(
        blinded.owner, None,
        "but the old quote cannot name the new copy"
    );
    assert_eq!(
        blinded.path, None,
        "the discarded history's paths are unknown"
    );
    // Unrelated summaries were never merged and still exist.
    assert!(ledger.correlate(61, &quote(6001)).summarized);
    // Once the discarded history's horizon passes, the copy is attributable.
    let after = ledger.correlate(10 + horizon, &quote(6000));
    assert_eq!(after.owner.map(|r| r.evidence.owner), Some(reuse.owner));
}

// RFC 4821 implicit probes need unfragmented delivery: the final submitted
// bytes decide. An IPv4 packet whose embedding cleared DF before submission
// (the native IP_PMTUDISC_DONT rewrite), or any packet whose submission is
// uncertain, is delivered and acknowledged normally but never raises the
// connection's search_low; definitely submitted DF/IPv6 output does.
#[test]
fn only_definitely_submitted_unfragmentable_bytes_prove_size() {
    // 0: DF kept, Submitted. 1: DF cleared, Submitted. 2: Unknown outcome.
    for v6 in [false, true] {
        for case in 0..3 {
            if v6 && case == 1 {
                continue; // IPv6 has no DF bit to clear.
            }
            let cfg = config(2);
            let (mut a, mut b, id, child) = connected(v6, &cfg, 2000 + case);
            let before = a.1.path_mtu_info(id).unwrap().unwrap();
            assert!(before.search_low < 1500, "initial search_low below a full packet");
            a.1.write(id, &[9; 1448]).unwrap();
            let mut now = 100;
            let (attempt, _, mut frame) = selected(&mut a.1, now).unwrap();
            assert_eq!(frame.len(), 1500);
            if case == 1 {
                // As the native runtime does: DF clear, leased Identification,
                // recomputed header checksum.
                frame[4..6].copy_from_slice(&7u16.to_be_bytes());
                frame[6] &= !0x40;
                frame[10..12].fill(0);
                let checksum = ntcp_ip_common::checksum(&frame[..20]);
                frame[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            let context = a.0.egress_context(&mut a.1, attempt).unwrap();
            let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let outcome = if case == 2 {
                BackendOutcome::Unknown
            } else {
                BackendOutcome::Submitted
            };
            let result =
                a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| outcome)
                    .unwrap();
            if case == 2 {
                assert_eq!(result, Submission::PossiblySubmitted);
                // The embedding accepts an uncertain outcome without a receipt.
                assert!(a.1.accept_transmit(now, attempt).unwrap());
            } else {
                assert_eq!(result, Submission::Submitted);
            }
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            pump(&mut b, &mut a, &mut now);
            // Delivery and ACK accounting are unaffected.
            let progress = a.1.send_progress(id).unwrap();
            assert_eq!(progress.acknowledged, progress.queued_end);
            let mut received = [0; 2048];
            assert_eq!(b.1.read(child, &mut received).unwrap(), 1448);
            let after = a.1.path_mtu_info(id).unwrap().unwrap();
            if case == 0 {
                assert_eq!(after.search_low, 1500, "v6={v6}");
            } else {
                assert_eq!(after.search_low, before.search_low, "v6={v6} case={case}");
            }
            assert_eq!(after.current_mtu, before.current_mtu);
        }
    }
}
