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
        header_len: header as u32,
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
    identity: u64,
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
    // `pump` submits through the transaction; connections record nothing.
    for side in [&a, &b] {
        assert_eq!(side.0.ledger.records().count(), 0);
    }
    let child = b.1.accept(listener).unwrap();
    (a, b, id, child)
}
// A Host without a listener, holding the stateless reset it owes the SYN it
// just received, and that SYN, which draws another.
fn refused(v6: bool, cfg: &EndpointConfig, identity: u64) -> (Side, Vec<u8>) {
    let (local, remote) = addresses(v6);
    let mut a = managed(local, identity, cfg.clone());
    let mut b = managed(remote, identity + 1, cfg.clone());
    a.1.connect_with_path_provider(0, local, remote, options(cfg, 0), &mut a.0)
        .unwrap();
    let syn = send(&mut a, 1).unwrap();
    input(&mut b.0, &mut b.1, b.2, 2, &syn, 0);
    (b, syn)
}
fn records(host: &Host) -> Vec<Record> {
    host.ledger.records().collect()
}
// The connection a quote of `frame` names, with the span it quotes
// (`Host::tcp_quote`): none once no sent, unacknowledged sequence space holds
// it.
fn quoted_span(side: &Side, frame: &[u8]) -> Option<(ConnectionId, u32, u32)> {
    side.0
        .tcp_quote(&side.1, &quote(frame), None)
        .map(|(owner, segment, _)| (owner, segment.start, segment.end))
}

// A connection's physical attempt reserves and records no ledger evidence
// (ICMP errors about it are judged against its send window): blocked retries
// reach the backend until one is accepted, its quote names the connection by
// its outstanding sequence space, and a path change before a retry is
// refused before any backend call.
#[test]
fn connection_retries_block_and_refuse_without_ledger_evidence() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, mut b, id, child) = connected(v6, &cfg, 1000);
        a.1.write(id, &[5; 1000]).unwrap();
        let (attempt, _, frame) = selected(&mut a.1, 100).unwrap();
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        for _ in 0..3 {
            a.0.egress_context(&mut a.1, attempt).unwrap();
            a.0.validate_egress(&mut a.1, context, &frame, 0).unwrap();
        }
        let mut ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
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
        assert!(a.1.transmit_attempt_packet(attempt).is_none());
        assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
        let start = sequence(&frame);
        assert_eq!(
            quoted_span(&a, &frame),
            Some((id, start, start.wrapping_add(1000)))
        );
        let (_, _, path) = a.0.tcp_quote(&a.1, &quote(&frame), None).unwrap();
        assert_eq!(path, a.0.binding(id).unwrap().snapshot.path());
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
        assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
        std::println!("v6={v6}: 3 WouldBlock retries, refused stale retry, nothing recorded");
    }
}

// The stateless lane records every physical submission: repeated authority
// and validation of one attempt reserve exactly one slot, its single ticket
// survives blocked retries without a record, and the accepted call seals it
// once. A path change before a retry is refused, recording nothing.
#[test]
fn stateless_blocked_retry_revalidates_idempotently_and_seals_once() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut b, syn) = refused(v6, &cfg, 1004);
        let (attempt, packet, frame) = selected(&mut b.1, 3).unwrap();
        assert_eq!(packet.connection, None);
        let context = b.0.egress_context(&mut b.1, attempt).unwrap();
        // Repeated authority and validation reserve exactly one slot.
        for _ in 0..3 {
            b.0.egress_context(&mut b.1, attempt).unwrap();
            b.0.validate_egress(&mut b.1, context, &frame, 0).unwrap();
        }
        assert_eq!(b.0.ledger.pending_count(), 1);
        let mut ticket = b.0.submission_ticket(&mut b.1, context).unwrap();
        assert_eq!(
            b.0.submission_ticket(&mut b.1, context),
            Err(Error::InvalidContext)
        );
        let mut calls = 0;
        for retry in 0..3 {
            match b
                .0
                .submit(&mut b.1, 4 + retry, ticket, context, &frame, 0, |_| {
                    calls += 1;
                    BackendOutcome::WouldBlock
                })
                .unwrap()
            {
                Submission::Blocked(t) => ticket = t,
                other => panic!("{other:?}"),
            }
            assert_eq!(b.0.ledger.pending_count(), 1);
            assert!(records(&b.0).is_empty());
            assert!(b.1.transmit_attempt_packet(attempt).is_some());
        }
        let result =
            b.0.submit(&mut b.1, 10, ticket, context, &frame, 0, |_| {
                calls += 1;
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(result == Submission::Submitted);
        assert_eq!(calls, 4);
        assert_eq!(b.0.ledger.pending_count(), 0);
        assert!(b.1.transmit_attempt_packet(attempt).is_none());
        let sealed = records(&b.0);
        assert_eq!(sealed.len(), 1);
        let start = sequence(&frame);
        assert_eq!(
            sealed[0].evidence.transport,
            Selector::Tcp {
                source_port: 8080,
                destination_port: 1000,
                start,
                end: start,
            }
        );
        assert_eq!(sealed[0].committed_at, 10);
        assert!(!sealed[0].possibly_submitted);
        assert_eq!(sealed[0].evidence.owner, Owner::Stateless);
        assert_eq!(sealed[0].evidence.packet_len as usize, frame.len());
        let correlation = b.0.correlate(11, &quote(&frame));
        assert_eq!(correlation.unique, Some(sealed[0]));
        assert_eq!(correlation.path, Some(context.binding.snapshot.path()));
        // A path change before a retry is refused before any backend call.
        b.0.collect(&b.1).unwrap();
        input(&mut b.0, &mut b.1, b.2, 20, &syn, 0);
        let (next, _, frame) = selected(&mut b.1, 21).unwrap();
        let context = b.0.egress_context(&mut b.1, next).unwrap();
        let ticket = b.0.submission_ticket(&mut b.1, context).unwrap();
        let path = context.binding.snapshot.path();
        b.0.trusted_decrease(22, path, if v6 { 1280 } else { 1100 })
            .unwrap();
        let refused =
            b.0.submit(&mut b.1, 23, ticket, context, &frame, 0, |_| {
                panic!("obsolete attempt reached the backend")
            })
            .unwrap_err();
        assert_eq!(refused.error, Error::Obsolete);
        b.1.reject_unsubmitted(next).unwrap();
        b.0.cancel_submission(refused.ticket);
        assert_eq!(b.0.ledger.pending_count(), 0);
        assert_eq!(records(&b.0).len(), 1);
        std::println!(
            "v6={v6}: stateless 3 WouldBlock retries, 1 seal, refused stale retry recorded nothing"
        );
    }
}

// An unknown backend outcome is never success and never unsent: the Endpoint
// keeps the attempt for the caller's quarantine. A connection's records
// nothing; the stateless lane seals possibly-submitted evidence that still
// correlates. Either way the quarantine's own new reservation is reclaimed,
// never sealed.
#[test]
fn unknown_outcome_keeps_quarantine_and_seals_only_stateless_evidence() {
    let cfg = config(2);
    let (mut a, _b, id, _) = connected(false, &cfg, 1010);
    a.1.write(id, &[1; 500]).unwrap();
    let (attempt, _, result) = attempt_with(&mut a, 100, BackendOutcome::Unknown).unwrap();
    assert_eq!(result, Submission::PossiblySubmitted);
    assert!(a.1.transmit_attempt_packet(attempt).is_some());
    assert!(a.1.is_output_reserved(id));
    assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    assert!(a.1.abandon_transmit(attempt).unwrap());
    a.0.cancel_submission(ticket);
    a.0.collect(&a.1).unwrap();
    assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));

    let (mut b, _) = refused(false, &cfg, 1012);
    let (attempt, frame, result) = attempt_with(&mut b, 3, BackendOutcome::Unknown).unwrap();
    assert_eq!(result, Submission::PossiblySubmitted);
    let sealed = records(&b.0);
    assert_eq!(sealed.len(), 1);
    assert!(sealed[0].possibly_submitted);
    assert!(b.1.transmit_attempt_packet(attempt).is_some());
    assert_eq!(b.0.ledger.pending_count(), 0);
    // Its ticket is gone; the evidence can still correlate.
    assert!(
        b.0.correlate(4, &quote(&frame))
            .unique
            .is_some_and(|r| r.possibly_submitted)
    );
    let context = b.0.egress_context(&mut b.1, attempt).unwrap();
    let ticket = b.0.submission_ticket(&mut b.1, context).unwrap();
    assert!(b.1.abandon_transmit(attempt).unwrap());
    b.0.cancel_submission(ticket);
    b.0.collect(&b.1).unwrap();
    assert_eq!(records(&b.0).len(), 1);
    assert_eq!(b.0.ledger.pending_count(), 0);
}

// A software GSO aggregate leaves one physical segment per call. One that a
// decrease made obsolete before its call is refused and cancelled, and the
// aggregate continues at the new size; none of it is ledger evidence, and
// the receiver reads the stream exactly once.
#[test]
fn partial_software_gso_refusal_repacketizes_without_evidence() {
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
        // The second physical segment is authorized on its own; a decrease
        // makes it obsolete before the call.
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
        now += 20;
        let mut segments = 1;
        while a.1.is_output_reserved(id) {
            let frame = send(&mut a, now).unwrap();
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
            segments += 1;
        }
        assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
        now += 10;
        pump(&mut a, &mut b, &mut now);
        let mut bytes = vec![0; payload.len()];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
        assert_eq!(bytes, payload);
        std::println!("v6={v6}: {segments} physical segments, nothing recorded");
    }
}

// A backend rejection retains the ticket. A connection's replacement attempt
// submits under it (it carries no reservation), recording nothing. A
// withdrawn stateless reply's reservation is reclaimed by `collect`, which
// also frees the reply's path lease, so its ticket names nothing and the
// next reply takes its own.
#[test]
fn retained_rejection_reuses_its_ticket_for_the_replacement_attempt() {
    let cfg = config(2);
    let (mut b, syn) = refused(false, &cfg, 1030);
    let (attempt, _, result) = attempt_with(&mut b, 3, BackendOutcome::Rejected).unwrap();
    let Submission::Rejected(ticket) = result else {
        panic!("{result:?}")
    };
    assert!(records(&b.0).is_empty());
    assert_eq!(b.0.ledger.pending_count(), 1);
    b.1.reject_unsubmitted(attempt).unwrap();
    b.0.collect(&b.1).unwrap();
    assert_eq!(b.0.ledger.pending_count(), 0, "reclaimed");
    input(&mut b.0, &mut b.1, b.2, 4, &syn, 0);
    let (next, _, frame) = selected(&mut b.1, 5).unwrap();
    assert_ne!(next, attempt);
    let context = b.0.egress_context(&mut b.1, next).unwrap();
    let refused =
        b.0.submit(&mut b.1, 6, ticket, context, &frame, 0, |_| {
            panic!("a reclaimed ticket reached the backend")
        })
        .unwrap_err();
    assert_eq!(refused.error, Error::Obsolete);
    b.0.cancel_submission(refused.ticket);
    let ticket = b.0.submission_ticket(&mut b.1, context).unwrap();
    let result =
        b.0.submit(&mut b.1, 6, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(result == Submission::Submitted);
    assert_eq!(records(&b.0).len(), 1);
    assert_eq!(b.0.ledger.pending_count(), 0);

    let (mut a, mut b, id, child) = connected(false, &cfg, 1032);
    a.1.write(id, &[3; 1200]).unwrap();
    let (attempt, _, result) = attempt_with(&mut a, 100, BackendOutcome::Rejected).unwrap();
    let Submission::Rejected(ticket) = result else {
        panic!("{result:?}")
    };
    assert!(a.1.reject_unsubmitted(attempt).unwrap());
    let (next, _, frame) = selected(&mut a.1, 101).unwrap();
    assert_ne!(next, attempt);
    let context = a.0.egress_context(&mut a.1, next).unwrap();
    let result =
        a.0.submit(&mut a.1, 102, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(result == Submission::Submitted);
    assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
    input(&mut b.0, &mut b.1, b.2, 103, &frame, 0);
    let mut now = 110;
    pump(&mut a, &mut b, &mut now);
    assert_eq!(b.1.read(child, &mut [0; 2000]).unwrap(), 1200);
}

// RFC 5927 section 4.1 with serial arithmetic: a connection's ICMP quote is
// judged by its own sent sequence space. Each outstanding segment's quote,
// the one spanning 2^32 included, names the connection until a cumulative
// acknowledgment covers it; once the generation ends nothing does, and a
// later generation on the same four-tuple accepts only quotes of its own
// sequence space. Nothing enters the ledger.
#[test]
fn tcp_quotes_follow_the_send_window_across_sequence_wrap_and_generation_reuse() {
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
    let mut a = managed(local, 1070, cfg.clone());
    let mut b = managed(remote, 1071, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(open, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let syn = send(&mut a, open).unwrap();
    assert_eq!(sequence(&syn), target);
    assert_eq!(quoted_span(&a, &syn).map(|(owner, ..)| owner), Some(id));
    input(&mut b.0, &mut b.1, b.2, open + 1, &syn, 0);
    let mut now = open + 2;
    pump(&mut a, &mut b, &mut now);
    let child = b.1.accept(listener).unwrap();
    assert_eq!(quoted_span(&a, &syn), None, "acknowledged SYN");
    a.1.write(id, &[2; 4000]).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = send(&mut a, now) {
        frames.push(frame);
        now += 1;
    }
    let spans: Vec<(u32, u32)> = frames
        .iter()
        .map(|frame| {
            let (owner, start, end) = quoted_span(&a, frame).unwrap();
            assert_eq!(owner, id);
            assert_eq!(start, sequence(frame));
            (start, end)
        })
        .collect();
    assert_eq!(spans.len(), 3);
    assert!(
        spans.iter().any(|(s, e)| s > e),
        "one segment spans the wrap"
    );
    // Deliver one segment at a time; each ACK ends exactly the quotes of
    // what it covers.
    for (delivered, frame) in frames.iter().enumerate() {
        input(&mut b.0, &mut b.1, b.2, now, frame, 0);
        let ack = send(&mut b, now + 1).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 2, &ack, 0);
        for (k, frame) in frames.iter().enumerate() {
            assert_eq!(
                quoted_span(&a, frame).is_some(),
                k > delivered,
                "segment {k} after delivering {delivered}"
            );
        }
        now += 10;
    }
    assert_eq!(b.1.read(child, &mut [0; 5000]).unwrap(), 4000);

    // A generation that ends takes its sequence space with it; the next one
    // on the four-tuple starts from its own ISS.
    a.1.write(id, &[7; 500]).unwrap();
    let lost = send(&mut a, now).unwrap();
    assert_eq!(quoted_span(&a, &lost).map(|(owner, ..)| owner), Some(id));
    a.1.abort(id).unwrap();
    while emit(&mut a.0, &mut a.1, now).is_some() {}
    a.1.release(id).unwrap();
    // Its reset sent, the old generation is reclaimed at release.
    assert!(!a.1.connection_exists(id));
    a.0.collect(&a.1).unwrap();
    assert_eq!(quoted_span(&a, &lost), None);
    let replacement =
        a.1.connect_with_path_provider(now + 10, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    assert_ne!(replacement, id);
    let syn = send(&mut a, now + 11).unwrap();
    assert_eq!(quoted_span(&a, &lost), None, "the old generation's data");
    assert_eq!(
        quoted_span(&a, &syn).map(|(owner, ..)| owner),
        Some(replacement)
    );
    assert!(records(&a.0).is_empty());
}

// Connections never wait for ledger capacity: with one owner record and one
// unsealed attempt, two connections' attempts are authorized and submitted
// together, recording nothing, and the stateless lane still records its
// reply within the same limits.
#[test]
fn connections_need_no_ledger_capacity_and_the_stateless_lane_still_records() {
    fn one_each(l: &mut LedgerLimits) -> usize {
        l.owners = 1;
        l.concurrent_attempts = 1;
        2
    }
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = managed_with(local, 1080, cfg.clone(), false, None, None, one_each);
    a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let second_local = SocketAddr::new(local.ip(), local.port() + 1);
    let second =
        a.1.connect_with_path_provider(0, second_local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let (one, _, frame_one) = selected(&mut a.1, 1).unwrap();
    let (two, _, frame_two) = selected(&mut a.1, 1).unwrap();
    assert_eq!(
        a.1.transmit_attempt_packet(two).unwrap().connection,
        Some(second)
    );
    let contexts = [one, two].map(|attempt| a.0.egress_context(&mut a.1, attempt).unwrap());
    for (context, frame) in contexts.into_iter().zip([&frame_one, &frame_two]) {
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let result =
            a.0.submit(&mut a.1, 2, ticket, context, frame, 0, |_| {
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(result == Submission::Submitted);
    }
    assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
    // Without a listener, the peer resets the first SYN.
    let mut b = managed_with(remote, 1081, cfg.clone(), false, None, None, one_each);
    input(&mut b.0, &mut b.1, b.2, 3, &frame_one, 0);
    send(&mut b, 4).unwrap();
    let sealed = records(&b.0);
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].evidence.owner, Owner::Stateless);
    assert_eq!(b.0.ledger.pending_count(), 0);
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

// Non-TCP owners: a datagram flow's aggregated call pre-reserves every
// segment, and identical datagrams from successive flow generations stay
// ambiguous until the configured horizon.
#[test]
fn datagram_owner_group_reservation_identical_quotes_and_horizon() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    // Two unsealed attempts: the group's two segments.
    let two = |l: &mut LedgerLimits| {
        l.concurrent_attempts = 2;
        1
    };
    let (mut host, mut endpoint, ingress) =
        managed_with(local, 1090, cfg.clone(), false, None, None, two);
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

// Evicted history of different owners never merges: two datagram flows from
// the same address to the same peer, and a stateless lane that sent resets to
// many tuples (one of them from the second flow's ports), all overflow their
// one-entry history. Each flow's live, unique quote still names it.
#[test]
fn evictions_of_other_owners_never_shadow_a_unique_live_quote() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let one = |l: &mut LedgerLimits| {
            l.owners = 3;
            l.history_per_owner = 1;
            1
        };
        let (mut host, mut endpoint, ingress) =
            managed_with(local, 1100, cfg.clone(), false, None, None, one);
        let id = endpoint
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut host)
            .unwrap();
        let snapshot = host.binding(id).unwrap().snapshot;
        let header: u32 = if v6 { 40 } else { 20 };
        let datagram = |flow: usize, port: u16, length: u16| Evidence {
            link: ingress.link(),
            path: snapshot.path(),
            owner: Owner::Datagram {
                flow,
                generation: 1,
            },
            source: local.ip(),
            destination: remote.ip(),
            dscp: 0,
            header_len: header,
            packet_len: header + u32::from(length),
            protocol: 17,
            transport: Selector::Udp {
                source_port: port,
                destination_port: 7,
                length,
                checksum: 0x4242,
            },
        };
        let reset = |port: u16| Evidence {
            link: ingress.link(),
            path: snapshot.path(),
            owner: Owner::Stateless,
            source: local.ip(),
            destination: remote.ip(),
            dscp: 0,
            header_len: header,
            packet_len: header + 20,
            protocol: 6,
            transport: Selector::Tcp {
                source_port: port,
                destination_port: 7,
                start: 7,
                end: 7,
            },
        };
        let key = |e: &Evidence| QuoteKey {
            source: e.source,
            destination: e.destination,
            header_len: e.header_len,
            packet_len: e.packet_len,
            protocol: e.protocol,
            transport: match e.transport {
                Selector::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                } => QuotedSelector::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
                Selector::Tcp {
                    source_port,
                    destination_port,
                    start,
                    ..
                } => QuotedSelector::Tcp {
                    source_port,
                    destination_port,
                    sequence: start,
                },
                _ => unreachable!(),
            },
        };
        let ledger = &mut host.ledger;
        let mut commit = |e: Evidence, at| {
            let index = ledger.admit(e.owner).unwrap();
            let ticket = ledger.reserve_group(index, &[e]).unwrap();
            assert_eq!(ledger.seal(ticket, at, false), 1);
        };
        let old1 = datagram(0, 5000, 100);
        let live1 = datagram(0, 5000, 108);
        let old2 = datagram(1, 5001, 100);
        let live2 = datagram(1, 5001, 108);
        commit(old1, 10);
        commit(live1, 11);
        commit(old2, 12);
        commit(live2, 13);
        // Resets from arbitrary ports, then one from the second flow's.
        for port in 0..8u16 {
            commit(reset(40000 + port), 14);
        }
        commit(reset(5001), 15);
        commit(reset(1), 16);
        for (live, old) in [(live1, old1), (live2, old2)] {
            let correlation = ledger.correlate(20, &key(&live));
            assert_eq!(correlation.matches, 1, "{:?}", live.owner);
            assert_eq!(
                correlation.owner.map(|r| r.evidence.owner),
                Some(live.owner)
            );
            assert_eq!(correlation.path, Some(snapshot.path()));
            // The owner's own evicted datagram is still remembered, but only
            // as ambiguous history.
            let evicted = ledger.correlate(20, &key(&old));
            assert_eq!(
                (evicted.matches, evicted.summarized, evicted.owner),
                (0, true, None)
            );
        }
        // The stateless lane's own evicted resets stay ambiguous for it.
        let quoted = ledger.correlate(20, &key(&reset(40003)));
        assert_eq!(
            (quoted.matches, quoted.summarized, quoted.owner),
            (0, true, None)
        );
    }
}

// When every summary slot holds another key's unexpired history, the one
// closest to its horizon is discarded, and every owner that could submit
// under it is denied owner-level attribution until that horizon instead.
#[test]
fn discarded_summary_blinds_owners_that_could_reuse_its_key() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    // Two flow records: a new flow is admitted while another is open.
    let two = |l: &mut LedgerLimits| {
        l.owners = 2;
        1
    };
    let (mut host, mut endpoint, ingress) =
        managed_with(local, 1110, cfg.clone(), false, None, None, two);
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

// IP packets around `tcp` bytes of `packet`'s connection.
fn ip_frame(packet: Transmit, tcp: &[u8]) -> Vec<u8> {
    let base = if packet.ip.source.is_ipv4() { 20 } else { 40 };
    let mut frame = vec![0; base + tcp.len()];
    frame[base..].copy_from_slice(tcp);
    let packet = Transmit {
        len: tcp.len(),
        ..packet
    };
    let n = if packet.ip.source.is_ipv4() {
        ntcp_ip::encode(&mut frame, packet, 0).unwrap()
    } else {
        ntcp_ip6::encode(&mut frame, packet).unwrap()
    };
    frame.truncate(n);
    frame
}
// A group's aggregate, as an embedding hands it to a segmenting backend
// (one IP header, both checksum fields zero), and the packets the backend
// cuts from it, as Linux tcp_gso_segment cuts them.
fn group_frames(endpoint: &Endpoint, group: ntcp::TransmitGroup) -> (Vec<u8>, Vec<Vec<u8>>) {
    let view = endpoint.transmit_group(group).unwrap();
    let mut tcp = vec![0; view.packet.len];
    let n = ntcp::wire::encode(view.packet.ip, view.header, view.options, &[], &mut tcp).unwrap();
    tcp[16..18].fill(0);
    tcp[n..].copy_from_slice(view.payload);
    let size = view.segment_payload_len;
    let segments = (0..view.segment_count)
        .map(|k| {
            let mut header = view.header;
            header.sequence = header.sequence.wrapping_add((k * size) as u32);
            if k + 1 != view.segment_count {
                header.flags &= !ntcp::wire::PSH;
            }
            if k != 0 {
                header.flags &= !ntcp::wire::CWR;
            }
            let mut out = vec![0; 2048];
            let len = ntcp::wire::encode(
                view.packet.ip,
                header,
                view.options,
                &view.payload[k * size..(k + 1) * size],
                &mut out,
            )
            .unwrap();
            ip_frame(view.packet, &out[..len])
        })
        .collect();
    let mut frame = ip_frame(view.packet, &tcp);
    if view.packet.ip.source.is_ipv4() {
        frame[10..12].fill(0);
    }
    (frame, segments)
}

// A group goes through the same transaction as one packet: a blocked call
// keeps it for a retry, a submitted one is accepted with every segment's
// receipt, and a path that changed before a retry refuses it before any
// backend call. Nothing is ledger evidence, and the stream arrives once.
#[test]
fn groups_retry_submit_and_refuse_like_one_packet() {
    for v6 in [false, true] {
        let mut cfg = config(4);
        cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
        let (local, remote) = addresses(v6);
        let mut a = managed_configured(local, 1030, cfg.clone(), true, None);
        let mut b = managed(remote, 1031, cfg.clone());
        let listener = b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let child = b.1.accept(listener).unwrap();
        let limits = ntcp::TransmitGroupLimits {
            max_bytes: usize::MAX,
            max_segments: usize::MAX,
            allow_psh: false,
            allow_cwr: false,
            allow_options: true,
        };
        let payload: Vec<u8> = (0..16000).map(|i| (i * 3) as u8).collect();
        a.1.write(id, &payload).unwrap();
        now += 10;
        let (attempt, _, _) = selected(&mut a.1, now).unwrap();
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let group =
            a.1.prepare_transmit_group(attempt, limits)
                .unwrap()
                .unwrap();
        let (frame, segments) = group_frames(&a.1, group);
        assert!(segments.len() >= 2);
        let mut calls = 0;
        for retry in 0..2 {
            let result =
                a.0.submit_group(&mut a.1, now + retry, context, group, &frame, |_| {
                    calls += 1;
                    BackendOutcome::WouldBlock
                })
                .unwrap();
            assert!(matches!(result, Submission::Blocked(_)));
        }
        let result =
            a.0.submit_group(&mut a.1, now + 3, context, group, &frame, |_| {
                calls += 1;
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(result == Submission::Submitted);
        assert_eq!(calls, 3);
        assert!(a.1.transmit_group(group).is_none());
        for segment in &segments {
            input(&mut b.0, &mut b.1, b.2, now + 4, segment, 0);
        }
        // The next group meets a path that shrank after its authority.
        now += 10;
        let (attempt, _, _) = selected(&mut a.1, now).unwrap();
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let group =
            a.1.prepare_transmit_group(attempt, limits)
                .unwrap()
                .unwrap();
        let (frame, _) = group_frames(&a.1, group);
        let mtu = if v6 { 1280 } else { 1100 };
        let path = a.0.binding(id).unwrap().snapshot.path();
        a.0.trusted_decrease(now + 1, path, mtu).unwrap();
        assert_eq!(
            a.0.submit_group(&mut a.1, now + 2, context, group, &frame, |_| {
                panic!("an obsolete group reached the backend")
            }),
            Err(Error::Obsolete)
        );
        assert!(a.1.reject_unsubmitted_group(group).unwrap());
        now += 20;
        while a.1.is_output_reserved(id) {
            let frame = send(&mut a, now).unwrap();
            assert!(frame.len() <= mtu as usize);
            input(&mut b.0, &mut b.1, b.2, now + 1, &frame, 0);
        }
        assert_eq!((a.0.ledger.pending_count(), records(&a.0).len()), (0, 0));
        for _ in 0..10 {
            now += 10;
            pump(&mut a, &mut b, &mut now);
        }
        let mut bytes = vec![0; payload.len()];
        assert_eq!(b.1.read(child, &mut bytes).unwrap(), payload.len());
        assert_eq!(bytes, payload);
    }
}
