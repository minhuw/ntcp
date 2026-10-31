use super::*;
use core::net::Ipv6Addr;
use ntcp::Event;

type Side = (Host, Endpoint, IngressContext);

fn send(side: &mut Side, now: u64) -> Option<Vec<u8>> {
    let (attempt, _, frame) = selected(&mut side.1, now)?;
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let result = side
        .0
        .submit(&mut side.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(result == Submission::Submitted);
    Some(frame)
}
fn connected(v6: bool, cfg: &EndpointConfig, identity: u128) -> (Side, Side, ConnectionId) {
    let (local, remote) = addresses(v6);
    let mut a = managed(local, identity, cfg.clone());
    let mut b = managed(remote, identity + 1, cfg.clone());
    b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    (a, b, id)
}
pub(super) fn header(frame: &[u8]) -> usize {
    if frame[0] >> 4 == 6 {
        40
    } else {
        usize::from(frame[0] & 15) * 4
    }
}
pub(super) fn seal_ipv4(frame: &mut [u8]) {
    if frame[0] >> 4 == 4 {
        let h = header(frame);
        frame[10..12].fill(0);
        let sum = ntcp_icmp::checksum(&frame[..h]);
        frame[10..12].copy_from_slice(&sum.to_be_bytes());
    }
}
// A router (never the peer) reports an error quoting `frame`'s header and
// first eight transport bytes. `value` fills ICMP bytes 4..8 (the MTU).
pub(super) fn icmp(frame: &[u8], kind: (u8, u8), value: u32) -> Vec<u8> {
    let h = header(frame);
    let v6 = frame[0] >> 4 == 6;
    let mut packet = vec![0; h + 8 + h + 8];
    packet[..h].copy_from_slice(&frame[..h]);
    if v6 {
        packet[8..24].copy_from_slice(&"2001:db8::fe".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&frame[8..24]);
        packet[4..6].copy_from_slice(&((8 + h + 8) as u16).to_be_bytes());
        packet[6] = 58;
    } else {
        packet[12..16].copy_from_slice(&[192, 0, 2, 254]);
        packet[16..20].copy_from_slice(&frame[12..16]);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[9] = 1;
    }
    packet[h] = kind.0;
    packet[h + 1] = kind.1;
    packet[h + 4..h + 8].copy_from_slice(&value.to_be_bytes());
    packet[h + 8..].copy_from_slice(&frame[..h + 8]);
    seal_ipv4(&mut packet);
    let sum = if v6 {
        ntcp_icmp::icmpv6_checksum(
            IpMetadata {
                source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()).into(),
                destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()).into(),
            },
            &packet[h..],
        )
        .unwrap()
    } else {
        ntcp_icmp::checksum(&packet[h..])
    };
    packet[h + 2..h + 4].copy_from_slice(&sum.to_be_bytes());
    packet
}
pub(super) fn ptb(frame: &[u8], mtu: u32) -> Vec<u8> {
    icmp(frame, if frame[0] >> 4 == 6 { (2, 0) } else { (3, 4) }, mtu)
}
// A quote of a packet this host never sent: mutate the original first.
fn forged(frame: &[u8], mtu: u32, mutate: impl FnOnce(&mut Vec<u8>, usize)) -> Vec<u8> {
    let mut copy = frame.to_vec();
    mutate(&mut copy, header(frame));
    seal_ipv4(&mut copy);
    ptb(&copy, mtu)
}
fn dispatch(side: &mut Side, now: u64, report: &[u8]) -> IcmpDispatch {
    side.0.input_icmp(&mut side.1, side.2, now, report).unwrap()
}
fn smaller(v6: bool) -> u32 {
    if v6 { 1280 } else { 1100 }
}
fn learned(side: &Side, id: ConnectionId) -> Option<u32> {
    let path = side.0.binding(id).unwrap().snapshot.path();
    side.0.paths().path_snapshot(path).unwrap().learned_mtu()
}
fn current_mtu(side: &Side, id: ConnectionId) -> u32 {
    side.1.path_mtu_info(id).unwrap().unwrap().current_mtu
}
fn drain_events(endpoint: &mut Endpoint) -> Vec<Event> {
    std::iter::from_fn(|| endpoint.next_event()).collect()
}
pub(super) fn tcp_report(dispatch: IcmpDispatch) -> (TcpReport, Option<path::EstimateChange>) {
    match dispatch {
        IcmpDispatch::Completed(IcmpOutcome::Tcp {
            report, published, ..
        }) => (report, published),
        other => panic!("{other:?}"),
    }
}
fn quote_key(frame: &[u8]) -> QuoteKey {
    let quote = ntcp_icmp::decode_icmp(&ptb(frame, 1280)).unwrap().quoted;
    QuoteKey {
        source: quote.ip.source,
        destination: quote.ip.destination,
        header_len: quote.ip_header_len,
        packet_len: quote.ip_packet_len,
        protocol: 6,
        transport: QuotedSelector::Tcp {
            source_port: quote.source_port,
            destination_port: quote.destination_port,
            sequence: quote.sequence,
        },
    }
}
const UNCORRELATED: IcmpDispatch =
    IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated));

#[test]
fn router_ptb_publishes_after_tcp_decrease_and_forgeries_change_nothing() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, _b, id) = connected(v6, &cfg, 2000);
        let (_, remote) = addresses(v6);
        a.1.write(id, &[1; 1400]).unwrap();
        let original = send(&mut a, 100).unwrap();
        assert_eq!(original.len(), 1452 + if v6 { 20 } else { 0 });
        let mtu = smaller(v6);
        let report = ptb(&original, mtu);
        let feedback = ntcp_icmp::decode_icmp(&report).unwrap();
        assert_ne!(feedback.outer.source, remote.ip(), "router, not the peer");
        let before = (current_mtu(&a, id), learned(&a, id));
        // Wrong address, length, ports and sequence: no submission matches.
        let forgeries = [
            forged(&original, mtu, |f, _| {
                let at = if v6 { 39 } else { 19 };
                f[at] ^= 1;
            }),
            forged(&original, mtu, |f, _| {
                let at = if v6 { 4 } else { 2 };
                let len = u16::from_be_bytes([f[at], f[at + 1]]) - 4;
                f[at..at + 2].copy_from_slice(&len.to_be_bytes());
            }),
            forged(&original, mtu, |f, h| f[h + 1] ^= 1),
            forged(&original, mtu, |f, h| f[h + 3] ^= 1),
            forged(&original, mtu, |f, h| f[h + 7] ^= 1),
        ];
        for (n, forgery) in forgeries.iter().enumerate() {
            assert_eq!(dispatch(&mut a, 101, forgery), UNCORRELATED, "forgery {n}");
        }
        // Wrong header length or protocol, at the correlation boundary.
        let quote = ntcp_icmp::decode_icmp(&report).unwrap().quoted;
        let key = QuoteKey {
            source: quote.ip.source,
            destination: quote.ip.destination,
            header_len: quote.ip_header_len,
            packet_len: quote.ip_packet_len,
            protocol: 6,
            transport: QuotedSelector::Tcp {
                source_port: quote.source_port,
                destination_port: quote.destination_port,
                sequence: quote.sequence,
            },
        };
        assert!(a.0.correlate(101, &key).owner.is_some());
        for wrong in [
            QuoteKey {
                header_len: key.header_len + 4,
                ..key
            },
            QuoteKey {
                protocol: 17,
                ..key
            },
        ] {
            assert_eq!(a.0.correlate(101, &wrong).matches, 0);
        }
        // Wrong context: another Host never submitted this packet.
        let (local, _) = addresses(v6);
        let mut other = managed(local, 2100, cfg.clone());
        assert_eq!(dispatch(&mut other, 101, &report), UNCORRELATED);
        assert_eq!((current_mtu(&a, id), learned(&a, id)), before);

        let (report, published) = tcp_report(dispatch(&mut a, 102, &report));
        assert!(matches!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        assert_eq!(published, Some(path::EstimateChange::Decreased));
        assert_eq!(current_mtu(&a, id), mtu);
        assert_eq!(learned(&a, id), Some(mtu));
        let repair = send(&mut a, 103).unwrap();
        assert!(repair.len() <= mtu as usize);
        std::println!(
            "v6={v6}: router PTB {} -> TCP {mtu}, shared {mtu}; 5 forged quotes, 2 wrong keys, foreign context discarded; repair {} bytes",
            original.len(),
            repair.len()
        );
    }
}

#[test]
fn deferred_tcp_report_is_not_preempted_by_shared_publication() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, mut b, id) = connected(v6, &cfg, 2010);
        a.1.write(id, &[2; 1400]).unwrap();
        let delivered = send(&mut a, 100).unwrap();
        input(&mut b.0, &mut b.1, b.2, 101, &delivered, 0);
        let ack = emit(&mut b.0, &mut b.1, 102).unwrap();
        input(&mut a.0, &mut a.1, a.2, 103, &ack, 0);
        a.1.write(id, &[3; 1400]).unwrap();
        let outstanding = send(&mut a, 104).unwrap();
        let before = current_mtu(&a, id);
        let (report, published) =
            tcp_report(dispatch(&mut a, 105, &ptb(&outstanding, smaller(v6))));
        // Below the proven 1452/1472-byte delivery: TCP defers, and so the
        // shared estimate, which TCP would adopt on refresh, is untouched.
        assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Deferred));
        assert_eq!(published, None);
        assert_eq!(learned(&a, id), None);
        assert_eq!(current_mtu(&a, id), before);
        a.0.refresh(&mut a.1, id).unwrap();
        assert_eq!(current_mtu(&a, id), before);
        std::println!("v6={v6}: deferred below proven delivery, shared estimate untouched");
    }
}

// Connection churn overflows the summaries of released generations, which
// discards the oldest. Only owners that could reuse a discarded four-tuple
// lose owner-level attribution: a later connection on another four-tuple
// still has its router PTB correlated, while a reuse of the discarded tuple
// stays ambiguous until that summary's horizon.
#[test]
fn discarded_churn_summaries_blind_only_owners_of_their_key() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 2200, cfg.clone());
        let mut b = managed(remote, 2201, cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let slots = 2 * a.0.ledger.limits().owners;
        let mut now = 0;
        let mut syns = Vec::new();
        // One more generation than summaries; the next keeps the last released
        // generation's record busy until then.
        for n in 0..slots + 2 {
            let from = SocketAddr::new(local.ip(), 3000 + n as u16);
            let id =
                a.1.connect_with_path_provider(now, from, remote, options(&cfg, 0), &mut a.0)
                    .unwrap();
            now += 10;
            syns.push(send(&mut a, now).unwrap());
            a.1.abort(id).unwrap();
            a.1.release(id).unwrap();
            a.0.collect(&a.1).unwrap();
            while emit(&mut a.0, &mut a.1, now).is_some() {}
        }
        // The first generation's summary was discarded for the last released.
        assert_eq!(a.0.correlate(now, &quote_key(&syns[0])).matches, 0);
        let survivor = a.0.correlate(now, &quote_key(&syns[1]));
        assert_eq!(
            (survivor.matches, survivor.summarized),
            (0, true),
            "other summaries survive, as lossy history only"
        );

        let fresh = SocketAddr::new(local.ip(), 4000);
        let id =
            a.1.connect_with_path_provider(now, fresh, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        pump(&mut a, &mut b, &mut now);
        a.1.write(id, &[6; 1400]).unwrap();
        now += 10;
        let original = send(&mut a, now).unwrap();
        let (report, published) =
            tcp_report(dispatch(&mut a, now + 1, &ptb(&original, smaller(v6))));
        assert!(matches!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        assert_eq!(published, Some(path::EstimateChange::Decreased));

        // A new generation on the discarded tuple is not attributable: its
        // packets could be identical to the forgotten generation's.
        now += 10;
        pump(&mut a, &mut b, &mut now);
        let reuse = SocketAddr::new(local.ip(), 3000);
        let again =
            a.1.connect_with_path_provider(now, reuse, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let syn = send(&mut a, now).unwrap();
        let key = quote_key(&syn);
        let correlation = a.0.correlate(now, &key);
        assert_eq!(correlation.matches, 1);
        assert_eq!(correlation.owner, None, "blinded by the discarded summary");
        let horizon = a.0.ledger.limits().feedback_horizon;
        assert_eq!(
            a.0.correlate(now + horizon, &key)
                .owner
                .map(|r| r.evidence.owner),
            Some(Owner::Tcp(again))
        );
        std::println!(
            "v6={v6}: {} churned generations over {slots} summaries; new tuple PTB Decreased, reused tuple blinded until horizon",
            slots + 2
        );
    }
}

#[test]
fn unchanged_estimate_drop_advice_is_consumed_without_side_effects() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, _b, id) = connected(v6, &cfg, 2020);
        a.1.write(id, &[4; 1400]).unwrap();
        let original = send(&mut a, 100).unwrap();
        let mtu = smaller(v6);
        let (report, _) = tcp_report(dispatch(&mut a, 101, &ptb(&original, mtu)));
        assert!(matches!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        // Drain the repair the decrease created; it is never delivered.
        let mut now = 102;
        while send(&mut a, now).is_some() {
            now += 1;
        }
        drain_events(&mut a.1);
        let snapshot = a.0.binding(id).unwrap().snapshot;
        let before = (
            a.1.path_mtu_info(id).unwrap(),
            a.1.next_deadline(),
            a.1.send_progress(id).unwrap(),
        );
        // Equal and still-smaller-than-the-packet reports identify a drop.
        // Each is still a fresh validated report about the shared path: the
        // shared estimate stays, its hold restarts from this report.
        let units = cfg.connection.timebase.units_per_second;
        for candidate in [mtu, mtu + 50] {
            now += 1;
            let (report, published) = tcp_report(dispatch(&mut a, now, &ptb(&original, candidate)));
            assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Unchanged));
            assert_eq!(published, Some(path::EstimateChange::Unchanged));
            let shared = a.0.paths().path_snapshot(snapshot.path()).unwrap();
            assert_eq!(shared.learned_mtu(), snapshot.learned_mtu());
            assert_eq!(shared.negative_revision(), snapshot.negative_revision());
            assert_eq!(shared.retry_not_before(), now + 600 * units);
        }
        // Impossible reports are rejected outright.
        let size = original.len() as u32;
        let mut impossible = vec![size];
        if v6 {
            impossible.push(1279);
        }
        for candidate in impossible {
            let (report, _) = tcp_report(dispatch(&mut a, now, &ptb(&original, candidate)));
            assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Rejected));
        }
        let after = (
            a.1.path_mtu_info(id).unwrap(),
            a.1.next_deadline(),
            a.1.send_progress(id).unwrap(),
        );
        assert_eq!(
            before, after,
            "no local increase, deadline or progress change"
        );
        assert!(selected(&mut a.1, now).is_none(), "no repeated head retry");
        assert!(drain_events(&mut a.1).is_empty(), "no fabricated error");
        std::println!(
            "v6={v6}: 2 unchanged reports consumed as advice restarting the shared hold, impossible rejected"
        );
    }
}

#[test]
fn stale_path_incarnation_never_changes_an_estimate() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, _b, id) = connected(v6, &cfg, 2030);
        a.1.write(id, &[5; 1400]).unwrap();
        let original = send(&mut a, 100).unwrap();
        let old = a.0.binding(id).unwrap().snapshot.path();
        a.0.rebind_dscp(&mut a.1, id, 8).unwrap();
        assert_ne!(a.0.binding(id).unwrap().snapshot.path(), old);
        let before = current_mtu(&a, id);
        let (report, published) = tcp_report(dispatch(&mut a, 101, &ptb(&original, smaller(v6))));
        assert_eq!(report, TcpReport::PacketTooBig(PmtuFeedback::Unchanged));
        assert_eq!(published, None);
        assert_eq!(current_mtu(&a, id), before);
        assert_eq!(learned(&a, id), None);
        if let Ok(snapshot) = a.0.paths().path_snapshot(old) {
            assert_eq!(snapshot.learned_mtu(), None);
        }
    }
}

#[test]
fn correlated_errors_and_source_quench() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, _b, id) = connected(v6, &cfg, 2040);
        a.1.write(id, &[6; 500]).unwrap();
        let original = send(&mut a, 100).unwrap();
        drain_events(&mut a.1);
        let unreachable = if v6 { (1, 0) } else { (3, 1) };
        let mut wrong = original.clone();
        let h = header(&wrong);
        wrong[h + 7] ^= 1;
        seal_ipv4(&mut wrong);
        assert_eq!(
            dispatch(&mut a, 101, &icmp(&wrong, unreachable, 0)),
            UNCORRELATED
        );
        assert!(drain_events(&mut a.1).is_empty());
        let (report, published) =
            tcp_report(dispatch(&mut a, 102, &icmp(&original, unreachable, 0)));
        assert_eq!(
            report,
            TcpReport::NetworkError {
                error: NetworkError::SoftUnreachable,
                accepted: true
            }
        );
        assert_eq!(published, None);
        assert!(drain_events(&mut a.1).iter().any(|e| matches!(
            e,
            Event::Connection(c, events) if *c == id
                && events.network_error == Some(NetworkError::SoftUnreachable)
        )));
        assert_eq!(a.1.state(id).unwrap(), State::Established);
        if !v6 {
            let quench = icmp(&original, (4, 0), 0);
            assert_eq!(
                dispatch(&mut a, 103, &quench),
                IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::SourceQuench))
            );
            assert_eq!(
                a.0.input_ip(
                    &mut a.1,
                    a.2,
                    103,
                    &quench,
                    RxPacketMetadata::default(),
                    0,
                    None
                ),
                Ok(ntcp::InputDisposition::Dropped)
            );
            assert!(drain_events(&mut a.1).is_empty());
        }
    }
}

#[test]
fn reserved_owner_defers_without_effect_and_replay_revalidates_generation() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (mut a, _b, id) = connected(v6, &cfg, 2050);
        a.1.write(id, &[7; 2800]).unwrap();
        let original = send(&mut a, 100).unwrap();
        let (held, _, frame) = selected(&mut a.1, 101).unwrap();
        assert!(a.1.is_output_reserved(id));
        let report = ptb(&original, smaller(v6));
        let before = (current_mtu(&a, id), learned(&a, id));
        let IcmpDispatch::Deferred(deferred) = dispatch(&mut a, 102, &report) else {
            panic!("reserved owner must defer");
        };
        assert_eq!((deferred.owner(), deferred.context()), (id, a.2));
        // The established entrypoint keeps OutputReserved, nothing applied.
        assert_eq!(
            a.0.input_ip(
                &mut a.1,
                a.2,
                102,
                &report,
                RxPacketMetadata::default(),
                0,
                None
            ),
            Err(Error::Endpoint(EndpointError::OutputReserved))
        );
        assert_eq!((current_mtu(&a, id), learned(&a, id)), before);
        // Still reserved: replay defers again.
        assert!(matches!(
            a.0.replay_icmp(&mut a.1, deferred, 103, &report).unwrap(),
            IcmpDispatch::Deferred(_)
        ));
        // The held attempt is submitted; the reservation resolves.
        let context = a.0.egress_context(&mut a.1, held).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let result =
            a.0.submit(&mut a.1, 103, ticket, context, &frame, 0, |_| {
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(result == Submission::Submitted);
        assert!(!a.1.is_output_reserved(id));
        let (report_out, published) =
            tcp_report(a.0.replay_icmp(&mut a.1, deferred, 104, &report).unwrap());
        assert!(matches!(
            report_out,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        assert_eq!(published, Some(path::EstimateChange::Decreased));
        assert_eq!(learned(&a, id), Some(smaller(v6)));
        // The generation ends: a later replay of the same frame is stale.
        a.1.abort(id).unwrap();
        a.1.release(id).unwrap();
        assert_eq!(
            a.0.replay_icmp(&mut a.1, deferred, 105, &report).unwrap(),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Stale))
        );
        // Fresh input about the released generation is equally stale.
        a.0.collect(&a.1).unwrap();
        assert_eq!(
            dispatch(&mut a, 106, &report),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Stale))
        );
        std::println!("v6={v6}: deferred while reserved, replay decreased, ended generation stale");
    }
}

// A deferred report acts only for its own generation even when the frame
// replayed under it correlates with a different live, sealed generation:
// here the retained frame quotes another connection's SYN, which a fresh
// dispatch would apply to that connection.
#[test]
fn replay_never_applies_a_deferred_report_to_another_live_generation() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let (mut a, _b, id) = connected(v6, &cfg, 2060);
        a.1.write(id, &[7; 2800]).unwrap();
        let original = send(&mut a, 100).unwrap();
        let (held, _, frame) = selected(&mut a.1, 101).unwrap();
        let IcmpDispatch::Deferred(deferred) = dispatch(&mut a, 102, &ptb(&original, smaller(v6)))
        else {
            panic!("reserved owner must defer");
        };
        assert_eq!(deferred.owner(), id);
        let context = a.0.egress_context(&mut a.1, held).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        a.0.submit(&mut a.1, 103, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
        assert!(!a.1.is_output_reserved(id));
        let second_local = SocketAddr::new(local.ip(), local.port() + 1);
        let other =
            a.1.connect_with_path_provider(104, second_local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let syn = send(&mut a, 104).unwrap();
        drain_events(&mut a.1);
        let unreachable = if v6 { (1, 4) } else { (3, 3) };
        let report = icmp(&syn, unreachable, 0);
        let before = (current_mtu(&a, id), learned(&a, id), learned(&a, other));
        assert_eq!(
            a.0.replay_icmp(&mut a.1, deferred, 105, &report).unwrap(),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Stale))
        );
        assert_eq!(a.1.state(other).unwrap(), State::SynSent);
        assert!(drain_events(&mut a.1).is_empty());
        assert_eq!(
            (current_mtu(&a, id), learned(&a, id), learned(&a, other)),
            before
        );
        // The same frame, dispatched fresh, does belong to the other owner.
        assert!(matches!(
            dispatch(&mut a, 106, &report),
            IcmpDispatch::Completed(IcmpOutcome::Tcp { owner, .. }) if owner == other
        ));
        std::println!("v6={v6}: replay for {id:?} discarded a quote owned by {other:?}");
    }
}

// One Host context with two links; the local address is registered (and
// routed) on link 1 only.
fn two_links(v6: bool, identity: u128, cfg: &EndpointConfig) -> (Side, IngressContext) {
    let (local, _) = addresses(v6);
    let (mut paths, limits) = managed_limits(cfg, 2, 2, 2, 4, 1).unwrap();
    paths.paths += 1;
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
    )
    .unwrap();
    let capabilities = ReceiveCapabilities {
        max_ip_packet: 65575,
        ipv4: Ipv4Receive::Options {
            source_routes: false,
        },
        ipv6: Ipv6Receive::BaseHeader,
        gro: false,
    };
    let first = host
        .register_link(
            InterfaceKey(1),
            1500,
            capabilities,
            Forwarding::Forwarder(ForwarderId(9)),
        )
        .unwrap();
    let second = host
        .register_link(
            InterfaceKey(2),
            1500,
            capabilities,
            Forwarding::Forwarder(ForwarderId(10)),
        )
        .unwrap();
    host.register_source(ScopedAddress::new(local.ip(), None).unwrap(), first.link())
        .unwrap();
    if v6 {
        host.register_source(
            ScopedAddress::new("fe80::1".parse().unwrap(), Some(first.link())).unwrap(),
            first.link(),
        )
        .unwrap();
    }
    host.add_route(path::Route {
        destination: path::IpPrefix::new(if v6 { "::" } else { "0.0.0.0" }.parse().unwrap(), 0)
            .unwrap(),
        source: None,
        dscp: None,
        link: first.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    })
    .unwrap();
    let mut endpoint =
        Endpoint::new(
            cfg.clone(),
            [identity as u8; 32],
            0,
            move |request| match request {
                ntcp::AddressValidation::Bind { local: address }
                | ntcp::AddressValidation::Open { local: address, .. } => address == local.ip(),
                ntcp::AddressValidation::Incoming { destination, .. } => destination == local.ip(),
                ntcp::AddressValidation::Route { source, .. } => source == local.ip(),
            },
        )
        .unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    ((host, endpoint, first), second)
}

#[test]
fn asymmetric_arrival_admits_unscoped_errors_only() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let (mut a, second) = two_links(v6, 2060, &cfg);
        let mut b = managed(remote, 2061, cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        a.1.write(id, &[8; 1400]).unwrap();
        let original = send(&mut a, now + 10).unwrap();
        // TCP ingress ownership is unchanged: the address is not owned on
        // the second link, so a peer segment arriving there is refused.
        b.1.write(
            b.1.connection_id(Tuple {
                local: remote,
                remote: local,
            })
            .unwrap(),
            &[1; 10],
        )
        .unwrap();
        let data = emit(&mut b.0, &mut b.1, now + 11).unwrap();
        assert_eq!(
            a.0.input_ip(
                &mut a.1,
                second,
                now + 12,
                &data,
                RxPacketMetadata::default(),
                0,
                None
            ),
            Err(Error::Path(path::Error::NoRoute))
        );
        // The router's error about our submission returns over link 2.
        let report = ptb(&original, smaller(v6));
        let (report, published) =
            tcp_report(a.0.input_icmp(&mut a.1, second, now + 13, &report).unwrap());
        assert!(matches!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        assert_eq!(published, Some(path::EstimateChange::Decreased));
        // The outgoing link is not inferred from arrival.
        assert_eq!(a.0.binding(id).unwrap().snapshot.key().link(), a.2.link());
        if v6 {
            // A link-scoped destination stays bound to its own link.
            let mut scoped = original.clone();
            scoped[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
            let report = ptb(&scoped, 1280);
            assert_eq!(
                a.0.input_icmp(&mut a.1, second, now + 14, &report),
                Err(Error::Path(path::Error::NoRoute))
            );
            assert_eq!(
                a.0.input_icmp(&mut a.1, a.2, now + 14, &report).unwrap(),
                UNCORRELATED
            );
        }
        std::println!("v6={v6}: PTB via second link accepted; TCP and scoped ICMP there refused");
    }
}
