// Exact dropped-range repair driven by Host-dispatched PTBs, through real
// Host/Endpoint owners and a real peer receiver: only the quoted connection
// repairs, a partially acknowledged quote stays valid, a reserved owner's
// deferred report survives ledger eviction and path replacement, and a
// reserved repair raced by a decrease is one physical Host submission in
// Restart.
use super::dispatch::{header, ptb, quote_key, tcp_report};
use super::fanout::{Held, reserve};
use super::*;

type Side = (Host, Endpoint, IngressContext);

fn cfg() -> EndpointConfig {
    let mut cfg = config(4);
    cfg.connection.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    cfg.connection.sack = true;
    cfg
}
// Payload of a full-sized 1500-octet segment (timestamps negotiated), and the
// payload a complete IP packet of `mtu` octets carries.
fn full(v6: bool) -> usize {
    payload(v6, 1500)
}
fn payload(v6: bool, mtu: u32) -> usize {
    mtu as usize - if v6 { 40 } else { 20 } - 32
}
fn connect(side: &mut Side, cfg: &EndpointConfig, port: u16, now: u64) -> ConnectionId {
    let (local, remote) = addresses(is_v6(side));
    side.1
        .connect_with_path_provider(
            now,
            SocketAddr::new(local.ip(), port),
            remote,
            options(cfg, 0),
            &mut side.0,
        )
        .unwrap()
}
fn is_v6(side: &Side) -> bool {
    side.0
        .paths()
        .sources()
        .next()
        .is_some_and(|(_, a)| a.address().is_ipv6())
}
// (source port, sequence, payload length, flags) of complete wire bytes.
pub(super) fn segment(wire: &[u8]) -> (u16, u32, usize, u8) {
    let t = &wire[header(wire)..];
    let offset = usize::from(t[12] >> 4) * 4;
    (
        u16::from_be_bytes([t[0], t[1]]),
        u32::from_be_bytes(t[4..8].try_into().unwrap()),
        t.len() - offset,
        t[13],
    )
}
// Submit one reserved attempt through the Host transaction.
fn commit(side: &mut Side, attempt: TransmitAttempt, frame: &[u8], external: usize, now: u64) {
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let result = side
        .0
        .submit(&mut side.1, now, ticket, context, frame, external, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(result == Submission::Submitted);
}
// Reserve and submit one physical packet of `id`; the complete wire bytes.
fn submit(side: &mut Side, id: ConnectionId, now: u64, mode: Held) -> Option<Vec<u8>> {
    let (attempt, frame, external, wire) = reserve(side, id, now, mode)?;
    commit(side, attempt, &frame, external, now);
    Some(wire)
}
fn deliver(to: &mut Side, now: u64, frames: &[Vec<u8>]) {
    for frame in frames {
        input(&mut to.0, &mut to.1, to.2, now, frame, 0);
    }
}
fn drain(side: &mut Side, now: u64) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| emit(&mut side.0, &mut side.1, now)).collect()
}
// Exchange until quiet; every frame `a` emits is returned.
fn exchange(a: &mut Side, b: &mut Side, now: &mut u64) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    for _ in 0..256 {
        *now += 10;
        let out = drain(a, *now);
        deliver(b, *now + 1, &out);
        let back = drain(b, *now + 2);
        deliver(a, *now + 3, &back);
        if out.is_empty() && back.is_empty() {
            return sent;
        }
        sent.extend(out);
    }
    panic!("wire exchange did not quiesce");
}
fn read_all(side: &mut Side, id: ConnectionId, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len + 1];
    let n = side.1.read(id, &mut bytes).unwrap();
    bytes.truncate(n);
    bytes
}
fn peer(b: &Side, local: SocketAddr, port: u16) -> ConnectionId {
    b.1.connection_id(Tuple {
        local: addresses(local.is_ipv6()).1,
        remote: SocketAddr::new(local.ip(), port),
    })
    .unwrap()
}
fn stream(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ salt).collect()
}

// Two TCP owners share one path and both have three full-sized segments in
// flight; the path drops only A's middle segment and the router's PTB quotes
// it. A repairs exactly the quoted range: one packet in Restart at the new
// size, the rest after useful ACK progress. B adopts the shared decrease by
// budget alone and never retransmits (T10's fanout isolation). A later,
// smaller PTB for the same original arrives once its prefix is cumulatively
// acknowledged: it is accepted, not rejected, and repairs nothing twice.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.2
//= type=test
//= reason=Drop notification is distinct from path-change notification: Host::input_icmp correlates a validated PTB with committed submission evidence and hands it to the quoting connection at once (a report for an owner whose output is reserved is deferred with its normalized evidence and replayed when the reservation ends, without the possibly evicted ledger record), while the PMTU change reaches other users of the path only through Host::service_changes before their next output. Only bytes a PTB names are retransmitted: repair work is the quoted span's intersection with outstanding, unSACKed, never-retransmitted bytes, reclipped at selection, including non-head, partially acknowledged, wrapped and SACK-split ranges, and a PTB-caused MSS decrease no longer schedules a head retry. Dual-family Host tests repair exactly the quoted range of the quoted connection while an unquoted connection on the same path only adopts the budget and never retransmits; the isolated namespace tcp-staged case shows from captured packets that the first PTB-driven retransmission lies inside the quoted non-head range milliseconds after the real router PTB, while the head is unacknowledged.
//# It is important to understand that the notification of the packetization layer instances using the path about the change in the PMTU is distinct from the notification of a specific instance that a packet has been dropped. The latter should be done as soon as practical (i.e., asynchronously from the point of view of the packetization layer instance), while the former may be delayed until a packetization layer instance wants to create a packet. Retransmission should be done for only for those packets that are known to be dropped, as indicated by a Datagram Too Big message.
fn host_ptb_repairs_exact_quoted_range_of_the_quoted_connection_only() {
    for v6 in [false, true] {
        let cfg = cfg();
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 7000 + u64::from(v6), cfg.clone());
        let mut b = managed(remote, 7100 + u64::from(v6), cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let flow_a = connect(&mut a, &cfg, 1000, 0);
        let flow_b = connect(&mut a, &cfg, 1001, 0);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        let seg = full(v6);
        let data = [stream(3 * seg, 0), stream(3 * seg, 0x5a)];
        a.1.write(flow_a, &data[0]).unwrap();
        a.1.write(flow_b, &data[1]).unwrap();
        now += 10;
        let mut sent = Vec::new();
        for id in [flow_a, flow_b] {
            while let Some(wire) = submit(&mut a, id, now, Held::Scalar) {
                assert_eq!(wire.len(), 1500);
                sent.push(wire);
            }
        }
        assert_eq!(sent.len(), 6);
        let quoted = sent.remove(1);
        let (_, start, len, _) = segment(&quoted);
        deliver(&mut b, now + 1, &sent);
        // The peer's ACKs (A's carry a SACK block) are still on the way.
        let held = drain(&mut b, now + 2);
        let mtu = if v6 { 1350 } else { 1100 };
        let (report, published) = tcp_report(
            a.0.input_icmp(&mut a.1, a.2, now + 3, &ptb(&quoted, mtu), None)
                .unwrap(),
        );
        assert!(matches!(
            report,
            TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
        ));
        assert_eq!(published, Some(path::EstimateChange::Decreased));
        assert_eq!(a.0.service_changes(&mut a.1, now + 3).unwrap().failed, 0);
        for id in [flow_a, flow_b] {
            assert_eq!(a.1.managed_path(id).unwrap().ordinary_ip_budget, mtu);
        }
        // Restart: one repair packet, the head of the quoted range.
        assert!(submit(&mut a, flow_b, now + 4, Held::Scalar).is_none());
        let first = submit(&mut a, flow_a, now + 4, Held::Scalar).unwrap();
        let prefix = payload(v6, mtu);
        assert_eq!(segment(&first), (1000, start, prefix, segment(&first).3));
        assert!(submit(&mut a, flow_a, now + 4, Held::Scalar).is_none());
        deliver(&mut b, now + 5, &[first]);
        deliver(&mut a, now + 6, &held);
        let acks = drain(&mut b, now + 7);
        deliver(&mut a, now + 8, &acks);
        let suffix = start.wrapping_add(prefix as u32);
        assert_eq!(
            a.1.send_progress(flow_a).unwrap().unacknowledged_sequence,
            suffix
        );
        // A late, smaller report quoting the partially acknowledged original.
        let lower = if v6 { 1280 } else { 1006 };
        let (late, _) = tcp_report(
            a.0.input_icmp(&mut a.1, a.2, now + 9, &ptb(&quoted, lower), None)
                .unwrap(),
        );
        // Below the 1500-octet delivery the peer has now proven: the size waits
        // for authorization, the drop advice does not.
        assert_eq!(late, TcpReport::PacketTooBig(PmtuFeedback::Deferred));
        // The unrepaired suffix follows under ordinary admission, once.
        let rest = submit(&mut a, flow_a, now + 10, Held::Scalar).unwrap();
        assert_eq!(
            segment(&rest),
            (1000, suffix, len - prefix, segment(&rest).3)
        );
        assert!(submit(&mut a, flow_a, now + 10, Held::Scalar).is_none());
        assert!(submit(&mut a, flow_b, now + 10, Held::Scalar).is_none());
        deliver(&mut b, now + 11, &[rest]);
        now += 20;
        let later = exchange(&mut a, &mut b, &mut now);
        assert!(
            later.iter().all(|f| segment(f).2 == 0),
            "nothing else is retransmitted"
        );
        for (port, (id, data)) in [(1000, (flow_a, &data[0])), (1001, (flow_b, &data[1]))] {
            let child = peer(&b, local, port);
            assert_eq!(&read_all(&mut b, child, data.len()), data);
            assert_eq!(a.1.acknowledged(id).unwrap(), data.len() as u64);
        }
        let info = a.1.transport_info(flow_b).unwrap();
        assert_eq!(
            (info.lost, info.retransmitted, info.recovery),
            (0, 0, false)
        );
        std::println!(
            "HOST_REPAIR v6={v6} quoted=[{start},+{len}) restart={prefix} suffix={} late={late:?}",
            len - prefix
        );
    }
}

// A report about a reserved owner is deferred with its normalized evidence.
// Before it is replayed, the owner's bounded two-entry history evicts the
// quoted submission (a fresh dispatch of the same frame no longer names the
// owner) and, in one variant, the owner moves to another path incarnation.
// The token alone still drives exact repair of the quoted range; on the
// replaced path it is drop advice only, with nothing published or lowered.
#[test]
fn deferred_report_survives_ledger_eviction_and_path_replacement() {
    for v6 in [false, true] {
        for replace in [false, true] {
            let cfg = cfg();
            let (local, remote) = addresses(v6);
            let identity = 7200 + u64::from(v6) * 2 + u64::from(replace);
            let send_capacity = cfg.connection.send_capacity;
            let mut a = managed_with(local, identity, cfg.clone(), false, None, None, |l| {
                l.segment_bytes = send_capacity;
                l.history_per_owner = 2;
                1
            });
            let mut b = managed(remote, identity + 100, cfg.clone());
            b.1.listen(remote, 4).unwrap();
            let id = connect(&mut a, &cfg, 1000, 0);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            let seg = full(v6);
            let data = stream(4 * seg, 3);
            a.1.write(id, &data).unwrap();
            now += 10;
            let quoted = submit(&mut a, id, now, Held::Scalar).unwrap();
            let (_, start, len, _) = segment(&quoted);
            let (attempt, frame, external, second) =
                reserve(&mut a, id, now, Held::Scalar).unwrap();
            let mtu = if v6 { 1350 } else { 1100 };
            let report = ptb(&quoted, mtu);
            let IcmpDispatch::Deferred(deferred) =
                a.0.input_icmp(&mut a.1, a.2, now + 1, &report, None).unwrap()
            else {
                panic!("reserved owner must defer");
            };
            commit(&mut a, attempt, &frame, external, now + 1);
            let mut rest = vec![second];
            while let Some(wire) = submit(&mut a, id, now + 1, Held::Scalar) {
                rest.push(wire);
            }
            assert_eq!(rest.len(), 3);
            // The quoted record was evicted: the raw frame no longer names A.
            assert_eq!(a.0.correlate(now + 2, &quote_key(&quoted)).owner, None);
            assert!(matches!(
                a.0.input_icmp(&mut a.1, a.2, now + 2, &report, None).unwrap(),
                IcmpDispatch::Completed(IcmpOutcome::Discarded(_))
            ));
            let old = a.0.binding(id).unwrap().snapshot.path();
            if replace {
                a.0.rebind_dscp(&mut a.1, id, 8).unwrap();
                assert_ne!(a.0.binding(id).unwrap().snapshot.path(), old);
            }
            let (outcome, published) =
                tcp_report(a.0.replay_icmp(&mut a.1, deferred, now + 3).unwrap());
            let current = a.1.path_mtu_info(id).unwrap().unwrap().current_mtu;
            let budget = if replace {
                assert_eq!(
                    (outcome, published),
                    (TcpReport::PacketTooBig(PmtuFeedback::Unchanged), None)
                );
                assert_eq!(current, 1500);
                if let Ok(snapshot) = a.0.paths().path_snapshot(old) {
                    assert_eq!(snapshot.learned_mtu(), None);
                }
                1500
            } else {
                assert!(matches!(
                    outcome,
                    TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
                ));
                assert_eq!(published, Some(path::EstimateChange::Decreased));
                assert_eq!(current, mtu);
                mtu
            };
            // Exact repair of the quoted range, one packet in Restart.
            let repair = submit(&mut a, id, now + 4, Held::Scalar).unwrap();
            let first = payload(v6, budget).min(len);
            assert_eq!(segment(&repair), (1000, start, first, segment(&repair).3));
            assert!(submit(&mut a, id, now + 4, Held::Scalar).is_none());
            deliver(&mut b, now + 5, &rest);
            deliver(&mut b, now + 5, &[repair]);
            let acks = drain(&mut b, now + 6);
            deliver(&mut a, now + 7, &acks);
            now += 10;
            let later = exchange(&mut a, &mut b, &mut now);
            let repaired: usize = later.iter().map(|f| segment(f).2).sum();
            assert_eq!(repaired, len - first, "only the quoted suffix follows");
            let child = peer(&b, local, 1000);
            assert_eq!(read_all(&mut b, child, data.len()), data);
            std::println!(
                "DEFERRED v6={v6} replace={replace} evicted=true outcome={outcome:?} published={published:?} repair={first}+{}",
                len - first
            );
        }
    }
}

// Replay revalidates the quote's overlap with outstanding data: a deferred
// report whose quoted segment the peer cumulatively acknowledged meanwhile is
// rejected, with no repair, estimate change or publication.
#[test]
fn deferred_report_about_data_acknowledged_meanwhile_is_rejected_on_replay() {
    for v6 in [false, true] {
        let cfg = cfg();
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 7300 + u64::from(v6), cfg.clone());
        let mut b = managed(remote, 7350 + u64::from(v6), cfg.clone());
        b.1.listen(remote, 4).unwrap();
        let id = connect(&mut a, &cfg, 1000, 0);
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        a.1.write(id, &stream(2 * full(v6), 5)).unwrap();
        now += 10;
        let quoted = submit(&mut a, id, now, Held::Scalar).unwrap();
        let (attempt, frame, external, second) = reserve(&mut a, id, now, Held::Scalar).unwrap();
        let mtu = if v6 { 1350 } else { 1100 };
        let IcmpDispatch::Deferred(deferred) =
            a.0.input_icmp(&mut a.1, a.2, now + 1, &ptb(&quoted, mtu), None)
                .unwrap()
        else {
            panic!("reserved owner must defer");
        };
        commit(&mut a, attempt, &frame, external, now + 1);
        deliver(&mut b, now + 2, &[quoted, second]);
        let acks = drain(&mut b, now + 3);
        deliver(&mut a, now + 4, &acks);
        assert_eq!(a.1.transport_info(id).unwrap().unacked, 0);
        let path = a.0.binding(id).unwrap().snapshot.path();
        assert_eq!(
            tcp_report(a.0.replay_icmp(&mut a.1, deferred, now + 5).unwrap()),
            (TcpReport::PacketTooBig(PmtuFeedback::Rejected), None)
        );
        assert_eq!(a.1.path_mtu_info(id).unwrap().unwrap().current_mtu, 1500);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        assert!(submit(&mut a, id, now + 5, Held::Scalar).is_none());
    }
}

// A reserved Restart repair (scalar, zero-copy, or after software-GSO
// originals) raced by a first-hop decrease: the Host barrier refuses the
// held bytes before any backend call, the retained reservation's first
// fitting fragment is the one physical packet submitted through the Host
// transaction, and that acceptance releases the reservation (the never
// charged suffix waits for useful ACK progress). Outside Restart, another
// racing decrease uses ordinary fragment acceptance.
#[test]
fn host_reserved_ptb_repair_raced_by_decrease_is_one_physical_packet_in_restart() {
    use Held::*;
    for v6 in [false, true] {
        for mode in [Scalar, ZeroCopy, PartialGso] {
            let cfg = cfg();
            let (local, remote) = addresses(v6);
            let identity = 7400 + u64::from(v6) * 4 + mode as u64;
            let mut a = managed_configured(local, identity, cfg.clone(), mode == PartialGso, None);
            let mut b = managed(remote, identity + 100, cfg.clone());
            b.1.listen(remote, 4).unwrap();
            let id = connect(&mut a, &cfg, 1000, 0);
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            let seg = full(v6);
            let data = stream(3 * seg, 9);
            if mode == ZeroCopy {
                a.1.enable_shared_output(4).unwrap();
                a.1.write_shared(id, ntcp::Payload::from_vec(data.clone()), false, true, None)
                    .unwrap();
            } else {
                a.1.write(id, &data).unwrap();
            }
            now += 10;
            let mut originals = Vec::new();
            while let Some((attempt, frame, external, wire)) = reserve(&mut a, id, now, mode) {
                if originals.is_empty() {
                    assert_eq!(
                        a.1.transmit_segmentation(attempt).is_some(),
                        mode == PartialGso
                    );
                }
                commit(&mut a, attempt, &frame, external, now);
                originals.push(wire);
            }
            assert_eq!(originals.len(), 3);
            let quoted = originals.remove(1);
            let (_, start, len, _) = segment(&quoted);
            deliver(&mut b, now + 1, &originals);
            let held_acks = drain(&mut b, now + 2);
            let mtu = if v6 { 1420 } else { 1300 };
            assert!(matches!(
                tcp_report(
                    a.0.input_icmp(&mut a.1, a.2, now + 3, &ptb(&quoted, mtu), None)
                        .unwrap()
                )
                .0,
                TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
            ));
            let (held, frame, external, wire) = reserve(&mut a, id, now + 4, mode).unwrap();
            assert_eq!(
                segment(&wire),
                (1000, start, payload(v6, mtu), segment(&wire).3)
            );
            let context = a.0.egress_context(&mut a.1, held).unwrap();
            let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let link = a.0.binding(id).unwrap().snapshot.key().link();
            let racing = if v6 { 1300 } else { 1000 };
            a.0.set_link_mtu(link, racing).unwrap();
            assert_eq!(a.0.service_changes(&mut a.1, now + 4).unwrap().failed, 0);
            let mut calls = 0;
            let refused =
                a.0.submit(&mut a.1, now + 4, ticket, context, &frame, external, |_| {
                    calls += 1;
                    BackendOutcome::Submitted
                })
                .unwrap_err();
            assert_eq!((refused.error, calls), (Error::Obsolete, 0));
            assert!(a.1.reject_unsubmitted(held).unwrap());
            a.0.cancel_submission(refused.ticket);
            let before = a.1.transport_info(id).unwrap();
            let prefix = submit(&mut a, id, now + 5, mode).unwrap();
            let first = payload(v6, racing);
            assert!(prefix.len() <= racing as usize);
            assert_eq!(segment(&prefix), (1000, start, first, segment(&prefix).3));
            assert!(!a.1.is_output_reserved(id), "the reservation ends there");
            assert!(reserve(&mut a, id, now + 5, mode).is_none());
            let after = a.1.transport_info(id).unwrap();
            // Charged once, for the accepted fragment only.
            assert_eq!(after.retransmitted, before.retransmitted + 1);
            deliver(&mut b, now + 6, &[prefix]);
            deliver(&mut a, now + 7, &held_acks);
            let acks = drain(&mut b, now + 8);
            deliver(&mut a, now + 9, &acks);
            let suffix = start.wrapping_add(first as u32);
            assert_eq!(
                a.1.send_progress(id).unwrap().unacknowledged_sequence,
                suffix
            );
            // Outside Restart: ordinary fragment acceptance after a decrease.
            let (held, frame, external, wire) = reserve(&mut a, id, now + 10, mode).unwrap();
            assert_eq!(
                segment(&wire),
                (1000, suffix, len - first, segment(&wire).3)
            );
            let context = a.0.egress_context(&mut a.1, held).unwrap();
            let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
            let smallest = if v6 { 1280 } else { 400 };
            a.0.set_link_mtu(link, smallest).unwrap();
            assert_eq!(a.0.service_changes(&mut a.1, now + 10).unwrap().failed, 0);
            let end = start.wrapping_add(len as u32);
            let (mut at, mut fragments) = (suffix, 0);
            match a.0.submit(
                &mut a.1,
                now + 10,
                ticket,
                context,
                &frame,
                external,
                |_| BackendOutcome::Submitted,
            ) {
                Err(refused) => {
                    assert_eq!(refused.error, Error::Obsolete);
                    assert!(a.1.reject_unsubmitted(held).unwrap());
                    a.0.cancel_submission(refused.ticket);
                }
                // IPv6's 1280-octet floor leaves the suffix fitting whole.
                Ok(result) => {
                    assert!(v6 && result == Submission::Submitted);
                    assert!(!a.1.is_output_reserved(id));
                    deliver(&mut b, now + 12, &[wire]);
                    (at, fragments) = (end, 1);
                }
            }
            while at != end {
                let wire = submit(&mut a, id, now + 11, mode).unwrap();
                let (_, seq, n, _) = segment(&wire);
                assert!(wire.len() <= smallest as usize);
                assert_eq!(seq, at);
                at = at.wrapping_add(n as u32);
                fragments += 1;
                assert_eq!(a.1.is_output_reserved(id), at != end);
                deliver(&mut b, now + 12, &[wire]);
            }
            assert_eq!(fragments > 1, !v6);
            assert!(reserve(&mut a, id, now + 12, mode).is_none());
            now += 20;
            let later = exchange(&mut a, &mut b, &mut now);
            assert!(later.iter().all(|f| segment(f).2 == 0));
            let child = peer(&b, local, 1000);
            assert_eq!(read_all(&mut b, child, data.len()), data);
            std::println!(
                "HOST_RESERVED v6={v6} mode={mode:?} restart_prefix={first} suffix={} fragments={fragments}",
                len - first
            );
        }
    }
}

// Reference model of one TCP owner generation in the randomized driver, per
// stream offset: transmissions observed on the wire, the bytes an accepted
// report may have made pending (quoted, outstanding, sent once, not SACKed,
// not in an RTO's old flight), and the SACK scoreboard the peer reported.
struct Flow {
    id: ConnectionId,
    port: u16,
    base: Option<u32>,
    written: Vec<u8>,
    received: Vec<u8>,
    copies: Vec<u8>,
    pending: Vec<bool>,
    sacked: Vec<bool>,
    high: usize,
    una: usize,
    rto_until: Option<usize>,
    quoted: bool,
    restart: bool,
    restart_packets: u32,
    live: bool,
}
impl Flow {
    fn new(id: ConnectionId, port: u16) -> Self {
        Self {
            id,
            port,
            base: None,
            written: Vec::new(),
            received: Vec::new(),
            copies: Vec::new(),
            pending: Vec::new(),
            sacked: Vec::new(),
            high: 0,
            una: 0,
            rto_until: None,
            quoted: false,
            restart: false,
            restart_packets: 0,
            live: true,
        }
    }
    fn offset(&self, seq: u32) -> Option<usize> {
        let off = seq.wrapping_sub(self.base?) as usize;
        (off <= self.written.len() + 1).then_some(off)
    }
    fn grow(&mut self) {
        let n = self.written.len() + 1;
        self.copies.resize(n, 0);
        self.pending.resize(n, false);
        self.sacked.resize(n, false);
    }
}

#[derive(Default, Debug)]
struct TcpCoverage {
    submissions: usize,
    accepted_reports: usize,
    partial_ack_quotes: usize,
    restarts: usize,
    ptb_repairs: usize,
    ordinary_retransmissions: usize,
    sack_progress: usize,
    cumulative_progress: usize,
    rtos: usize,
    rto_scoreboard_resets: usize,
    repair_copy_reports: usize,
    deferred: usize,
    replays: usize,
    resegmentations: usize,
    generation_reuse: usize,
    stale_reports: usize,
}

type Infos = Vec<Option<ntcp::TransportInfo>>;

fn infos(a: &Side, flows: &[Flow]) -> Infos {
    flows
        .iter()
        .map(|f| f.live.then(|| a.1.transport_info(f.id).ok()).flatten())
        .collect()
}

// One frame A submitted: update the model and check every invariant a
// PTB repair must hold. A retransmission is ordinary when the owner is in
// loss recovery or the bytes belong to an RTO's old flight (TLP and RACK
// are disabled); any other retransmission is PTB repair.
fn observe(a: &Side, flows: &mut [Flow], before: &Infos, wire: &[u8], cov: &mut TcpCoverage) {
    cov.submissions += 1;
    let (port, seq, len, _) = segment(wire);
    let Some(index) = flows.iter().position(|f| f.live && f.port == port) else {
        return;
    };
    let f = &mut flows[index];
    let Some(start) = f.offset(seq).filter(|_| len != 0) else {
        return;
    };
    let end = start + len;
    if start < f.high {
        let info = before[index].unwrap();
        if info.recovery || f.rto_until.is_some_and(|until| start < until) {
            cov.ordinary_retransmissions += 1;
        } else {
            cov.ptb_repairs += 1;
            assert!(f.quoted, "PTB repair on an owner no report quoted");
            assert!(
                (start..end).all(|i| f.pending[i]),
                "repaired byte outside the eligible quoted outstanding intersection: [{start},{end}) una={} high={}",
                f.una,
                f.high
            );
            if f.restart {
                f.restart_packets += 1;
                assert!(
                    f.restart_packets <= 1,
                    "two PTB repair packets in one Restart"
                );
            }
            let after = a.1.transport_info(f.id).unwrap();
            assert_eq!(
                (after.retransmitted, after.lost),
                (info.retransmitted + 1, info.lost),
                "a committed repair copy is counted once, with no loss subtraction"
            );
        }
    }
    for i in start..end {
        f.copies[i] = f.copies[i].saturating_add(1);
        if f.copies[i] > 1 {
            f.pending[i] = false;
        }
    }
    f.high = f.high.max(end);
}

// ACK frames from the peer reached A: cumulative and SACK progress.
fn acknowledged(a: &Side, flows: &mut [Flow], acks: &[Vec<u8>], cov: &mut TcpCoverage) {
    for ack in acks {
        let h = header(ack);
        let t = &ack[h..];
        let port = u16::from_be_bytes([t[2], t[3]]);
        let Some(f) = flows.iter_mut().find(|f| f.live && f.port == port) else {
            continue;
        };
        let options = &t[20..usize::from(t[12] >> 4) * 4];
        let mut at = 0;
        while at < options.len() {
            match options[at] {
                0 => break,
                1 => at += 1,
                kind => {
                    let n = usize::from(options[at + 1]).max(2);
                    if kind == 5 {
                        for block in options[at + 2..at + n].chunks(8) {
                            let word =
                                |k: usize| u32::from_be_bytes(block[k..k + 4].try_into().unwrap());
                            let (Some(left), Some(right)) = (f.offset(word(0)), f.offset(word(4)))
                            else {
                                continue;
                            };
                            let mut new = false;
                            for i in left.max(f.una)..right.min(f.high) {
                                new |= !f.sacked[i];
                                f.sacked[i] = true;
                                f.pending[i] = false;
                            }
                            if new {
                                cov.sack_progress += 1;
                                f.restart = false;
                            }
                        }
                    }
                    at += n;
                }
            }
        }
    }
    for f in flows.iter_mut().filter(|f| f.live && f.base.is_some()) {
        let Ok(progress) = a.1.send_progress(f.id) else {
            continue;
        };
        let Some(una) = f.offset(progress.unacknowledged_sequence) else {
            continue;
        };
        if una > f.una {
            cov.cumulative_progress += 1;
            for i in f.una..una.min(f.pending.len()) {
                f.pending[i] = false;
            }
            f.una = una;
            f.restart = false;
            if f.rto_until.is_some_and(|until| una >= until) {
                f.rto_until = None;
            }
        }
    }
}

// An accepted report for `quote` of `f`: the bytes it may make pending.
fn accepted(f: &mut Flow, quote: &[u8], cov: &mut TcpCoverage) {
    cov.accepted_reports += 1;
    f.quoted = true;
    let (_, seq, len, _) = segment(quote);
    let Some(start) = f.offset(seq) else {
        return;
    };
    cov.partial_ack_quotes += usize::from(start < f.una && f.una < start + len);
    cov.repair_copy_reports += usize::from((start..start + len).any(|i| f.copies[i] > 1));
    let mut added = false;
    for i in start.max(f.una)..(start + len).min(f.high) {
        if f.copies[i] == 1
            && !f.sacked[i]
            && f.rto_until.is_none_or(|until| i >= until)
            && !f.pending[i]
        {
            f.pending[i] = true;
            added = true;
        }
    }
    if added {
        cov.restarts += 1;
        f.restart = true;
        f.restart_packets = 0;
    }
}

// A PTB never manufactures loss, recovery or a timer backoff.
fn unchanged(before: Option<ntcp::TransportInfo>, after: Option<ntcp::TransportInfo>) {
    let key = |i: Option<ntcp::TransportInfo>| {
        i.map(|i| (i.lost, i.retransmitted, i.recovery, i.rto_backoff))
    };
    assert_eq!(key(before), key(after), "PTB changed loss state");
}

// The peer accepts its children and the application reads every stream.
fn read_peer(
    b: &mut Side,
    listener: ntcp::ListenerId,
    flows: &mut [Flow],
    children: &mut Vec<(u16, ConnectionId)>,
    local: SocketAddr,
) {
    let remote = addresses(local.is_ipv6()).1;
    while let Ok(child) = b.1.accept(listener) {
        if let Some(port) = flows.iter().map(|f| f.port).find(|&p| {
            b.1.connection_id(Tuple {
                local: remote,
                remote: SocketAddr::new(local.ip(), p),
            }) == Some(child)
        }) {
            children.push((port, child));
        }
    }
    for &(port, child) in children.iter() {
        if let Some(f) = flows.iter_mut().find(|f| f.live && f.port == port) {
            let mut bytes = vec![0; 65536];
            if let Ok(n) = b.1.read(child, &mut bytes) {
                f.received.extend_from_slice(&bytes[..n]);
            }
        }
    }
}

// Expire A's earliest timer; an owner whose backoff grew had an RTO: its
// pending work ends, its scoreboard resets and its old flight belongs to
// ordinary recovery until acknowledged.
fn expire(a: &mut Side, flows: &mut [Flow], now: &mut u64, cov: &mut TcpCoverage) {
    // Retransmission timers only: the driver never jumps to the 600-second
    // PMTU hold or other long timers.
    let Some(deadline) = a.1.next_deadline().filter(|d| *d <= *now + 120_000_000) else {
        return;
    };
    *now = (*now).max(deadline);
    let before = infos(a, flows);
    a.1.on_timeout(*now, 32).unwrap();
    for (f, before) in flows.iter_mut().zip(before) {
        let (Some(before), Ok(after)) = (before, a.1.transport_info(f.id)) else {
            continue;
        };
        if f.base.is_some() && after.rto_backoff > before.rto_backoff {
            cov.rtos += 1;
            if f.sacked.iter().any(|s| *s) {
                cov.rto_scoreboard_resets += 1;
            }
            f.rto_until = Some(f.high);
            f.pending.iter_mut().for_each(|p| *p = false);
            f.sacked.iter_mut().for_each(|s| *s = false);
            f.restart = false;
        }
    }
}

// The Host-level seeded driver with TCP owners: three owner slots on one
// path send random writes through the Host transaction to a real peer over a
// random network (delivered, silently lost, or dropped as too big and quoted
// by a router PTB, repair copies included), with partial and SACK ACKs, RTOs
// (which reset the SACK scoreboard: a reneging receiver is indistinguishable),
// decreasing reports (resegmentation), PTBs about reserved owners deferred
// and replayed from their tokens, and generation reuse with stale reports
// about released owners. After every step: no PTB repair on an owner no
// report quoted, at most one PTB repair packet per Restart, no repaired byte
// outside the eligible quoted outstanding intersection (bytes sent once, so
// eligibility persists through RTO and scoreboard reset), each committed
// repair copy counted once without loss subtraction, and no PTB changes
// loss, recovery or backoff. Every stream is finally delivered intact.
#[test]
fn randomized_host_tcp_drop_repair_never_acts_beyond_the_model() {
    use super::fanout::Rng;
    let mut cov = TcpCoverage::default();
    let (seeds, steps) = (6u64, 400);
    for v6 in [false, true] {
        for seed in 1..=seeds {
            let mut rng = Rng((seed + 50 * u64::from(v6)).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let cfg = cfg();
            let (local, remote) = addresses(v6);
            let identity = 7600 + u64::from(seed) * 2 + u64::from(v6);
            let mut a = managed(local, identity, cfg.clone());
            // The peer outlives every generation the driver opens.
            let peer_cfg = EndpointConfig {
                max_connections: 64,
                ..cfg.clone()
            };
            let mut b = managed(remote, identity + 100, peer_cfg);
            let listener = b.1.listen(remote, 16).unwrap();
            let mut flows: Vec<Flow> = Vec::new();
            let mut next_port = 2000;
            let mut children: Vec<(u16, ConnectionId)> = Vec::new();
            for _ in 0..3 {
                flows.push(Flow::new(connect(&mut a, &cfg, next_port, 0), next_port));
                next_port += 1;
            }
            // Frames on the way to the peer and back, and quotable drops
            // with the owner generation that sent them.
            let (mut to_b, mut to_a): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), Vec::new());
            let mut quotable: Vec<(Vec<u8>, ConnectionId)> = Vec::new();
            let candidates: &[u32] = if v6 {
                &[1280, 1350, 1400]
            } else {
                &[0, 576, 1006, 1300]
            };
            let mut dscp = 0;
            let mut now = 1;
            let fate = |rng: &mut Rng,
                        wire: Vec<u8>,
                        owner: Option<ConnectionId>,
                        to_b: &mut Vec<Vec<u8>>,
                        quotable: &mut Vec<(Vec<u8>, ConnectionId)>| {
                match (rng.below(10), owner) {
                    (0..=1, Some(owner)) if wire.len() > if v6 { 1300 } else { 600 } => {
                        quotable.push((wire, owner))
                    }
                    (2, _) => {}
                    _ => to_b.push(wire),
                }
            };
            let owner_of = |flows: &[Flow], wire: &[u8]| {
                let port = segment(wire).0;
                flows
                    .iter()
                    .find(|f| f.live && f.port == port)
                    .map(|f| f.id)
            };
            for _ in 0..steps {
                now += 1 + rng.below(5);
                // The embedding's change service runs before output.
                assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().failed, 0);
                for f in flows.iter_mut().filter(|f| f.live && f.base.is_none()) {
                    if a.1.state(f.id).ok() == Some(State::Established) {
                        f.base = Some(a.1.send_progress(f.id).unwrap().unacknowledged_sequence);
                        f.grow();
                    }
                }
                let op = rng.below(100);
                if op < 14 {
                    let f = &mut flows[rng.below(3) as usize];
                    if f.live && f.base.is_some() {
                        let data = stream(rng.pick(&[300usize, 1400, 2900, 6000]), now as u8);
                        let n = a.1.write(f.id, &data).unwrap_or(0);
                        f.written.extend_from_slice(&data[..n]);
                        f.grow();
                    }
                } else if op < 44 {
                    for _ in 0..1 + rng.below(4) {
                        let before = infos(&a, &flows);
                        let Some(wire) = emit(&mut a.0, &mut a.1, now) else {
                            break;
                        };
                        observe(&a, &mut flows, &before, &wire, &mut cov);
                        let owner = owner_of(&flows, &wire);
                        fate(&mut rng, wire, owner, &mut to_b, &mut quotable);
                    }
                } else if op < 60 {
                    let n = rng.below(to_b.len() as u64 + 1) as usize;
                    deliver(&mut b, now, &to_b.drain(..n).collect::<Vec<_>>());
                    read_peer(&mut b, listener, &mut flows, &mut children, local);
                    to_a.extend(drain(&mut b, now));
                } else if op < 76 {
                    let n = rng.below(to_a.len() as u64 + 1) as usize;
                    let acks: Vec<_> = to_a.drain(..n).filter(|_| rng.below(8) != 0).collect();
                    deliver(&mut a, now, &acks);
                    acknowledged(&a, &mut flows, &acks, &mut cov);
                } else if op < 88 && !quotable.is_empty() {
                    let (quote, owner) =
                        quotable[rng.below(quotable.len() as u64) as usize].clone();
                    let choices: Vec<u32> = candidates
                        .iter()
                        .copied()
                        .filter(|&c| c < quote.len() as u32)
                        .collect();
                    if choices.is_empty() {
                        continue;
                    }
                    let report = ptb(&quote, rng.pick(&choices));
                    let index = flows.iter().position(|f| f.live && f.id == owner);
                    let Some(index) = index else {
                        // A released generation: nothing may act for it.
                        cov.stale_reports += 1;
                        let before = infos(&a, &flows);
                        assert!(matches!(
                            a.0.input_icmp(&mut a.1, a.2, now, &report, None).unwrap(),
                            IcmpDispatch::Completed(IcmpOutcome::Discarded(_))
                        ));
                        for (x, y) in before.iter().zip(infos(&a, &flows)) {
                            unchanged(*x, y);
                        }
                        continue;
                    };
                    // Sometimes the owner holds a reservation meanwhile.
                    let held = if rng.below(4) == 0 {
                        let before = infos(&a, &flows);
                        reserve(&mut a, owner, now, Held::Scalar).map(|r| (r, before))
                    } else {
                        None
                    };
                    let before = a.1.transport_info(owner).ok();
                    let mut dispatch = a.0.input_icmp(&mut a.1, a.2, now, &report, None).unwrap();
                    unchanged(before, a.1.transport_info(owner).ok());
                    if let Some(((attempt, frame, external, wire), infos_before)) = held {
                        // Nothing a reserved owner's report could act on is
                        // applied before the reservation resolves.
                        let token = match dispatch {
                            IcmpDispatch::Deferred(token) => Some(token),
                            IcmpDispatch::Completed(IcmpOutcome::Discarded(_)) => None,
                            other => panic!("reserved owner must defer: {other:?}"),
                        };
                        commit(&mut a, attempt, &frame, external, now);
                        observe(&a, &mut flows, &infos_before, &wire, &mut cov);
                        fate(&mut rng, wire, Some(owner), &mut to_b, &mut quotable);
                        let Some(token) = token else {
                            continue;
                        };
                        cov.deferred += 1;
                        let before = a.1.transport_info(owner).ok();
                        dispatch = a.0.replay_icmp(&mut a.1, token, now).unwrap();
                        unchanged(before, a.1.transport_info(owner).ok());
                        cov.replays += 1;
                    }
                    if let IcmpDispatch::Completed(IcmpOutcome::Tcp {
                        owner: acted,
                        report: TcpReport::PacketTooBig(class),
                        ..
                    }) = dispatch
                    {
                        assert_eq!(acted, owner, "a report acts for its own owner only");
                        if class != PmtuFeedback::Rejected {
                            accepted(&mut flows[index], &quote, &mut cov);
                        }
                        // Later output and repair are segmented smaller.
                        cov.resegmentations +=
                            usize::from(matches!(class, PmtuFeedback::Decreased { .. }));
                    }
                } else if op < 93 {
                    expire(&mut a, &mut flows, &mut now, &mut cov);
                } else {
                    // Generation reuse: release one owner and open another
                    // in its slot, on a fresh routing class (a path no report
                    // lowered below the converged initial search).
                    // Preferably an owner some quotable drop belongs to, so
                    // that later reports about it are stale.
                    let quoted_slot = quotable
                        .last()
                        .and_then(|(_, owner)| flows.iter().position(|f| f.id == *owner));
                    let slot = quoted_slot.unwrap_or(rng.below(3) as usize);
                    let id = flows[slot].id;
                    if a.1.is_output_reserved(id) {
                        continue;
                    }
                    let Ok(fresh) = a.1.connect_with_path_provider(
                        now,
                        SocketAddr::new(local.ip(), next_port),
                        remote,
                        options(&cfg, dscp + 1),
                        &mut a.0,
                    ) else {
                        continue;
                    };
                    dscp += 1;
                    flows[slot].live = false;
                    a.1.abort(id).unwrap();
                    a.1.release(id).unwrap();
                    a.0.collect(&a.1).unwrap();
                    assert_ne!(fresh, id);
                    flows[slot] = Flow::new(fresh, next_port);
                    next_port += 1;
                    cov.generation_reuse += 1;
                }
            }
            // Finish: a lossless network until every live stream is delivered.
            for _ in 0..2000 {
                now += 10;
                assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().failed, 0);
                for f in flows.iter_mut().filter(|f| f.live && f.base.is_none()) {
                    if a.1.state(f.id).ok() == Some(State::Established) {
                        f.base = Some(a.1.send_progress(f.id).unwrap().unacknowledged_sequence);
                        f.grow();
                    }
                }
                let mut sent = 0;
                loop {
                    let before = infos(&a, &flows);
                    let Some(wire) = emit(&mut a.0, &mut a.1, now) else {
                        break;
                    };
                    observe(&a, &mut flows, &before, &wire, &mut cov);
                    to_b.push(wire);
                    sent += 1;
                }
                deliver(&mut b, now, &core::mem::take(&mut to_b));
                read_peer(&mut b, listener, &mut flows, &mut children, local);
                to_a.extend(drain(&mut b, now + 1));
                let acks = core::mem::take(&mut to_a);
                deliver(&mut a, now + 2, &acks);
                acknowledged(&a, &mut flows, &acks, &mut cov);
                let done = flows.iter().all(|f| {
                    !f.live
                        || a.1
                            .acknowledged(f.id)
                            .is_ok_and(|n| n == f.written.len() as u64)
                });
                if done && sent == 0 {
                    break;
                }
                if sent == 0 && acks.is_empty() {
                    expire(&mut a, &mut flows, &mut now, &mut cov);
                }
            }
            for f in flows.iter().filter(|f| f.live) {
                assert_eq!(f.received, f.written, "seed {seed} v6={v6} port {}", f.port);
            }
        }
    }
    std::println!("HOST_TCP_REPAIR_INVARIANT families=2 seeds={seeds} steps={steps} {cov:?}");
    let TcpCoverage {
        submissions,
        accepted_reports,
        partial_ack_quotes,
        restarts,
        ptb_repairs,
        ordinary_retransmissions,
        sack_progress,
        cumulative_progress,
        rtos,
        rto_scoreboard_resets,
        repair_copy_reports,
        deferred,
        replays,
        resegmentations,
        generation_reuse,
        stale_reports,
    } = cov;
    for (name, count) in [
        ("submissions", submissions),
        ("accepted reports", accepted_reports),
        ("partially acknowledged quotes", partial_ack_quotes),
        ("Restarts", restarts),
        ("PTB repairs", ptb_repairs),
        ("ordinary retransmissions", ordinary_retransmissions),
        ("SACK progress", sack_progress),
        ("cumulative progress", cumulative_progress),
        ("RTOs", rtos),
        ("RTO scoreboard resets", rto_scoreboard_resets),
        ("repair-copy reports", repair_copy_reports),
        ("deferred reports", deferred),
        ("replays", replays),
        ("resegmentations", resegmentations),
        ("generation reuse", generation_reuse),
        ("stale reports", stale_reports),
    ] {
        assert!(count > 0, "no {name}");
    }
}
