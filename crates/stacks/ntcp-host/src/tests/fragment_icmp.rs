// ICMP errors quoting fragments this Host source-fragmented: a first
// fragment correlates by its UDP selector, a later one only by its exact
// physical evidence (never ports, never the IPv4 Identification); a unique
// match advises its owner with the dropped fragment's length, aliases allow
// only a path-level decrease, stale and evicted (portless summary) history
// keeps its ambiguity, and fragment quotes never reach TCP.
use super::dispatch::seal_ipv4;
use super::*;
use std::boxed::Box;
use std::sync::{Arc, Mutex};

type Side = (Host, Endpoint, IngressContext);

const MDL: u64 = 120_000_000;

fn side(local: SocketAddr, identity: u64, signatures: usize) -> Side {
    let cfg = config(2);
    let mut side = managed_limited(local, identity, cfg, false, None, None, |p, mut l| {
        l.datagrams = DatagramLimits {
            max_fragments: 8,
            identifiers: IdentifierLimits {
                lifetime_seconds: 120,
                ipv4_tuples: 4,
                ipv6_leases: 16,
            },
            // Fragments cut to the 1500 first hop, so an IPv6 PTB (at least
            // 1280) can report a fragment too big.
            connectionless: ConnectionlessSizing {
                ipv4: 1500,
                ipv6: 1500,
            },
            peer_reassembly_ipv4: None,
            peer_reassembly_ipv6: None,
            adjunct: AdjunctLimits::default(),
        };
        let udp = UdpLimits {
            flows: 3,
            receive_datagrams: 1,
            max_payload: 8000,
            events: 2,
            evicted_signatures: signatures,
            probe_receipts: 2,
        };
        let (p, l) = managed_udp_limits(p, l, udp).unwrap();
        (p, l, 1)
    });
    let state = Arc::new(Mutex::new(0x31u32));
    side.0.set_entropy(Box::new(move |out: &mut [u8]| {
        let mut s = state.lock().unwrap();
        for b in out.iter_mut() {
            *b = *s as u8;
        }
        *s = s.wrapping_add(1);
        Ok(())
    }));
    side.0.start_identifiers(Continuity::Fresh).unwrap();
    side
}

fn open(a: &mut Side, port: u16, remote: SocketAddr) -> UdpFlowId {
    let (local, _) = addresses(remote.is_ipv6());
    let options = UdpOptions {
        dscp: 0,
        hop_limit: 64,
    };
    let bind = SocketAddr::new(local.ip(), port);
    a.0.udp_open(&a.1, bind, Some(remote), options).unwrap()
}

// One fragmented datagram: its ledger owner (the flow generation) and every
// physical fragment as submitted.
fn send(a: &mut Side, now: u64, flow: UdpFlowId, payload: &[u8]) -> (Owner, Vec<Vec<u8>>) {
    let mut packet = vec![0; 16384];
    let mut sent = Vec::new();
    let send = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(8000),
    };
    let report =
        a.0.udp_send_datagram(
            &a.1,
            MDL + now,
            flow,
            None,
            Some(send),
            payload,
            &mut packet,
            |_, bytes| {
                sent.push(bytes.to_vec());
                BackendOutcome::Submitted
            },
        )
        .unwrap();
    assert_eq!(report.submitted, sent.len());
    assert_eq!(sent.len(), 3);
    let owner =
        a.0.ledger
            .records()
            .find(|r| {
                r.committed_at == MDL + now
                    && matches!(r.evidence.transport, Selector::UdpFirstFragment { .. })
            })
            .unwrap()
            .evidence
            .owner;
    (owner, sent)
}

fn address(packet: &[u8], at: usize, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::from(<[u8; 16]>::try_from(&packet[at..at + 16]).unwrap())
    } else {
        IpAddr::from(<[u8; 4]>::try_from(&packet[at..at + 4]).unwrap())
    }
}

// A router error about `packet`: ICMPv4 quotes its header and eight data
// octets, ICMPv6 as much as fits in 1280 octets.
fn report(packet: &[u8], kind: (u8, u8), value: u32) -> Vec<u8> {
    let v6 = packet[0] >> 4 == 6;
    let quote = &packet[..if v6 { packet.len().min(1232) } else { 28 }];
    let outer = IpMetadata {
        source: if v6 { "2001:db8::fe" } else { "192.0.2.254" }
            .parse()
            .unwrap(),
        destination: address(packet, if v6 { 8 } else { 12 }, v6),
    };
    let mut message = vec![0; 8 + quote.len()];
    message[0] = kind.0;
    message[1] = kind.1;
    message[4..8].copy_from_slice(&value.to_be_bytes());
    message[8..].copy_from_slice(quote);
    let sum = if v6 {
        ntcp_icmp::icmpv6_checksum(outer, &message).unwrap()
    } else {
        ntcp_icmp::checksum(&message)
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut frame = vec![0; 40 + message.len()];
    let n = if v6 {
        frame[40..].copy_from_slice(&message);
        let h = ntcp_ip6::Header {
            ip: outer,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_datagram(&mut frame, h, 58, message.len()).unwrap()
    } else {
        frame[20..20 + message.len()].copy_from_slice(&message);
        let h = ntcp_ip::Header {
            ip: outer,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        ntcp_ip::encode_datagram(&mut frame, h, 1, message.len(), 0).unwrap()
    };
    frame.truncate(n);
    frame
}

fn ptb(packet: &[u8], mtu: u32) -> Vec<u8> {
    report(
        packet,
        if packet[0] >> 4 == 6 { (2, 0) } else { (3, 4) },
        mtu,
    )
}

fn unreachable(packet: &[u8]) -> Vec<u8> {
    report(packet, if packet[0] >> 4 == 6 { (1, 3) } else { (3, 1) }, 0)
}

fn dispatch(a: &mut Side, now: u64, report: &[u8]) -> IcmpDispatch {
    let context = a.2;
    a.0.input_icmp(&mut a.1, context, MDL + now, report, None)
        .unwrap()
}

const UNCORRELATED: IcmpDispatch =
    IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated));

fn advice(owner: Option<Owner>, mtu: u32, dropped: &[u8], published: bool) -> IcmpDispatch {
    IcmpDispatch::Completed(IcmpOutcome::Advice {
        owner,
        advice: Advice::PacketTooBig {
            mtu: Some(mtu),
            dropped_len: dropped.len() as u32,
        },
        published: published.then_some(path::EstimateChange::Decreased),
    })
}

fn payload() -> Vec<u8> {
    (0..3500u32).map(|i| (i * 7 + 3) as u8).collect()
}

// Rewrite the IPv4 Identification or the IPv6 Fragment header's.
fn set_identification(packet: &mut [u8], value: u32) {
    if packet[0] >> 4 == 6 {
        packet[44..48].copy_from_slice(&value.to_be_bytes());
    } else {
        packet[4..6].copy_from_slice(&(value as u16).to_be_bytes());
        seal_ipv4(packet);
    }
}
// Move a fragment's offset by eight octets.
fn shift_offset(packet: &mut [u8]) {
    let at = if packet[0] >> 4 == 6 { 42 } else { 6 };
    let field = u16::from_be_bytes([packet[at], packet[at + 1]]) + 8;
    packet[at..at + 2].copy_from_slice(&field.to_be_bytes());
    seal_ipv4(packet);
}
fn data_at(packet: &[u8]) -> usize {
    if packet[0] >> 4 == 6 { 48 } else { 20 }
}

#[test]
fn first_and_later_fragment_ptbs_advise_their_owner_with_the_fragment_length() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9100 + u64::from(v6), 1);
        let flow = open(&mut a, 5000, remote);
        let (owner, sent) = send(&mut a, 1, flow, &payload());
        // A PTB for the first fragment: its UDP selector correlates.
        assert_eq!(
            dispatch(&mut a, 2, &ptb(&sent[0], 1400)),
            advice(Some(owner), 1400, &sent[0], true)
        );
        assert_eq!(
            a.0.udp_event(flow).unwrap(),
            Some(UdpEvent::PacketTooBig {
                remote,
                mtu: Some(1400),
                dropped_len: sent[0].len() as u32,
            })
        );
        // Near misses of the later fragment correlate with nothing: another
        // offset, a changed data octet, and (IPv4, eight octets quoted) a
        // quote missing a recorded data octet.
        let mut moved = sent[1].clone();
        shift_offset(&mut moved);
        assert_eq!(dispatch(&mut a, 3, &ptb(&moved, 1300)), UNCORRELATED);
        let mut changed = sent[1].clone();
        let at = data_at(&changed) + 5;
        changed[at] ^= 1;
        seal_ipv4(&mut changed);
        assert_eq!(dispatch(&mut a, 3, &ptb(&changed, 1300)), UNCORRELATED);
        if !v6 {
            let mut short = ptb(&sent[1], 1300);
            short.truncate(short.len() - 1);
            let total = (short.len() as u16).to_be_bytes();
            short[2..4].copy_from_slice(&total);
            seal_ipv4(&mut short);
            short[22..24].fill(0);
            let sum = ntcp_icmp::checksum(&short[20..]);
            short[22..24].copy_from_slice(&sum.to_be_bytes());
            assert!(!matches!(
                a.0.input_icmp(&mut a.1, a.2, MDL + 3, &short, None),
                Ok(IcmpDispatch::Completed(IcmpOutcome::Advice { .. }))
            ));
        }
        assert_eq!(a.0.udp_event(flow).unwrap(), None);
        // The Identification grants nothing and is not compared: the exact
        // later fragment under another Identification still correlates.
        let mut renumbered = sent[1].clone();
        set_identification(&mut renumbered, 0x1234);
        assert_eq!(
            dispatch(&mut a, 4, &ptb(&renumbered, 1300)),
            advice(Some(owner), 1300, &sent[1], true)
        );
        assert_eq!(
            a.0.udp_event(flow).unwrap(),
            Some(UdpEvent::PacketTooBig {
                remote,
                mtu: Some(1300),
                dropped_len: sent[1].len() as u32,
            })
        );
        // A network error about the last fragment reaches the owner too.
        assert_eq!(
            dispatch(&mut a, 5, &unreachable(&sent[2])),
            IcmpDispatch::Completed(IcmpOutcome::Advice {
                owner: Some(owner),
                advice: Advice::NetworkError(ntcp::NetworkError::SoftUnreachable),
                published: None,
            })
        );
    }
}

#[test]
fn aliased_later_fragments_allow_only_a_path_level_decrease() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9200 + u64::from(v6), 1);
        let first = open(&mut a, 5000, remote);
        let second = open(&mut a, 5001, remote);
        let (first_owner, one) = send(&mut a, 1, first, &payload());
        let (_, two) = send(&mut a, 2, second, &payload());
        // Later fragments of the two flows carry no ports and the same data:
        // only their Identification differs, which is never evidence.
        assert_ne!(one[1], two[1]);
        assert_eq!(one[1][data_at(&one[1])..], two[1][data_at(&two[1])..]);
        assert_eq!(
            dispatch(&mut a, 3, &ptb(&two[1], 1400)),
            advice(None, 1400, &two[1], true)
        );
        assert_eq!(a.0.udp_event(first).unwrap(), None);
        assert_eq!(a.0.udp_event(second).unwrap(), None);
        // Without a PTB there is no path-level action to take.
        assert_eq!(
            dispatch(&mut a, 4, &unreachable(&one[2])),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Ambiguous))
        );
        // First fragments differ in their ports: each is unique.
        assert_eq!(
            dispatch(&mut a, 5, &ptb(&one[0], 1300)),
            advice(Some(first_owner), 1300, &one[0], true)
        );
    }
}

#[test]
fn stale_and_evicted_fragment_history_keeps_its_ambiguity() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        // An exact evicted signature per flow: a closed flow's fragments stay
        // exact evidence without an owner.
        let mut a = side(local, 9300 + u64::from(v6), 1);
        let closed = open(&mut a, 5000, remote);
        let (_, sent) = send(&mut a, 1, closed, &payload());
        // Keep the path alive for path-level action.
        let _other = open(&mut a, 5001, remote);
        a.0.udp_close(closed).unwrap();
        assert!(matches!(
            dispatch(&mut a, 2, &ptb(&sent[1], 1400)),
            IcmpDispatch::Completed(IcmpOutcome::Advice { owner: None, .. })
        ));
        let horizon = a.0.ledger.limits().feedback_horizon;
        assert_eq!(
            dispatch(&mut a, 2 + horizon, &ptb(&sent[2], 1300)),
            UNCORRELATED,
            "expired history is no evidence"
        );

        // No exact signatures: a closed flow's later fragments fold into
        // the portless summary of their addresses, shared across flows.
        let mut b = side(local, 9400 + u64::from(v6), 0);
        let closed = open(&mut b, 5000, remote);
        let (_, old) = send(&mut b, 1, closed, &payload());
        let live = open(&mut b, 5001, remote);
        b.0.udp_close(closed).unwrap();
        // A summary alone proves nothing.
        assert_eq!(dispatch(&mut b, 2, &ptb(&old[1], 1400)), UNCORRELATED);
        let (live_owner, new) = send(&mut b, 3, live, &payload());
        let quote = ntcp_icmp::decode_icmp_quote(&ptb(&new[1], 1400)).unwrap();
        let fragment = quote.quoted.fragment.unwrap();
        let key = QuoteKey {
            source: quote.quoted.ip.source,
            destination: quote.quoted.ip.destination,
            header_len: u32::from(quote.quoted.ip_header_len),
            packet_len: quote.quoted.ip_packet_len,
            protocol: quote.quoted.protocol,
            transport: QuotedSelector::Fragment {
                offset: fragment.offset,
                more: fragment.more_fragments,
                prefix: FragmentPrefix::new(fragment.data()),
            },
        };
        let c = b.0.correlate(MDL + 4, &key);
        assert_eq!((c.matches, c.summarized), (1, true), "cross-flow alias");
        assert_eq!(c.owner, None);
        // The live flow's exact match agrees with the summary's path: only
        // the path may change, and the live owner gets no advice.
        assert_eq!(
            dispatch(&mut b, 4, &ptb(&new[1], 1400)),
            advice(None, 1400, &new[1], true)
        );
        assert_eq!(b.0.udp_event(live).unwrap(), None);
        // Its first fragment has ports on the wire, outside that summary.
        assert_eq!(
            dispatch(&mut b, 5, &ptb(&new[0], 1300)),
            advice(Some(live_owner), 1300, &new[0], true)
        );
    }
}

#[test]
fn fragment_quotes_never_reach_tcp() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 9500 + u64::from(v6), 1);
        let mut b = managed(remote, 9600 + u64::from(v6), cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        a.1.write(id, &[1; 1400]).unwrap();
        let (attempt, _, segment) = selected(&mut a.1, now + 1).unwrap();
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let submitted =
            a.0.submit(&mut a.1, now + 1, ticket, context, &segment, 0, |_| {
                BackendOutcome::Submitted
            })
            .unwrap();
        assert!(submitted == Submission::Submitted);
        let before = a.1.path_mtu_info(id).unwrap().unwrap().current_mtu;
        // The live TCP segment as a first fragment: IPv4 MF, or IPv6 behind
        // a Fragment header at offset zero with M set.
        let fragment = if v6 {
            let mut f = segment[..40].to_vec();
            f[6] = 44;
            let payload = u16::from_be_bytes([f[4], f[5]]) + 8;
            f[4..6].copy_from_slice(&payload.to_be_bytes());
            f.extend_from_slice(&[6, 0, 0, 1, 0, 0, 0, 9]);
            f.extend_from_slice(&segment[40..]);
            f
        } else {
            let mut f = segment.clone();
            f[6] |= 0x20;
            seal_ipv4(&mut f);
            f
        };
        let mtu = if v6 { 1280 } else { 1100 };
        let report = ptb(&fragment, mtu);
        let context = a.2;
        assert_eq!(
            a.0.input_icmp(&mut a.1, context, now + 2, &report, None).unwrap(),
            UNCORRELATED
        );
        assert_eq!(a.1.path_mtu_info(id).unwrap().unwrap().current_mtu, before);
        // A UDP fragment PTB on the same path is datagram advice, never a
        // TCP report: TCP only adopts the shared budget at its next service.
        let flow = open(&mut a, 5000, remote);
        let (owner, sent) = send(&mut a, now + 3, flow, &payload());
        assert_eq!(
            dispatch(&mut a, now + 4, &ptb(&sent[1], 1400)),
            advice(Some(owner), 1400, &sent[1], true)
        );
        assert_eq!(a.1.path_mtu_info(id).unwrap().unwrap().current_mtu, before);
    }
}
