// The ICMP Echo adjunct (RFC 4821 section 10.3): retained fragmentation
// demand, the section 7.3 search with convergence and restart, exact reply
// validation, silence that never decreases anything, probe PTBs as ordinary
// trusted decreases, publication only under PathService rules, bounded
// state, a seeded model of adjunct events, and the administrative search
// transition (hold, targeted probe, no reopening, policy revisions).
use super::*;
use std::boxed::Box;

type Side = (Host, Endpoint, IngressContext);

const S: u64 = 1_000_000;
// Identifiers start one MDL after the predecessor stopped at 0.
const MDL: u64 = 120 * S;
const TIMEOUT: u64 = 3 * S;

fn limits(paths: usize) -> DatagramLimits {
    DatagramLimits {
        max_fragments: 8,
        identifiers: IdentifierLimits {
            lifetime_seconds: 120,
            ipv4_tuples: 4,
            ipv6_leases: 512,
        },
        connectionless: ConnectionlessSizing::default(),
        peer_reassembly_ipv4: None,
        peer_reassembly_ipv6: None,
        adjunct: AdjunctLimits {
            paths,
            ..AdjunctLimits::default()
        },
    }
}

fn side(local: SocketAddr, identity: u128, paths: usize) -> Side {
    let mut side = managed_limited(local, identity, config(2), false, None, None, |p, mut l| {
        l.datagrams = limits(paths);
        let (p, l) = managed_udp_limits(
            p,
            l,
            UdpLimits {
                flows: 1,
                receive_datagrams: 1,
                max_payload: 4000,
                events: 1,
                evicted_signatures: 1,
                probe_receipts: 2,
            },
        )
        .unwrap();
        let (p, mut l) = managed_icmp_output_limits(
            p,
            l,
            IcmpOutputLimits {
                messages: 2,
                message_bytes: 4096,
                hop_limit: 64,
            },
        )
        .unwrap();
        l.reassembly = ReassemblyLimits {
            assemblies: 4,
            fragments: 600,
            buffered_bytes: 8192,
            ipv4_datagram: 4096,
            ipv6_datagram: 4136,
            ipv4_timeout_seconds: 60,
        };
        (p, l, 1)
    });
    let mut counter = 0x31u8;
    side.0.set_entropy(Box::new(move |out: &mut [u8]| {
        for b in out.iter_mut() {
            *b = counter;
            counter = counter.wrapping_mul(5).wrapping_add(7);
        }
        Ok(())
    }));
    side.0.start_identifiers(Continuity::QuietSince(0)).unwrap();
    side
}

fn fragment() -> UdpSend {
    UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    }
}

fn open(a: &mut Side, local: SocketAddr, remote: Option<SocketAddr>) -> UdpFlowId {
    a.0.udp_open(
        &a.1,
        local,
        remote,
        UdpOptions {
            dscp: 0,
            hop_limit: 64,
        },
    )
    .unwrap()
}

// A 3000-octet payload: always beyond E, so it is fragmented (demand).
fn send(a: &mut Side, now: u64, flow: UdpFlowId, remote: Option<SocketAddr>) -> Vec<Vec<u8>> {
    let payload = vec![0x6b; 3000];
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    let report =
        a.0.udp_send_datagram(
            &a.1,
            now,
            flow,
            remote,
            Some(fragment()),
            &payload,
            &mut packet,
            |_, b| {
                sent.push(b.to_vec());
                BackendOutcome::Submitted
            },
        )
        .unwrap();
    assert!(report.fragments > 1);
    sent
}

fn effective(a: &mut Side, flow: UdpFlowId) -> u32 {
    a.0.udp_datagram_limits(&a.1, flow, None, Some(fragment()))
        .unwrap()
        .effective_size
}

// The next physical packet of the ICMP output drain, if any.
fn drain(a: &mut Side, now: u64) -> Option<Vec<u8>> {
    let mut packet = vec![0; 8192];
    let mut frames = Vec::new();
    let outcome =
        a.0.icmp_output(now, &mut packet, |_, b| {
            frames.push(b.to_vec());
            BackendOutcome::Submitted
        })
        .unwrap()?;
    assert_eq!(outcome, BackendOutcome::Submitted);
    assert_eq!(frames.len(), 1, "a probe is one packet");
    frames.pop()
}

struct Probe {
    ip: IpMetadata,
    identifier: u16,
    sequence: u16,
    data: Vec<u8>,
    len: usize,
}

// Parse a probe: unfragmented, IPv4 with DF, an Echo Request.
fn probe(packet: &[u8]) -> Probe {
    let (ip, protocol, payload) = if packet[0] >> 4 == 4 {
        let p = ntcp_ip::parse_fragment(packet, false).unwrap();
        assert!(p.fragmentation.is_complete(), "never fragmented");
        assert!(p.fragmentation.dont_fragment, "IPv4 probes carry DF");
        (p.ip, p.protocol, p.payload)
    } else {
        let p = ntcp_ip6::parse_fragment(packet).unwrap();
        assert!(p.fragment.is_none(), "never fragmented");
        (p.ip, p.protocol, p.payload)
    };
    assert_eq!(protocol, if ip.source.is_ipv4() { 1 } else { 58 });
    let echo = ntcp_icmp::decode_echo(ip, payload).unwrap();
    assert_eq!(echo.kind, ntcp_icmp::EchoKind::Request);
    Probe {
        ip,
        identifier: echo.identifier,
        sequence: echo.sequence,
        data: echo.data.to_vec(),
        len: packet.len(),
    }
}

fn ip_packet(ip: IpMetadata, protocol: u8, message: &[u8]) -> Vec<u8> {
    let header = if ip.source.is_ipv4() { 20 } else { 40 };
    let mut packet = vec![0; header + message.len()];
    packet[header..].copy_from_slice(message);
    let n = if ip.source.is_ipv4() {
        let h = ntcp_ip::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        ntcp_ip::encode_datagram(&mut packet, h, protocol, message.len(), 0).unwrap()
    } else {
        let h = ntcp_ip6::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_datagram(&mut packet, h, protocol, message.len()).unwrap()
    };
    assert_eq!(n, packet.len());
    packet
}

// The peer's Echo Reply, optionally altered or from another source.
fn reply(p: &Probe, identifier: u16, data: &[u8], source: IpAddr) -> Vec<u8> {
    let ip = IpMetadata {
        source,
        destination: p.ip.source,
    };
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n = ntcp_icmp::encode_echo(
        ip,
        ntcp_icmp::EchoKind::Reply,
        identifier,
        p.sequence,
        &mut message,
        data.len(),
    )
    .unwrap();
    ip_packet(ip, if ip.source.is_ipv4() { 1 } else { 58 }, &message[..n])
}

fn exact(p: &Probe) -> Vec<u8> {
    reply(p, p.identifier, &p.data, p.ip.destination)
}

fn input(a: &mut Side, now: u64, frame: &[u8]) -> IcmpDispatch {
    let context = a.2;
    a.0.input_icmp(&mut a.1, context, now, frame).unwrap()
}

fn outcome(dispatch: IcmpDispatch) -> ProbeOutcome {
    match dispatch {
        IcmpDispatch::Completed(IcmpOutcome::Probe(outcome)) => outcome,
        other => panic!("not a probe outcome: {other:?}"),
    }
}

// A router PTB quoting `packet` (header plus eight octets for IPv4, as
// much as fits for IPv6).
fn ptb(packet: &[u8], mtu: u32) -> Vec<u8> {
    let v6 = packet[0] >> 4 == 6;
    let quote = &packet[..if v6 { packet.len().min(1232) } else { 28 }];
    let destination = if v6 {
        IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
    } else {
        IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap())
    };
    let outer = IpMetadata {
        source: if v6 { "2001:db8::fe" } else { "192.0.2.254" }
            .parse()
            .unwrap(),
        destination,
    };
    let mut message = vec![0; 8 + quote.len()];
    (message[0], message[1]) = if v6 { (2, 0) } else { (3, 4) };
    message[4..8].copy_from_slice(&mtu.to_be_bytes());
    message[8..].copy_from_slice(quote);
    let sum = if v6 {
        ntcp_icmp::icmpv6_checksum(outer, &message).unwrap()
    } else {
        ntcp_icmp::checksum(&message)
    };
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    ip_packet(outer, if v6 { 58 } else { 1 }, &message)
}

fn initial(v6: bool) -> u32 {
    if v6 { 1280 } else { 1024 }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-10.3
//= type=test
//= reason=IP fragmentation is a packetization layer under unmodified applications here (Host UDP Fragment mode, Echo Replies (the Echo service does not answer an IPv4 Echo Request carrying a source route until T14 delivers received option metadata to Host-originated replies)), and it relies on Path MTU sharing plus an adjunct: fragments are cut to E, bounded by the shared PathService ordinary budget, which correlated PTBs about fragments and probes lower for every client; the Host-owned ICMP Echo adjunct (crates/stacks/ntcp-host/src/adjunct.rs) probes each path with fragmentation demand using unfragmented Echo Requests (DF on IPv4) carrying an unpredictable identifier, sequence and data nonce, sized by an RFC 4821 section 7.3 search between E (exclusive) and min(first-hop MTU, largest fragmented datagram). Only an exact, timely Echo Reply to a definitely submitted probe raises the path's confirmed lower bound and, under a learned ceiling below it, is offered to PathService::confirm_delivery (NotLarger on an unlearned path); silence and other errors lower only the search's upper bound, and a correlated PTB for a probe is an ordinary trusted decrease. Echo is used despite the preference for forward-only methods because every host implements the responder, the Host verifies its own nonce, and an exact reply proves forward delivery of the unfragmented request; a reply reassembled from fragments proves the same, so the return path limits the result only where the responder cannot deliver its reply at all (the search then stops lower, which is safe). Host tests cover the converging search, silence, forged, stale, mismatched and reassembled replies, a PTB for a probe and publication only under PathService rules; the integration/rfc_host fragment case raises IPv4 E only after a real Echo Reply and draws a real router PTB for a probe above 1280, and adjunct-silence shows that unanswered probes lower nothing.
//# To support IP fragmentation as a Packetization Layer under an unmodified application, an implementation SHOULD rely on the Path MTU sharing described in Section 5.2 plus an adjunct protocol to probe the Path MTU. There are a number of protocols that might be used for the purpose, such as ICMP ECHO and ECHO REPLY, or "traceroute" style UDP datagrams that trigger ICMP messages. Use of ICMP ECHO and ECHO REPLY will probe both forward and return paths, so the sender will only be able to take advantage of the minimum of the two. Other methods that probe only the forward path are preferred if available.
fn retained_demand_drives_a_converging_search_that_raises_e_only_on_replies() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 401, 2);
        let flow = open(&mut a, local, Some(remote));
        assert!(!a.0.adjunct_due(MDL));
        // One fragmented datagram is demand; it is retained without any
        // further send.
        let t0 = MDL + 1;
        let sent = send(&mut a, t0, flow, None);
        let lens: Vec<usize> = sent.iter().map(Vec::len).collect();
        assert_eq!(lens[0], if v6 { 1280 } else { 1020 });
        assert_eq!(a.0.next_adjunct_deadline(), Some(t0));
        assert!(a.0.adjunct_due(t0));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        // RFC 4821 7.3 halving between E (exclusive) and min(first hop,
        // largest fragmented datagram) (inclusive), with integer progress.
        let mut now = t0;
        let mut sizes = Vec::new();
        while let Some(packet) = drain(&mut a, now) {
            let p = probe(&packet);
            assert_eq!(p.ip.source, local.ip());
            assert_eq!(p.ip.destination, remote.ip());
            assert!(p.data.len() >= 16, "a 16-octet nonce at least");
            // At most one outstanding probe per path.
            assert_eq!(a.0.adjunct_outstanding(), 1);
            assert_eq!(drain(&mut a, now), None);
            let before = effective(&mut a, flow);
            assert!(p.len as u32 > before && p.len <= 1500);
            sizes.push(p.len);
            now += S / 10;
            match outcome(input(&mut a, now, &exact(&p))) {
                ProbeOutcome::Confirmed { size, published } => {
                    assert_eq!(size as usize, p.len);
                    // No learned ceiling: nothing to publish, nothing made up.
                    assert_eq!(published, Some(path::DeliveryConfirmation::NotLarger));
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(effective(&mut a, flow), p.len as u32);
            assert_eq!(a.0.adjunct_confirmed(path), p.len as u32);
        }
        let expected: &[usize] = if v6 {
            &[1390, 1445, 1473, 1487, 1494]
        } else {
            &[1262, 1381, 1441, 1471, 1486, 1493]
        };
        assert_eq!(sizes, expected);
        assert_eq!(a.0.adjunct_counters().converged, 1);
        assert_eq!(a.0.adjunct_counters().confirmed, sizes.len() as u64);
        assert!(
            !a.0.adjunct_due(now + 3600 * S),
            "no demand since convergence"
        );
        // The shared path never learned anything from the adjunct.
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        // Later sends use the confirmed size: IPv4 fragments of 1493
        // carry 1472 data octets.
        let sent = send(&mut a, now, flow, None);
        assert_eq!(sent[0].len(), if v6 { 1488 } else { 1492 });
    }
}

#[test]
fn silence_lowers_only_the_search_and_restart_waits_the_interval() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 402, 1);
        let flow = open(&mut a, local, Some(remote));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        send(&mut a, MDL, flow, None);
        let mut now = MDL;
        let mut sizes = Vec::new();
        loop {
            let Some(packet) = drain(&mut a, now) else {
                // Waiting for the reply deadline, or converged.
                match a.0.next_adjunct_deadline() {
                    Some(at) if at > now => {
                        // Nothing is due before the local retry deadline.
                        assert!(!a.0.adjunct_due(at - 1));
                        now = at;
                        continue;
                    }
                    _ => break,
                }
            };
            sizes.push(probe(&packet).len);
            // Silence never decreases E or anything shared.
            assert_eq!(effective(&mut a, flow), initial(v6));
            assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
            if sizes.len() > 20 {
                panic!("search does not converge: {sizes:?}");
            }
        }
        // Each lost probe set search_high to its size minus one.
        assert!(sizes.windows(2).all(|w| w[1] < w[0]), "{sizes:?}");
        assert!(*sizes.last().unwrap() < initial(v6) as usize + 8 * 2);
        let counters = a.0.adjunct_counters();
        assert_eq!(counters.lost, sizes.len() as u64);
        assert_eq!(counters.converged, 1);
        assert_eq!(effective(&mut a, flow), initial(v6));
        // A converged search restarts no sooner than RFC 4821 7.3's timer,
        // and only for demand that arrived after convergence.
        let converged = now;
        assert!(!a.0.adjunct_due(converged + 601 * S));
        send(&mut a, converged + 10 * S, flow, None);
        assert_eq!(a.0.next_adjunct_deadline(), Some(converged + 600 * S));
        assert!(!a.0.adjunct_due(converged + 600 * S - 1));
        assert_eq!(drain(&mut a, converged + 600 * S - 1), None);
        let restarted = probe(&drain(&mut a, converged + 600 * S).unwrap());
        assert_eq!(
            restarted.len, sizes[0],
            "search_high reset to its initial value"
        );
    }
}

#[test]
fn only_an_exact_timely_reply_to_a_definite_probe_certifies_delivery() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 403, 1);
        let flow = open(&mut a, local, Some(remote));
        send(&mut a, MDL, flow, None);
        let now = MDL + 1;
        let p = probe(&drain(&mut a, now).unwrap());
        let other: IpAddr = if v6 { "2001:db8::9" } else { "192.0.2.9" }
            .parse()
            .unwrap();
        let mut altered = p.data.clone();
        *altered.last_mut().unwrap() ^= 1;
        let mut short = p.data.clone();
        short.pop();
        for forged in [
            reply(&p, p.identifier ^ 1, &p.data, remote.ip()),
            reply(&p, p.identifier, &altered, remote.ip()),
            reply(&p, p.identifier, &short, remote.ip()),
            reply(&p, p.identifier, &p.data, other),
        ] {
            assert_eq!(
                outcome(input(&mut a, now, &forged)),
                ProbeOutcome::Unmatched
            );
            // The real probe stays outstanding.
            assert_eq!(a.0.adjunct_outstanding(), 1);
        }
        assert_eq!(a.0.adjunct_counters().unmatched_replies, 4);
        assert_eq!(effective(&mut a, flow), initial(v6));
        // A reply at the deadline is stale.
        assert_eq!(
            outcome(input(&mut a, now + TIMEOUT, &exact(&p))),
            ProbeOutcome::Unmatched
        );
        // The next probe (smaller after the loss) answered by a reply that
        // was fragmented on its way back still proves forward delivery.
        let later = now + TIMEOUT + 1;
        let q = probe(&drain(&mut a, later).unwrap());
        assert!(q.len < p.len);
        let whole = exact(&q);
        let pieces = fragment_packet(&whole, 600);
        assert!(pieces.len() > 1);
        let mut result = None;
        for piece in &pieces {
            let context = a.2;
            result = Some(a.0.input_ip(
                &mut a.1,
                context,
                later + 1,
                piece,
                RxPacketMetadata::default(),
                0,
                None,
            ));
        }
        assert_eq!(result.unwrap(), Ok(ntcp::InputDisposition::Processed));
        assert_eq!(a.0.adjunct_counters().confirmed, 1);
        assert_eq!(effective(&mut a, flow), q.len as u32);
        // A duplicate of the accepted reply matches nothing any more.
        assert_eq!(
            outcome(input(&mut a, later + 2, &whole)),
            ProbeOutcome::Unmatched
        );

        // A probe whose submission was uncertain is not certified.
        let mut b = side(local, 404, 1);
        let flow = open(&mut b, local, Some(remote));
        send(&mut b, MDL, flow, None);
        let mut packet = vec![0; 8192];
        let mut frame = None;
        let o =
            b.0.icmp_output(MDL + 1, &mut packet, |_, bytes| {
                frame = Some(bytes.to_vec());
                BackendOutcome::Unknown
            })
            .unwrap();
        assert_eq!(o, Some(BackendOutcome::Unknown));
        let u = probe(&frame.unwrap());
        assert_eq!(
            outcome(input(&mut b, MDL + 2, &exact(&u))),
            ProbeOutcome::Unmatched
        );
        assert_eq!(effective(&mut b, flow), initial(v6));
    }
}

// Fragments of a complete option-free datagram, `chunk` data octets each.
fn fragment_packet(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let v6 = packet[0] >> 4 == 6;
    let (ip, protocol, data) = if v6 {
        let p = ntcp_ip6::parse(packet).unwrap();
        (p.ip, p.protocol, p.payload.to_vec())
    } else {
        let p = ntcp_ip::parse(packet, false).unwrap();
        (p.ip, p.protocol, p.payload.to_vec())
    };
    let mut out = Vec::new();
    for offset in (0..data.len()).step_by(chunk) {
        let piece = &data[offset..data.len().min(offset + chunk)];
        let mut buffer = vec![0; 128 + piece.len()];
        let n = if v6 {
            let h = ntcp_ip6::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::Fragmenter::new(h, protocol, 77, data.len())
                .unwrap()
                .encode(&mut buffer, offset, piece)
                .unwrap()
        } else {
            let h = ntcp_ip::Header {
                ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::Fragmenter::new(h, protocol, 77, data.len(), 0)
                .unwrap()
                .encode(&mut buffer, offset, piece)
                .unwrap()
        };
        buffer.truncate(n);
        out.push(buffer);
    }
    out
}

#[test]
fn a_ptb_for_a_probe_is_an_ordinary_trusted_decrease() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 405, 1);
        let flow = open(&mut a, local, Some(remote));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        send(&mut a, MDL, flow, None);
        let now = MDL + 1;
        let packet = drain(&mut a, now).unwrap();
        let p = probe(&packet);
        let mtu = if v6 { 1350 } else { 1200 };
        // A PTB quoting another Echo Request is not about the probe.
        let mut foreign = packet.clone();
        let at = if v6 { 40 + 4 } else { 20 + 4 };
        foreign[at] ^= 0xff;
        assert_eq!(
            input(&mut a, now, &ptb(&foreign, mtu)),
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated))
        );
        assert_eq!(
            outcome(input(&mut a, now + 1, &ptb(&packet, mtu))),
            ProbeOutcome::TooBig {
                size: p.len as u32,
                mtu: Some(mtu),
                published: Some(path::EstimateChange::Decreased),
            }
        );
        let snapshot = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(snapshot.learned_mtu(), Some(mtu));
        assert_eq!(a.0.adjunct_counters().too_big, 1);
        // The search continues below the reported MTU after the hold.
        assert!(!a.0.adjunct_due(now + 2));
        let hold = snapshot.retry_not_before();
        assert_eq!(a.0.next_adjunct_deadline(), Some(hold));
        let q = probe(&drain(&mut a, hold).unwrap());
        assert!(
            q.len as u32 > initial(v6) && q.len as u32 <= mtu,
            "{}",
            q.len
        );
    }
}

#[test]
fn delivery_is_published_only_under_path_service_rules() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 406, 1);
        let flow = open(&mut a, local, Some(remote));
        // A learned 1280 ceiling, held for 600 seconds from 0.
        let snapshot = learn(&mut a.0, local, remote, 0, 1280);
        let hold = snapshot.retry_not_before();
        assert!(hold > MDL);
        send(&mut a, MDL, flow, None);
        // Demand waits for the hold, with no further sends.
        assert!(!a.0.adjunct_due(hold - 1));
        assert_eq!(a.0.next_adjunct_deadline(), Some(hold));
        assert_eq!(drain(&mut a, hold - 1), None);
        let mut now = hold;
        let mut published = Vec::new();
        while let Some(packet) = drain(&mut a, now) {
            let p = probe(&packet);
            now += 1;
            let ProbeOutcome::Confirmed { size, published: r } =
                outcome(input(&mut a, now, &exact(&p)))
            else {
                panic!()
            };
            published.push((size, r.unwrap()));
        }
        let learned =
            a.0.paths()
                .path_snapshot(snapshot.path())
                .unwrap()
                .learned_mtu();
        // A confirmed size within the learned ceiling is NotLarger; the
        // first larger one is Raised and every later one again.
        for (size, r) in &published {
            assert_eq!(
                *r,
                if *size <= 1280 {
                    path::DeliveryConfirmation::NotLarger
                } else {
                    path::DeliveryConfirmation::Raised
                },
                "{published:?}"
            );
        }
        assert!(published.iter().any(|(s, _)| *s > 1280));
        assert_eq!(learned, published.iter().map(|(s, _)| *s).max());
        // Under the learned 1280 ceiling before any raise, IPv4 confirmed
        // at least 1276: fragments become 1276-octet packets (D13).
    }
}

#[test]
fn ipv4_fragments_grow_to_1276_under_a_learned_1280_ceiling() {
    let (local, remote) = addresses(false);
    let mut a = side(local, 407, 1);
    let flow = open(&mut a, local, Some(remote));
    let snapshot = learn(&mut a.0, local, remote, 0, 1280);
    let hold = snapshot.retry_not_before();
    send(&mut a, MDL, flow, None);
    let mut now = hold;
    // The peer answers probes up to 1280; a router drops larger ones with
    // a 1280 PTB.
    while let Some(packet) = drain(&mut a, now) {
        let p = probe(&packet);
        now += 1;
        if p.len <= 1280 {
            input(&mut a, now, &exact(&p));
        } else {
            input(&mut a, now, &ptb(&packet, 1280));
            now = now.max(
                a.0.paths()
                    .path_snapshot(snapshot.path())
                    .unwrap()
                    .retry_not_before(),
            );
        }
    }
    assert!(effective(&mut a, flow) >= 1276);
    let sent = send(&mut a, now, flow, None);
    assert_eq!(sent[0].len(), 1276);
    assert_eq!(
        a.0.paths()
            .path_snapshot(snapshot.path())
            .unwrap()
            .learned_mtu(),
        Some(1280)
    );
}

#[test]
fn adjunct_state_is_bounded() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let second: SocketAddr = if v6 {
            "[2001:db8::3]:8080"
        } else {
            "192.0.2.3:8080"
        }
        .parse()
        .unwrap();
        let mut a = side(local, 408, 1);
        let flow = open(&mut a, local, None);
        send(&mut a, MDL, flow, Some(remote));
        let p = probe(&drain(&mut a, MDL).unwrap());
        assert_eq!(p.ip.destination, remote.ip());
        // The only entry has a probe outstanding: new demand is dropped.
        send(&mut a, MDL + 1, flow, Some(second));
        assert_eq!(a.0.adjunct_counters().demand_dropped, 1);
        assert_eq!(a.0.adjunct_paths(), 1);
        assert_eq!(drain(&mut a, MDL + 1), None);
        // Once it is answered, the least recently used entry is replaced.
        input(&mut a, MDL + 2, &exact(&p));
        send(&mut a, MDL + 3, flow, Some(second));
        assert_eq!(a.0.adjunct_paths(), 1);
        let q = probe(&drain(&mut a, MDL + 3).unwrap());
        assert_eq!(q.ip.destination, second.ip());
        // The adjunct needs the ICMP output drain.
        let (paths, mut l) = managed_limits(&config(2), 1, 1, 1, 4, 1).unwrap();
        l.datagrams = limits(1);
        assert!(matches!(
            Host::new(ContextId::new(9), paths, l, config(2).connection.timebase),
            Err(Error::Capacity)
        ));
        // RFC 4821 7.3: the restart timer is at least 5 minutes.
        l.datagrams.adjunct.restart_seconds = 299;
        assert_eq!(l.datagrams.validate(), Err(Error::Capacity));
    }
}

#[test]
fn entropy_failure_sends_no_probe() {
    let (local, remote) = addresses(false);
    let mut a = side(local, 409, 1);
    let flow = open(&mut a, local, Some(remote));
    send(&mut a, MDL, flow, None);
    a.0.set_entropy(Box::new(|_: &mut [u8]| Err(EntropyError)));
    let mut packet = vec![0; 8192];
    let mut sent = 0;
    let o = a.0.icmp_output(MDL, &mut packet, |_, _| {
        sent += 1;
        BackendOutcome::Submitted
    });
    assert_eq!(o, Ok(Some(BackendOutcome::NotSubmitted)));
    assert_eq!(sent, 0);
    assert_eq!(a.0.adjunct_counters().not_sent, 1);
    // Retried at the local retry deadline.
    assert_eq!(a.0.next_adjunct_deadline(), Some(MDL + TIMEOUT));
}

// Seeded model: random sends, exact/forged/late replies, silence, PTBs and
// time. Invariants: at most one outstanding probe; every probe unfragmented,
// above E and within the first hop; E and the confirmed bound never fall
// except through a shared decrease from a PTB; silence and forged replies
// change nothing shared.
#[test]
fn seeded_model_of_adjunct_events() {
    let mut coverage = [0u32; 6];
    for v6 in [false, true] {
        for seed in 1..=12u64 {
            let (local, remote) = addresses(v6);
            let mut a = side(local, 500 + seed as u128, 1);
            let flow = open(&mut a, local, Some(remote));
            let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
            let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let mut now = MDL;
            let mut outstanding: Option<(Vec<u8>, Probe)> = None;
            let mut last_e = effective(&mut a, flow);
            for _ in 0..60 {
                let learned = a.0.paths().path_snapshot(path).unwrap().learned_mtu();
                match next() % 6 {
                    0 => {
                        send(&mut a, now, flow, None);
                        coverage[0] += 1;
                    }
                    1 => {
                        if let Some(packet) = drain(&mut a, now) {
                            let p = probe(&packet);
                            assert!(p.len as u32 > effective(&mut a, flow));
                            assert!(p.len <= 1500);
                            assert_eq!(a.0.adjunct_outstanding(), 1);
                            outstanding = Some((packet, p));
                            coverage[1] += 1;
                        }
                    }
                    2 => {
                        if let Some((_, p)) = outstanding.take() {
                            input(&mut a, now, &exact(&p));
                            coverage[2] += 1;
                        }
                    }
                    3 => {
                        if let Some((_, p)) = &outstanding {
                            let forged =
                                reply(p, p.identifier.wrapping_add(1), &p.data, remote.ip());
                            assert_eq!(
                                outcome(input(&mut a, now, &forged)),
                                ProbeOutcome::Unmatched
                            );
                            coverage[3] += 1;
                        }
                    }
                    4 => {
                        if let Some((packet, p)) = outstanding.take() {
                            let mtu = ((p.len as u32 + initial(v6)) / 2).max(initial(v6));
                            if mtu < p.len as u32 {
                                input(&mut a, now, &ptb(&packet, mtu));
                                coverage[4] += 1;
                            }
                        }
                    }
                    _ => {
                        // Silence past the reply deadline.
                        now += TIMEOUT + next() % (2 * TIMEOUT);
                        a.0.service_changes(&mut a.1, now).unwrap();
                        outstanding = None;
                        coverage[5] += 1;
                    }
                }
                now += 1 + next() % 1000;
                assert!(a.0.adjunct_outstanding() <= 1);
                let e = effective(&mut a, flow);
                let learned_now = a.0.paths().path_snapshot(path).unwrap().learned_mtu();
                if e < last_e {
                    assert!(
                        learned_now.is_some() && learned_now < learned.or(Some(u32::MAX)),
                        "E fell without a shared decrease"
                    );
                }
                assert!(e >= initial(v6).min(learned_now.unwrap_or(u32::MAX)));
                last_e = e;
            }
        }
    }
    assert!(coverage.iter().all(|c| *c > 0), "{coverage:?}");
}

// ---- Administrative search transition (caller time, real Echo Replies) ----

const UP: u32 = 1450;
// The learned ceiling a trusted decrease at time 0 installs, held 600 s.
const LEARNED: u32 = 1300;

fn adjunct_report(a: &Side, capability: &Administration, path: path::PathId) -> ClientReport {
    let reports: Vec<_> =
        a.0.admin_clients(capability, &a.1, path)
            .unwrap()
            .filter(|c| c.client == AdminClient::Adjunct)
            .collect();
    assert_eq!(reports.len(), 1);
    reports[0]
}

// A flow with fragmentation demand on a path whose learned ceiling is
// LEARNED, held until the returned instant.
fn learned_side(v6: bool, identity: u128) -> (Side, UdpFlowId, path::PathId, u64) {
    let (local, remote) = addresses(v6);
    let mut a = side(local, identity, 1);
    let flow = open(&mut a, local, Some(remote));
    let snapshot = learn(&mut a.0, local, remote, 0, LEARNED);
    let hold = snapshot.retry_not_before();
    assert!(hold > MDL + 10);
    send(&mut a, MDL, flow, None);
    (a, flow, snapshot.path(), hold)
}

// An upward administrative set inside the hold is cached only: no shared,
// E or confirmed change, no probe, and the adjunct reports the hold as the
// deferral. After the hold the first probe is the value itself (not the
// midpoint); only its exact reply raises E and, through confirm_delivery,
// the accepted estimate, to that value and no further even though the
// responder answers every size.
#[test]
fn upward_set_waits_for_the_hold_then_one_adjunct_probe_targets_the_value() {
    use ntcp::{AdministrativeDeferral, AdministrativeSearch};
    for v6 in [false, true] {
        let (mut a, flow, path, hold) = learned_side(v6, 430 + u128::from(v6));
        let capability = a.0.administration();
        let e0 = effective(&mut a, flow);
        assert_eq!(e0, initial(v6));
        let before = a.0.paths().path_snapshot(path).unwrap();
        super::admin::set_estimate(&mut a, &capability, MDL + 1, path, Some(UP)).unwrap();
        a.0.service_changes(&mut a.1, MDL + 1).unwrap();
        let after = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(after.administrative_estimate(), Some(UP));
        assert_eq!(
            (after.learned_mtu(), after.retry_not_before(), after.negative_revision()),
            (Some(LEARNED), hold, before.negative_revision())
        );
        assert_eq!(effective(&mut a, flow), e0);
        assert_eq!(a.0.adjunct_confirmed(path), 0);
        // Inside the hold: fragments stay at E and nothing is probed.
        let sent = send(&mut a, MDL + 2, flow, None);
        assert!(sent.iter().all(|f| f.len() as u32 <= e0));
        assert!(!a.0.adjunct_due(hold - 1));
        assert_eq!(a.0.next_adjunct_deadline(), Some(hold));
        assert_eq!(drain(&mut a, hold - 1), None);
        a.0.service_changes(&mut a.1, hold - 1).unwrap();
        let report = adjunct_report(&a, &capability, path);
        assert_eq!(report.usable_ip_packet, Some(e0));
        assert_eq!(
            report.search,
            Some(AdministrativeSearch::Pending {
                target: UP,
                deferred: Some(AdministrativeDeferral::Hold)
            })
        );

        // After the hold: the value, not the midpoint of (E, UP].
        let p = probe(&drain(&mut a, hold).unwrap());
        assert_eq!(p.len as u32, UP, "v6={v6}");
        assert_eq!(
            adjunct_report(&a, &capability, path).search,
            Some(AdministrativeSearch::Attempted {
                target: UP,
                size: UP,
                clipped: None
            })
        );
        // Submission proves nothing.
        assert_eq!(effective(&mut a, flow), e0);
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(LEARNED)
        );
        assert_eq!(
            outcome(input(&mut a, hold + 1, &exact(&p))),
            ProbeOutcome::Confirmed {
                size: UP,
                published: Some(path::DeliveryConfirmation::Raised)
            }
        );
        assert_eq!(a.0.adjunct_confirmed(path), UP);
        assert_eq!(effective(&mut a, flow), UP);
        let admin = a.0.admin_path(&capability, path).unwrap();
        assert_eq!(admin.accepted.unwrap().value, UP);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(UP));

        // No further: the value caps the search, which converges.
        let mut now = hold + 2;
        while let Some(packet) = drain(&mut a, now) {
            let p = probe(&packet);
            assert!(p.len as u32 <= UP);
            now += 1;
            input(&mut a, now, &exact(&p));
        }
        assert_eq!(a.0.adjunct_counters().converged, 1);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), Some(UP));
        assert_eq!(effective(&mut a, flow), UP);
        let sent = send(&mut a, now, flow, None);
        assert!(sent.iter().all(|f| f.len() as u32 <= UP));
    }
}

// A path delivering up to 1400 octets: the targeted probe at UP is lost.
// Its failure lowers the search's upper bound only; a re-armed value (clear
// then set again, two administrative revisions) is clipped by that negative
// evidence, so no probe reaches UP again and growth stops at what replies
// prove. After convergence a further revision waits for fresh demand and
// the restart interval, reported as the deferral.
#[test]
fn failed_targeted_adjunct_probe_does_not_reopen_the_search() {
    use ntcp::{AdministrativeClip, AdministrativeDeferral, AdministrativeSearch};
    const PMTU: u32 = 1400;
    for v6 in [false, true] {
        let (mut a, flow, path, hold) = learned_side(v6, 440 + u128::from(v6));
        let capability = a.0.administration();
        let e0 = effective(&mut a, flow);
        super::admin::set_estimate(&mut a, &capability, MDL + 1, path, Some(UP)).unwrap();
        a.0.service_changes(&mut a.1, MDL + 1).unwrap();
        let p = probe(&drain(&mut a, hold).unwrap());
        assert_eq!(p.len as u32, UP);
        // Silence past the reply deadline.
        let mut now = hold + TIMEOUT;
        a.0.service_changes(&mut a.1, now).unwrap();
        assert_eq!(a.0.adjunct_counters().lost, 1);
        assert_eq!(effective(&mut a, flow), e0);
        assert_eq!(a.0.adjunct_confirmed(path), 0);
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(LEARNED)
        );
        let revise = |a: &mut Side, now: u64| {
            for value in [None, Some(UP)] {
                super::admin::set_estimate(a, &capability, now, path, value).unwrap();
                a.0.service_changes(&mut a.1, now).unwrap();
            }
        };
        revise(&mut a, now);
        assert_eq!(
            adjunct_report(&a, &capability, path).search,
            Some(AdministrativeSearch::Pending {
                target: UP,
                deferred: None
            })
        );
        let mut sizes = Vec::new();
        while let Some(packet) = drain(&mut a, now) {
            let p = probe(&packet);
            if sizes.is_empty() {
                // The re-armed target, clipped by the failure.
                assert_eq!(p.len as u32, UP - 1);
                assert_eq!(
                    adjunct_report(&a, &capability, path).search,
                    Some(AdministrativeSearch::Attempted {
                        target: UP,
                        size: UP - 1,
                        clipped: Some(AdministrativeClip::SearchHigh)
                    })
                );
            }
            sizes.push(p.len as u32);
            if p.len as u32 <= PMTU {
                now += 1;
                input(&mut a, now, &exact(&p));
            } else {
                now += TIMEOUT;
                a.0.service_changes(&mut a.1, now).unwrap();
            }
            assert!(sizes.len() < 20, "{sizes:?}");
        }
        assert!(sizes.iter().all(|s| *s < UP), "{sizes:?}");
        let confirmed = a.0.adjunct_confirmed(path);
        assert!(confirmed > LEARNED && confirmed <= PMTU, "{sizes:?}");
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(confirmed)
        );
        assert_eq!(a.0.adjunct_counters().converged, 1);

        // Converged: another revision reopens nothing; it waits for demand
        // and then for the restart interval.
        let converged = now;
        revise(&mut a, now);
        assert_eq!(drain(&mut a, now), None);
        assert_eq!(
            adjunct_report(&a, &capability, path).search,
            Some(AdministrativeSearch::Pending {
                target: UP,
                deferred: Some(AdministrativeDeferral::DataOrWindow)
            })
        );
        send(&mut a, now + 1, flow, None);
        a.0.service_changes(&mut a.1, now + 2).unwrap();
        assert_eq!(
            adjunct_report(&a, &capability, path).search,
            Some(AdministrativeSearch::Pending {
                target: UP,
                deferred: Some(AdministrativeDeferral::Cooldown)
            })
        );
        assert!(!a.0.adjunct_due(converged + 600 * S - 1));
        assert_eq!(a.0.next_adjunct_deadline(), Some(converged + 600 * S));
        assert_eq!(
            a.0.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(confirmed)
        );
    }
}

// A reply to a probe submitted before a discovery-policy transition (a
// disable and re-enable of the path) proves no size: the disable made the
// probe ineligible in the same administration transaction, so its exact
// reply settles it as Unmatched (a re-enable does not revive it).
#[test]
fn reply_across_a_discovery_policy_revision_proves_no_size() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 450 + u128::from(v6), 1);
        let flow = open(&mut a, local, Some(remote));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        let capability = a.0.administration();
        send(&mut a, MDL, flow, None);
        let p = probe(&drain(&mut a, MDL).unwrap());
        let revision = a.0.paths().path_snapshot(path).unwrap().discovery_revision();
        for disabled in [true, false] {
            let expected = a.0.admin_path(&capability, path).unwrap().generation;
            let candidate =
                a.0.admin_validate(
                    &capability,
                    MDL + 1,
                    path::AdminChange {
                        target: path::AdminTarget::Path(path),
                        expected,
                        policy: path::AdminPolicy {
                            discovery_disabled: disabled,
                            estimate: None,
                        },
                    },
                )
                .unwrap();
            a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        }
        assert!(a.0.paths().path_snapshot(path).unwrap().discovery_revision() > revision);
        let e0 = effective(&mut a, flow);
        // The Echo service and the adjunct are clients of the path.
        let clients: Vec<_> = a
            .0
            .admin_clients(&capability, &a.1, path)
            .unwrap()
            .map(|c| c.client)
            .collect();
        assert!(clients.contains(&crate::AdminClient::Adjunct));
        assert!(clients.contains(&crate::AdminClient::Echo { queued: 0 }));
        // The disable voided the outstanding probe's size result without
        // loss evidence, so its late reply proves nothing.
        assert_eq!(outcome(input(&mut a, MDL + 2, &exact(&p))), ProbeOutcome::Unmatched);
        assert_eq!(a.0.adjunct_confirmed(path), 0);
        assert_eq!(effective(&mut a, flow), e0);
        assert_eq!(a.0.adjunct_counters().confirmed, 0);
        // The search probes again under the current policy.
        assert_eq!(a.0.adjunct_outstanding(), 0);
        assert!(a.0.adjunct_due(MDL + 2));
    }
}

// A validated PTB quoting a probe definitely submitted before a discovery
// disable is still correlated under the existing rules (RFC 1191 6.6 /
// RFC 8201 5.6 stop new probing, not the processing of reports about
// earlier submissions): it is the ordinary trusted shared decrease, while
// the probe's search result stays void, and no probe leaves while the
// disable holds.
#[test]
fn ptb_for_a_probe_sent_before_a_disable_still_lowers_the_shared_estimate() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 455 + u128::from(v6), 1);
        let flow = open(&mut a, local, Some(remote));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        let capability = a.0.administration();
        send(&mut a, MDL, flow, None);
        let packet = drain(&mut a, MDL).unwrap();
        let p = probe(&packet);
        let expected = a.0.admin_path(&capability, path).unwrap().generation;
        let candidate = a
            .0
            .admin_validate(
                &capability,
                MDL + 1,
                path::AdminChange {
                    target: path::AdminTarget::Path(path),
                    expected,
                    policy: path::AdminPolicy {
                        discovery_disabled: true,
                        estimate: None,
                    },
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        let mtu = if v6 { 1350 } else { 1200 };
        assert_eq!(
            outcome(input(&mut a, MDL + 2, &ptb(&packet, mtu))),
            ProbeOutcome::TooBig {
                size: p.len as u32,
                mtu: Some(mtu),
                published: Some(path::EstimateChange::Decreased),
            }
        );
        let snapshot = a.0.paths().path_snapshot(path).unwrap();
        assert_eq!(snapshot.learned_mtu(), Some(mtu));
        assert!(snapshot.discovery_disabled());
        assert_eq!(a.0.adjunct_counters().too_big, 1);
        assert_eq!(a.0.adjunct_outstanding(), 0);
        assert_eq!(a.0.adjunct_confirmed(path), 0);
        // Disabled: nothing is due, even after the hold.
        let hold = snapshot.retry_not_before();
        assert!(!a.0.adjunct_due(hold));
        assert_eq!(drain(&mut a, hold), None);
    }
}

// RFC 1191 6.6 / RFC 8201 5.6: on a path whose owner disabled discovery the
// adjunct sends nothing (no probe is due, the drain sends none) while
// fragmentation demand is still recorded; its administrative state reports
// the disable; enabling again makes the search due.
#[test]
fn discovery_disable_stops_the_adjunct() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 470 + u128::from(v6), 1);
        let flow = open(&mut a, local, Some(remote));
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        let capability = a.0.administration();
        let set = |a: &mut Side, disabled: bool| {
            let expected = a.0.admin_path(&capability, path).unwrap().generation;
            let candidate = a
                .0
                .admin_validate(
                    &capability,
                    MDL,
                    path::AdminChange {
                        target: path::AdminTarget::Path(path),
                        expected,
                        policy: path::AdminPolicy {
                            discovery_disabled: disabled,
                            estimate: None,
                        },
                    },
                )
                .unwrap();
            a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        };
        set(&mut a, true);
        send(&mut a, MDL, flow, None);
        assert!(!a.0.adjunct_due(MDL));
        assert_eq!(drain(&mut a, MDL), None);
        assert_eq!(drain(&mut a, MDL + 10_000_000), None);
        assert_eq!(a.0.adjunct_outstanding(), 0);
        assert_eq!(a.0.adjunct_confirmed(path), 0);
        set(&mut a, false);
        assert!(a.0.adjunct_due(MDL + 10_000_000));
        assert!(drain(&mut a, MDL + 10_000_000).is_some());
    }
}
