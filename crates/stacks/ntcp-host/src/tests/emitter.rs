// The Host datagram emitter: send modes, the peer guarantee, source
// fragments on the wire, identifier leases and partial submissions, and
// Echo Replies through the same transaction.
use super::*;
use std::boxed::Box;
use std::sync::{Arc, Mutex};

type Side = (Host, Endpoint, IngressContext);

const UDP: UdpLimits = UdpLimits {
    flows: 1,
    receive_datagrams: 1,
    max_payload: 4000,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};

fn datagrams(ipv4_initial: u32) -> DatagramLimits {
    DatagramLimits {
        max_fragments: 8,
        identifiers: IdentifierLimits {
            lifetime_seconds: 120,
            ipv4_tuples: 2,
            ipv6_leases: 16,
        },
        connectionless: ConnectionlessSizing {
            ipv4: ipv4_initial,
            ipv6: 1280,
        },
        peer_reassembly_ipv4: None,
        peer_reassembly_ipv6: None,
        adjunct: AdjunctLimits::default(),
    }
}

// Deterministic counter entropy, so tests can force IPv6 collisions.
fn counter_entropy(state: Arc<Mutex<u32>>) -> Entropy {
    Box::new(move |out: &mut [u8]| {
        let mut s = state.lock().unwrap();
        for b in out.iter_mut() {
            *b = *s as u8;
        }
        *s = s.wrapping_add(1);
        Ok(())
    })
}

fn side(local: SocketAddr, identity: u128, limits: DatagramLimits) -> Side {
    let cfg = config(2);
    let mut side = managed_limited(local, identity, cfg, false, None, None, |p, mut l| {
        l.datagrams = limits;
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    });
    side.0
        .set_entropy(counter_entropy(Arc::new(Mutex::new(0x5a))));
    side.0.start_identifiers(Continuity::QuietSince(0)).unwrap();
    side
}

fn options() -> UdpOptions {
    UdpOptions {
        dscp: 0,
        hop_limit: 64,
    }
}

fn fragment(capability: Option<u32>) -> UdpSend {
    UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: capability,
    }
}

const MDL: u64 = 120_000_000;

// Parse one physical packet: (offset, more, identification, header, data).
fn piece(packet: &[u8]) -> (usize, bool, u32, usize, Vec<u8>) {
    if packet[0] >> 4 == 4 {
        let p = ntcp_ip::parse_fragment(packet, false).unwrap();
        assert!(p.fragmentation.dont_fragment, "DF on every IPv4 packet");
        (
            usize::from(p.fragmentation.offset),
            p.fragmentation.more_fragments,
            u32::from(p.fragmentation.identification),
            p.header.len(),
            p.payload.to_vec(),
        )
    } else {
        let p = ntcp_ip6::parse_fragment(packet).unwrap();
        match p.fragment {
            Some(f) => (
                usize::from(f.offset),
                f.more_fragments,
                f.identification,
                48,
                p.payload.to_vec(),
            ),
            None => (0, false, 0, 40, p.payload.to_vec()),
        }
    }
}

fn send(
    a: &mut Side,
    now: u64,
    flow: UdpFlowId,
    mode: Option<UdpSend>,
    payload: &[u8],
    mut outcome: impl FnMut(usize) -> BackendOutcome,
) -> (Result<DatagramReport, DatagramError>, Vec<Vec<u8>>) {
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    // Identifiers start one MDL after the predecessor stopped at 0.
    let result = a.0.udp_send_datagram(
        &a.1,
        MDL + now,
        flow,
        None,
        mode,
        payload,
        &mut packet,
        |_, bytes| {
            let o = outcome(sent.len());
            sent.push(bytes.to_vec());
            o
        },
    );
    (result, sent)
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Host fragmentation mimics IPv6 and happens only in the host: Host UDP datagrams in Fragment mode and the Host's Echo Replies (the Echo service does not answer an IPv4 Echo Request carrying a source route until T14 delivers received option metadata to Host-originated replies) leave through one datagram emitter (Host::transmit, crates/stacks/ntcp-host/src/emitter.rs) that cuts an IPv4 datagram larger than the connectionless effective size with ntcp_ip::Fragmenter, which sets DF on every fragment, just as it cuts IPv6 (base header, Fragment header, upper layer); the atomic IPv4 encoder (encode_present) sets DF on every unfragmented packet, and TCP never enters source fragmentation. Host tests assert DF on every IPv4 fragment and packet of a fragmented send, the tun_echo IPv4 path asserts DF on TCP packets and PLPMTUD probes, and the integration/rfc_host fragment, fragment-ptb and adjunct-silence cases check DF on every captured IPv4 fragment and probe. User disposition of the SHOULD (recorded): an application that sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT on a native socket gets its ordinary IPv4 TCP output without DF, an application-requested exception; every such packet carries an Identification leased from the Host allocator for its (source, destination, TCP) tuple, the RFC 6864 ceiling holds the packet instead of reusing a value, its PLPMTUD probes keep DF and TCP is never source-fragmented (ntcp-socket tests managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling and dont_packets_follow_the_source_quiet_assertion). User disposition for administratively flagged routes (recorded decision B): on an IPv4 route or path whose owner disabled discovery (RFC 1191 section 6.6, which RFC 4821 does not update) every packet of TCP, Host::udp_send, Host::udp_send_datagram and Echo replies, Host source fragments included, leaves DF clear with a leased Identification and a recomputed header checksum under the RFC 1122 section 3.3.3 sending limit, and no probe is sent there; fragments on enabled routes keep DF (ntcp-host tests disabled_ipv4_route_clears_df_on_udp_datagrams_and_source_fragments, disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments and disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams).
//# All hosts SHOULD use IPv4 fragmentation in a mode that mimics IPv6 functionality. All fragmentation SHOULD be done on the host, and all IPv4 packets, including fragments, SHOULD have the DF bit set such that they will not be fragmented (again) in the network. See Section 8.
//= https://www.rfc-editor.org/rfc/rfc4821#section-8
//= type=test
//= reason=Host::udp_send_datagram's Fragment mode (crates/stacks/ntcp-host/src/udp.rs) fragments, in the host IP layer, an application datagram larger than the connectionless effective Path MTU E = min(shared ordinary budget, max(connectionless initial eff_pmtu, adjunct-confirmed lower bound)), which the probe outcomes a flow's application reports (4821-160) raise or bound for that flow only, to E even when it is smaller than the first-hop MTU, within the receiver reassembly guarantee (IPv4 576, IPv6 1500) or a capability the application states; a datagram the guarantee forbids fragmenting still goes whole within the shared budget. Every IPv4 fragment carries DF (except on an owner-disabled IPv4 route, the user's recorded decision B under RFC 1191 section 6.6, where every packet leaves DF clear) and a leased Identification, and IPv6 uses the same emitter, so the behavior is the same in both families. Host tests cut a 3000-octet datagram at E = 1280 below a 1500 first hop into 1276-octet IPv4 and 1280-octet IPv6 fragments with DF on each IPv4 fragment and one complete-datagram checksum; the integration/rfc_host fragment case captures tun_echo replies cut to E below the 1500 first hop, and fragment-ptb shows a real router PTB for an oversized DF first fragment lowering the path so the next datagram is refragmented at 1280. Section 9's exception is Probe mode (4821-158).
//# It is RECOMMENDED that IPv4 implementations use a strategy that mimics IPv6 functionality. When an application sends datagrams that are larger than the effective Path MTU, they SHOULD be fragmented to the Path MTU in the host IP layer even if they are smaller than the MTU of the first link, directly attached to the host. The DF bit SHOULD be set on the fragments, so they will not be fragmented again in the network. This technique will minimize the likelihood that applications will rely on IPv4 fragmentation in a way that cannot be implemented in IPv6. At least one major operating system already uses this strategy. Section 9 describes some exceptions to this rule when the application is sending oversized packets for probing or diagnostic purposes.
fn fragment_mode_cuts_to_the_effective_size_with_df_and_one_checksum() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        // The connectionless size (1280) is below the 1500 first hop.
        let mut a = side(local, 81, datagrams(1280));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let limits = a
            .0
            .udp_datagram_limits(&a.1, flow, None, Some(fragment(Some(4000))))
            .unwrap();
        assert_eq!(limits.effective_size, 1280);
        assert_eq!(limits.guarantee, 4000);
        assert!(limits.guarantee_stated);
        assert_eq!(
            limits.unfragmented_payload,
            1500 - if v6 { 48 } else { 28 }
        );
        assert_eq!(limits.max_payload, 4000 - if v6 { 48 } else { 28 });
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 13) as u8).collect();
        let (report, sent) = send(&mut a, 5, flow, Some(fragment(Some(4000))), &payload, |_| {
            BackendOutcome::Submitted
        });
        let report = report.unwrap();
        assert_eq!(report.fragments, 3);
        assert_eq!((report.submitted, report.possibly_submitted), (3, 0));
        assert_eq!(report.terminal, None);
        assert_eq!(sent.len(), 3);
        let mut data = Vec::new();
        let mut ids = Vec::new();
        for (i, bytes) in sent.iter().enumerate() {
            let (offset, more, id, header, chunk) = piece(bytes);
            assert_eq!(offset, data.len());
            assert_eq!(more, i != 2);
            if more {
                // 1276-octet IPv4 fragments (1256 data) and 1280-octet IPv6
                // fragments on a 1280 effective size.
                assert_eq!(bytes.len(), if v6 { 1280 } else { 1276 });
                assert_eq!(chunk.len() % 8, 0);
            }
            assert_eq!(header, if v6 { 48 } else { 20 });
            ids.push(id);
            data.extend_from_slice(&chunk);
        }
        assert!(ids.iter().all(|id| Some(*id) == report.identification));
        // The checksum covers the complete datagram once.
        let udp = ntcp_ip_common::parse_udp(local.ip(), remote.ip(), &data).unwrap();
        assert_eq!(udp.payload, &payload[..]);
        // One ledger record per fragment: the first carries the UDP
        // selector of the complete datagram, later ones are portless with
        // their offset, MF and first eight data octets.
        let records: Vec<_> = a.0.ledger.records().collect();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            records[0].evidence.transport,
            Selector::UdpFirstFragment { length, .. } if usize::from(length) == 8 + payload.len()
        ));
        for (r, bytes) in records[1..].iter().zip(&sent[1..]) {
            let (offset, more, _, header, chunk) = piece(bytes);
            assert_eq!(
                r.evidence.transport,
                Selector::Fragment {
                    offset: offset as u16,
                    more,
                    prefix: FragmentPrefix::new(&chunk[..8]),
                    logical_ports: (local.port(), remote.port()),
                }
            );
            assert_eq!(usize::from(r.evidence.header_len), header);
        }
        let lens: Vec<_> = records.iter().map(|r| r.evidence.packet_len as usize).collect();
        assert_eq!(lens, sent.iter().map(Vec::len).collect::<Vec<_>>());

        // A second datagram to the same destination gets a new identifier.
        let (second, _) = send(&mut a, 6, flow, Some(fragment(Some(4000))), &payload, |_| {
            BackendOutcome::Submitted
        });
        assert_ne!(second.unwrap().identification, report.identification);
    }
}

#[test]
fn peer_guarantee_refuses_unless_capability_is_stated_and_never_below_the_path() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 82, datagrams(1024));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let overhead = if v6 { 48 } else { 28 };
        let guarantee = if v6 { 1500 } else { 576 };
        // 3000 octets exceed the receiver guarantee: refused with it.
        let (result, sent) = send(&mut a, 5, flow, Some(fragment(None)), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::PeerLimit {
                max_payload: 1500 - overhead,
                guarantee,
            })
        );
        assert!(sent.is_empty());
        // Within the path budget a datagram is never refused by the rule:
        // beyond the IPv4 guarantee it is simply not fragmented. IPv6's
        // 1500 guarantee covers the whole 1500 link, so it is fragmented to
        // the 1280 effective size.
        let (result, sent) = send(&mut a, 6, flow, Some(fragment(None)), &[2; 1400], |_| {
            BackendOutcome::Submitted
        });
        let report = result.unwrap();
        if v6 {
            assert_eq!(report.fragments, 2);
            assert!(report.identification.is_some());
        } else {
            assert_eq!((report.fragments, report.identification), (1, None));
            assert_eq!(sent[0].len(), 1400 + overhead);
        }
        // Within the guarantee and above the effective size: fragmented.
        let payload = vec![3; guarantee as usize - overhead];
        let (result, sent) = send(&mut a, 7, flow, Some(fragment(None)), &payload, |_| {
            BackendOutcome::Submitted
        });
        let report = result.unwrap();
        if v6 {
            assert_eq!(report.fragments, 2);
            assert!(sent.iter().all(|p| p.len() <= 1280));
        } else {
            // 576 < 1024: within the effective size, one packet.
            assert_eq!(report.fragments, 1);
        }
        // The flow default applies when no override is given.
        a.0.udp_set_send(flow, fragment(Some(4000))).unwrap();
        let (result, _) = send(&mut a, 8, flow, None, &[4; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert!(result.unwrap().fragments > 1);
    }
}

#[test]
fn refuse_mode_and_udp_send_keep_the_unfragmented_contract() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 83, datagrams(1024));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let max_payload = 1500 - if v6 { 48 } else { 28 };
        let (result, sent) = send(&mut a, 5, flow, None, &[0; 1600], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(result, Err(DatagramError::TooBig { max_payload }));
        assert!(sent.is_empty());
        let mut packet = vec![0; 4000];
        assert_eq!(
            a.0.udp_send(&a.1, 5, flow, None, &[0; 1600], &mut packet, |_, _| {
                BackendOutcome::Submitted
            }),
            Err(UdpSendError::TooBig { max_payload })
        );
        let (result, sent) = send(&mut a, 6, flow, None, &[0; 1000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(result.unwrap().fragments, 1);
        assert_eq!(sent.len(), 1);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
//# All implementations MUST include mechanisms for applications to selectively transmit packets larger than the current effective Path MTU, but smaller than the first-hop link MTU. This is necessary to implement PLPMTUD using a connectionless protocol within an application and to implement diagnostic tools that do not rely on the operating system's implementation of Path MTU Discovery. See Section 9 for further discussion.
//= https://www.rfc-editor.org/rfc/rfc4821#section-9
//= type=test
//= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
//# All implementations MUST include a mechanism where applications using connectionless protocols can send their own probes. This is necessary to implement PLPMTUD in an application protocol as described in Section 10.4 or to implement diagnostic tools for debugging problems with PMTUD. There MUST be a mechanism that permits an application to send datagrams that are larger than eff_pmtu, the operating systems estimate of the Path MTU, without being fragmented. If these are IPv4 packets, they MUST have the DF bit set.
//= https://www.rfc-editor.org/rfc/rfc4821#section-9
//= type=test
//= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
//# At this time, most operating systems support two modes for sending datagrams: one that silently fragments packets that are too large, and another that rejects packets that are too large. Neither of these modes is suitable for implementing PLPMTUD in an application or diagnosing problems with Path MTU Discovery. A third mode is REQUIRED where the datagram is sent even if it is larger than the current estimate of the Path MTU.
//= https://www.rfc-editor.org/rfc/rfc4821#section-10.4
//= type=test
//= reason=Host::udp_send_datagram's Probe mode (UdpSendMode::Probe, crates/stacks/ntcp-host/src/udp.rs), selected per send or as a flow default beside Fragment (fragments a datagram that is too large) and Refuse (rejects it; udp_send's contract), sends one application datagram larger than the current estimate (the shared learned budget, eff_pmtu) and up to the first-hop link MTU unfragmented: IPv4 with DF, IPv6 without a Fragment header. It bypasses only the learned-size admission and keeps first-hop, path-generation and exact-byte validation. Its ProbeRecord states definite or uncertain submission, flow generation, path incarnation, version and negative revision, size, the estimate it exceeded and the submission time; it proves submission, not delivery, and writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160). Host tests send a probe above a learned 1280 estimate within the 1500 first hop and assert one unfragmented packet (DF on IPv4), the record, an uncertain record for an unknown backend outcome, refusal beyond the first hop and an unchanged shared limit; the integration/rfc_host probe-mode case sends 1400- and 1500-octet probes above a router-taught 1280 estimate in both families and captures each as one unfragmented packet (DF on IPv4) drawing a real router PTB.
//# All application probing techniques require the ability to send messages that are larger than the current eff_pmtu described in Section 9.
fn probe_mode_sends_one_unfragmented_datagram_above_the_estimate() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut a = side(local, 84, datagrams(1024));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
        a.0.trusted_decrease(1, path, 1280).unwrap();
        let overhead = if v6 { 48 } else { 28 };
        let probe = UdpSend {
            mode: UdpSendMode::Probe,
            peer_capability: None,
        };
        let limits = a.0.udp_datagram_limits(&a.1, flow, None, Some(probe)).unwrap();
        assert_eq!(limits.unfragmented_payload, 1280 - overhead);
        assert_eq!(limits.max_payload, 1500 - overhead);
        // Above the 1280 estimate, within the 1500 first hop.
        let (result, sent) = send(&mut a, 5, flow, Some(probe), &[7; 1400], |_| {
            BackendOutcome::Submitted
        });
        let report = result.unwrap();
        let record = report.probe.unwrap();
        assert_eq!(sent.len(), 1);
        let (offset, more, _, header, _) = piece(&sent[0]);
        assert_eq!((offset, more, header), (0, false, if v6 { 40 } else { 20 }));
        assert!(record.definite);
        assert_eq!(record.size as usize, 1400 + overhead);
        assert_eq!(record.above, Some(1280));
        assert_eq!(record.path, path);
        assert_eq!(record.submitted_at, MDL + 5);
        // An unknown outcome is an uncertain probe.
        let (result, _) = send(&mut a, 6, flow, Some(probe), &[7; 1400], |_| {
            BackendOutcome::Unknown
        });
        assert!(!result.unwrap().probe.unwrap().definite);
        // Never beyond the first hop.
        let (result, sent) = send(&mut a, 7, flow, Some(probe), &[7; 1600], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::TooBig {
                max_payload: 1500 - overhead
            })
        );
        assert!(sent.is_empty());
        // The probe wrote no shared state.
        assert_eq!(
            a.0.udp_path_limits(&a.1, flow, None).unwrap().max_payload,
            1280 - overhead
        );
    }
}

#[test]
fn partial_and_unknown_outcomes_at_every_fragment_boundary() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        for stop in 0..3 {
            for terminal in [
                BackendOutcome::WouldBlock,
                BackendOutcome::NotSubmitted,
                BackendOutcome::Unknown,
            ] {
                let mut a = side(local, 85, datagrams(1280));
                let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
                let (result, sent) =
                    send(&mut a, 5, flow, Some(fragment(Some(4000))), &[9; 3000], |i| {
                        if i < stop {
                            BackendOutcome::Submitted
                        } else {
                            terminal
                        }
                    });
                // The transaction stops at the first non-Submitted outcome.
                assert_eq!(sent.len(), stop + 1);
                let records: Vec<_> = a.0.ledger.records().collect();
                let possibly = usize::from(terminal == BackendOutcome::Unknown);
                if stop == 0 && possibly == 0 {
                    assert_eq!(result, Err(DatagramError::NotSubmitted(terminal)));
                } else {
                    let report = result.unwrap();
                    assert_eq!(report.fragments, 3);
                    assert_eq!(report.submitted, stop);
                    assert_eq!(report.possibly_submitted, possibly);
                    assert_eq!(report.terminal, Some(terminal));
                }
                // Submitted and possibly submitted fragments are sealed one
                // by one; the unattempted suffix leaves nothing behind.
                assert_eq!(records.len(), stop + possibly);
                assert_eq!(
                    records.iter().filter(|r| r.possibly_submitted).count(),
                    possibly
                );
                assert_eq!(a.0.ledger.pending_count(), 0);
                // A whole retry is a new datagram with a new identifier.
                let first = piece(&sent[0]).2;
                let (retry, again) =
                    send(&mut a, 6, flow, Some(fragment(Some(4000))), &[9; 3000], |_| {
                        BackendOutcome::Submitted
                    });
                assert_eq!(retry.unwrap().submitted, 3);
                assert_ne!(piece(&again[0]).2, first);
            }
        }
    }
}

#[test]
fn identifiers_backpressure_without_entropy_or_before_the_quiet_period() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let cfg = config(2);
        let mut a = managed_limited(local, 86, cfg, false, None, None, |p, mut l| {
            l.datagrams = datagrams(1280);
            let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
            (p, l, 1)
        });
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let big = fragment(Some(4000));
        // Not started: unavailable.
        let (result, sent) = send(&mut a, 5, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::Backpressure(
                IdentifierBackpressure::Unavailable { until: None }
            ))
        );
        assert!(sent.is_empty());
        // Quiet for a full MDL after the previous context stopped at 10.
        a.0.start_identifiers(Continuity::QuietSince(MDL + 10)).unwrap();
        assert_eq!(
            a.0.start_identifiers(Continuity::QuietSince(MDL + 10)),
            Err(Error::InvalidContext)
        );
        let (result, _) = send(&mut a, 11, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::Backpressure(
                IdentifierBackpressure::Unavailable {
                    until: Some(10 + 2 * MDL)
                }
            ))
        );
        // No entropy: no weak fallback.
        let (result, _) = send(&mut a, 10 + MDL, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::Backpressure(IdentifierBackpressure::Entropy))
        );
        a.0.set_entropy(Box::new(|_: &mut [u8]| Err(EntropyError)));
        let (result, _) = send(&mut a, 10 + MDL, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(
            result,
            Err(DatagramError::Backpressure(IdentifierBackpressure::Entropy))
        );
        // Unfragmented datagrams need no identifier.
        let (result, _) = send(&mut a, 10 + MDL, flow, Some(big), &[1; 1000], |_| {
            BackendOutcome::Submitted
        });
        assert_eq!(result.unwrap().identification, None);
        a.0.set_entropy(counter_entropy(Arc::new(Mutex::new(1))));
        let (result, _) = send(&mut a, 10 + MDL, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert!(result.unwrap().identification.is_some());
    }
}

#[test]
fn ipv4_identifiers_are_unique_per_tuple_until_the_mdl_ceiling() {
    let mut allocator = IdentifierAllocator::new(
        IdentifierLimits {
            lifetime_seconds: 120,
            ipv4_tuples: 2,
            ipv6_leases: 0,
        },
        1_000_000,
    )
    .unwrap();
    // Quiet until one MDL after a predecessor stopped at 0.
    allocator.start_quiet(0);
    const B: u64 = MDL;
    let mut entropy = counter_entropy(Arc::new(Mutex::new(0xff)));
    let (s, d): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    let other: IpAddr = "192.0.2.3".parse().unwrap();
    let mut seen = std::collections::HashSet::new();
    // 65536 values per (source, destination, protocol) within one MDL,
    // wrapping from the random start; then explicit backpressure.
    let mut last = None;
    for i in 0..65536u32 {
        let id = allocator.issue(B + 1 + u64::from(i), s, d, 17, Some(&mut entropy)).unwrap();
        assert!(seen.insert(id), "identifier {id} reused within the MDL");
        last = Some(id);
    }
    assert_eq!(seen.len(), 65536);
    // The first value was 0xff00 (a random block start): it wrapped.
    assert_eq!(last, Some(0xfeff));
    let blocked = allocator.issue(B + 70_000, s, d, 17, Some(&mut entropy));
    assert!(matches!(
        blocked,
        Err(IdentifierBackpressure::Exhausted { retry_at }) if retry_at > B + 70_000
    ));
    // Other protocols and destinations have their own space.
    assert!(allocator.issue(B + 70_000, s, d, 1, Some(&mut entropy)).is_ok());
    // Both tuple slots are live and never evicted for a third tuple.
    assert!(matches!(
        allocator.issue(B + 70_000, s, other, 17, Some(&mut entropy)),
        Err(IdentifierBackpressure::Exhausted { .. })
    ));
    // After the MDL the oldest block is reusable again.
    let Err(IdentifierBackpressure::Exhausted { retry_at }) = blocked else {
        unreachable!()
    };
    assert!(allocator.issue(retry_at, s, d, 17, Some(&mut entropy)).is_ok());
}

#[test]
fn ipv6_identifiers_check_every_live_lease_and_bound_collisions() {
    let mut allocator = IdentifierAllocator::new(
        IdentifierLimits {
            lifetime_seconds: 1,
            ipv4_tuples: 0,
            ipv6_leases: 3,
        },
        1_000_000,
    )
    .unwrap();
    allocator.start_quiet(0);
    const B: u64 = 1_000_000;
    let (s, d): (IpAddr, IpAddr) = (
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    );
    // Constant entropy: every draw collides after the first lease.
    let mut constant: Entropy = Box::new(|out: &mut [u8]| {
        out.fill(7);
        Ok(())
    });
    let first = allocator.issue(B + 1, s, d, 17, Some(&mut constant)).unwrap();
    assert_eq!(first, 0x0707_0707);
    assert!(matches!(
        allocator.issue(B + 2, s, d, 17, Some(&mut constant)),
        Err(IdentifierBackpressure::Exhausted { .. })
    ));
    // Another pair may hold the same value.
    let other: IpAddr = "2001:db8::3".parse().unwrap();
    assert_eq!(allocator.issue(B + 2, s, other, 17, Some(&mut constant)), Ok(first));
    // Distinct draws fill the table; a full table of live leases is
    // backpressure until the oldest expires, never an eviction.
    let mut entropy = counter_entropy(Arc::new(Mutex::new(1)));
    allocator.issue(B + 3, s, d, 17, Some(&mut entropy)).unwrap();
    assert_eq!(
        allocator.issue(B + 4, s, d, 17, Some(&mut entropy)),
        Err(IdentifierBackpressure::Exhausted { retry_at: B + 1_000_001 })
    );
    assert!(allocator.issue(B + 1_000_001, s, d, 17, Some(&mut entropy)).is_ok());
    // An expired lease no longer blocks its value.
    assert_eq!(
        allocator.issue(B + 1_000_002, s, d, 17, Some(&mut constant)),
        Ok(first)
    );
}

#[test]
fn live_leases_survive_route_removal_and_host_replacement() {
    let (local, remote) = addresses(false);
    let mut a = side(local, 87, datagrams(1280));
    let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
    let big = fragment(Some(4000));
    let mut ids = std::collections::HashSet::new();
    for now in 1..=3 {
        let (r, _) = send(&mut a, now, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert!(ids.insert(r.unwrap().identification.unwrap()));
    }
    // A successor Host receives the allocator with its leases.
    let allocator = a.0.take_identifiers().unwrap();
    let (result, _) = send(&mut a, 4, flow, Some(big), &[1; 3000], |_| {
        BackendOutcome::Submitted
    });
    assert!(matches!(result, Err(DatagramError::Backpressure(_))));
    let mut b = managed_limited(local, 88, config(2), false, None, None, |p, mut l| {
        l.datagrams = datagrams(1280);
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    });
    // Same counter entropy as `a`: a fresh allocator would restart at the
    // same random value and repeat a's identifiers.
    b.0.set_entropy(counter_entropy(Arc::new(Mutex::new(0x5a))));
    b.0.start_identifiers(Continuity::Transfer(allocator)).unwrap();
    let flow = b.0.udp_open(&b.1, local, Some(remote), options()).unwrap();
    for now in 5..=7 {
        let (r, _) = send(&mut b, now, flow, Some(big), &[1; 3000], |_| {
            BackendOutcome::Submitted
        });
        assert!(ids.insert(r.unwrap().identification.unwrap()));
    }
    // A never-started allocator carries no continuity.
    let mut c = managed_limited(local, 89, config(2), false, None, None, |p, mut l| {
        l.datagrams = datagrams(1280);
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    });
    let unstarted = c.0.take_identifiers().unwrap();
    assert_eq!(
        b.0.start_identifiers(Continuity::Transfer(unstarted)),
        Err(Error::InvalidContext)
    );
}

#[test]
fn physical_receipt_reflects_the_actual_fragmentation_fields() {
    let mut v4 = [0u8; 20];
    v4[0] = 0x45;
    assert!(!unfragmentable(&v4));
    v4[6] = 0x40;
    assert!(unfragmentable(&v4));
    let mut v6 = [0u8; 48];
    v6[0] = 0x60;
    v6[6] = 6;
    assert!(unfragmentable(&v6));
    v6[6] = 44;
    assert!(!unfragmentable(&v6));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-10.3
//= type=test
//= reason=The Host has a separate Host-wide control for the connectionless initial eff_pmtu, DatagramLimits::connectionless (ConnectionlessSizing, crates/stacks/ntcp-host/src/emitter.rs), distinct from TCP's PLPMTUD configuration: by default RFC 4821 section 7.2's suggested 1024 octets for IPv4 and the 1280-octet IPv6 minimum link MTU, validated when the Host is created. Until the Echo adjunct confirms a larger size, Host UDP Fragment mode and Echo Replies (the Echo service does not answer an IPv4 Echo Request carrying a source route until T14 delivers received option metadata to Host-originated replies) cut fragments to min(shared ordinary budget, initial value), even below a 1500 first hop, and the initial value is never written into shared state or lowers another client's budget. Host tests assert the 1024/1280 effective size and fragments within it under a 1500 budget; the integration/rfc_host fragment case captures 1020-octet IPv4 and 1280-octet IPv6 reply fragments before any probe.
//# Since connectionless protocols might not keep enough state to effectively diagnose MTU black holes, it would be more robust to err on the side of using too small of an initial MTU (e.g., 1 kByte or less) prior to probing a path to measure the MTU. For this reason, implementations that use IP fragmentation SHOULD use an initial eff_pmtu, which is selected as described in Section 7.2, except using a separate global control for the default initial eff_mtu for connectionless protocols.
fn reported_limits_and_buffer_follow_the_send_decision_between_the_two_sizes() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        // Effective size 1024 (IPv4) / 1280 (IPv6) below the 1500 budget.
        let mut a = side(local, 90, datagrams(1024));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let overhead = if v6 { 48 } else { 28 };
        let effective = if v6 { 1280 } else { 1024 };
        // Above the effective payload, within the shared budget.
        let payload = vec![6u8; 1240];
        let complete = payload.len() + overhead;
        for capability in [Some(4000), None] {
            let mode = fragment(capability);
            let limits = a.0.udp_datagram_limits(&a.1, flow, None, Some(mode)).unwrap();
            assert_eq!(limits.effective_size, effective);
            assert_eq!(limits.effective_payload, effective as usize - overhead);
            assert_eq!(limits.unfragmented_payload, 1500 - overhead);
            assert!(payload.len() > limits.effective_payload);
            assert!(payload.len() <= limits.unfragmented_payload);
            // Without a stated capability IPv4 may not fragment beyond 576,
            // so the datagram goes whole; IPv6's 1500 guarantee covers it.
            let fragmented = capability.is_some() || v6;
            assert_eq!(limits.fragments(payload.len()), fragmented);
            assert_eq!(
                limits.fragmentable_payload,
                match (capability, v6) {
                    (Some(_), _) => 4000 - overhead,
                    (None, false) => 576 - overhead,
                    (None, true) => 1500 - overhead,
                }
            );
            let len = limits.buffer_len(payload.len());
            assert_eq!(
                len,
                if fragmented {
                    effective as usize + 8 + payload.len()
                } else {
                    complete
                }
            );
            if fragmented {
                // One octet less cannot hold the datagram and one fragment.
                let mut short = vec![0; len - 1];
                assert_eq!(
                    a.0.udp_send_datagram(
                        &a.1,
                        MDL + 5,
                        flow,
                        None,
                        Some(mode),
                        &payload,
                        &mut short,
                        |_, _| panic!("nothing is submitted"),
                    ),
                    Err(DatagramError::Host(Error::Capacity))
                );
            }
            let mut packet = vec![0; len];
            let mut sent = Vec::new();
            let report = a
                .0
                .udp_send_datagram(
                    &a.1,
                    MDL + 6,
                    flow,
                    None,
                    Some(mode),
                    &payload,
                    &mut packet,
                    |_, bytes| {
                        sent.push(bytes.len());
                        BackendOutcome::Submitted
                    },
                )
                .unwrap();
            assert_eq!(report.ip_len, complete);
            if fragmented {
                assert_eq!(report.fragments, 2);
                assert!(sent.iter().all(|&n| n <= effective as usize));
            } else {
                assert_eq!((report.fragments, report.identification), (1, None));
                assert_eq!(sent, [complete]);
            }
        }
        // Within the effective size: whole, and the buffer is the datagram.
        let limits = a
            .0
            .udp_datagram_limits(&a.1, flow, None, Some(fragment(Some(4000))))
            .unwrap();
        let small = limits.effective_payload;
        assert!(!limits.fragments(small));
        assert_eq!(limits.buffer_len(small), small + overhead);
        // Refuse mode never fragments.
        let refuse = a
            .0
            .udp_datagram_limits(&a.1, flow, None, Some(UdpSend::default()))
            .unwrap();
        assert_eq!(refuse.fragmentable_payload, 0);
        assert!(!refuse.fragments(payload.len()));
        assert_eq!(refuse.buffer_len(payload.len()), complete);
    }
}

#[test]
fn asserted_quiet_periods_count_from_when_emission_ceased() {
    let (local, remote) = addresses(true);
    let second = 1_000_000;
    for (seconds, available) in [(0, MDL), (30, MDL - 30 * second), (u64::MAX, 0)] {
        let mut a = managed_limited(local, 91, config(2), false, None, None, |p, mut l| {
            l.datagrams = datagrams(1280);
            let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
            (p, l, 1)
        });
        a.0.set_entropy(counter_entropy(Arc::new(Mutex::new(3))));
        a.0.start_identifiers(Continuity::QuietFor { at: 0, seconds })
            .unwrap();
        if available != 0 {
            assert_eq!(
                a.0.lease_identification(available - 1, local.ip(), remote.ip(), 17),
                Err(IdentifierBackpressure::Unavailable {
                    until: Some(available)
                })
            );
        }
        assert!(
            a.0.lease_identification(available, local.ip(), remote.ip(), 17)
                .is_ok()
        );
    }
}

// RFC 8201 section 5.6 / RFC 1191 section 6.6: an owner discovery disable
// on an IPv6 path is applied to an existing flow by the transaction (its
// change notification carries the capped limit at once): Refuse admits only
// datagrams that fit 1280 octets whole, Fragment cuts every physical packet
// to at most 1280, Probe is refused with DiscoveryDisabled before anything
// is submitted. IPv4 Probe is refused too and the IPv4 limit drops to 576
// octets (RFC 1122 section 3.3.3, off-link next hop); clearing the policy
// restores the earlier limits without any learned estimate.
#[test]
fn discovery_disable_caps_ipv6_flows_at_1280_and_refuses_probes() {
    use path::{AdminChange, AdminPolicy, AdminTarget};
    let probe = UdpSend {
        mode: UdpSendMode::Probe,
        peer_capability: None,
    };
    let refuse = UdpSend {
        mode: UdpSendMode::Refuse,
        peer_capability: None,
    };
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let remote = SocketAddr::new(remote.ip(), 7);
        let mut a = side(local, 9900 + u128::from(v6), datagrams(576));
        let flow = a.0.udp_open(&a.1, local, Some(remote), options()).unwrap();
        let before = a.0.udp_path_limits(&a.1, flow, None).unwrap();
        let path = before.path;
        let overhead = if v6 { 48 } else { 28 };
        assert_eq!(before.max_payload, 1500 - overhead);
        let capability = a.0.administration();
        let set = |a: &mut Side, disabled: bool| {
            let expected = a.0.admin_path(&capability, path).unwrap().generation;
            let candidate = a
                .0
                .admin_validate(
                    &capability,
                    MDL,
                    AdminChange {
                        target: AdminTarget::Path(path),
                        expected,
                        policy: AdminPolicy {
                            discovery_disabled: disabled,
                            estimate: None,
                        },
                    },
                )
                .unwrap();
            a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        };
        set(&mut a, true);
        let change = a.0.udp_path_change(flow).unwrap().unwrap();
        // IPv4: the RFC 1122 section 3.3.3 limit of a forwarder next hop.
        let cap = if v6 { 1280 } else { 576 };
        assert_eq!(change.max_payload, cap - overhead);
        assert_eq!(
            a.0.udp_datagram_limits(&a.1, flow, None, Some(probe)).unwrap().max_payload,
            0
        );
        let (result, sent) = send(&mut a, 1, flow, Some(probe), &[1; 100], |_| {
            panic!("no probe is submitted")
        });
        assert_eq!(result.err(), Some(DatagramError::DiscoveryDisabled));
        assert!(sent.is_empty());
        if v6 {
            let (result, _) = send(&mut a, 2, flow, Some(refuse), &[2; 1400], |_| {
                BackendOutcome::Submitted
            });
            assert_eq!(
                result.err(),
                Some(DatagramError::TooBig {
                    max_payload: 1280 - overhead
                })
            );
            let (result, sent) = send(&mut a, 3, flow, Some(refuse), &[3; 1280 - 48], |_| {
                BackendOutcome::Submitted
            });
            assert!(result.is_ok());
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].len(), 1280);
            let (result, sent) = send(&mut a, 4, flow, Some(fragment(None)), &[4; 1400], |_| {
                BackendOutcome::Submitted
            });
            assert!(result.is_ok());
            assert!(sent.len() > 1);
            assert!(sent.iter().all(|p| p.len() <= 1280));
        }
        set(&mut a, false);
        let after = a.0.udp_path_change(flow).unwrap().unwrap();
        assert_eq!(after.max_payload, before.max_payload);
        assert_eq!(a.0.paths().path_snapshot(path).unwrap().learned_mtu(), None);
    }
}
