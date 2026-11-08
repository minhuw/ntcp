// The IPv4 policy of a discovery-disabled route (RFC 1191 section 6.6 with
// RFC 791 fragmentation and the RFC 1122 section 3.3.3 sending limit): DF
// clear on every packet, TCP and UDP, whole packets and source fragments,
// each datagram with a leased Identification and a valid header checksum;
// the sending limit applied to existing and future users; identifier
// backpressure holds output; re-enabling restores DF without size proof.
use super::*;
use path::{AdminChange, AdminPolicy, AdminTarget};

type Side = (Host, Endpoint, IngressContext);

const MDL: u64 = 120_000_000;

fn set_route(a: &mut Side, route: path::RouteId, policy: AdminPolicy, now: u64) {
    let capability = a.0.administration();
    let expected = a
        .0
        .admin_routes(&capability)
        .unwrap()
        .find(|r| r.route == route)
        .unwrap()
        .generation;
    let candidate = a
        .0
        .admin_validate(
            &capability,
            now,
            AdminChange {
                target: AdminTarget::Route(route),
                expected,
                policy,
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
}

fn disabled(estimate: Option<u32>) -> AdminPolicy {
    AdminPolicy {
        discovery_disabled: true,
        estimate,
    }
}

// An IPv4 header the network may fragment: DF clear, the given
// Identification, a valid checksum.
fn assert_df_clear(packet: &[u8]) -> u16 {
    assert_eq!(packet[0] >> 4, 4);
    assert_eq!(packet[6] & 0x40, 0, "DF clear");
    let header = usize::from(packet[0] & 0x0f) * 4;
    assert_eq!(ntcp_ip_common::checksum(&packet[..header]), 0, "header checksum");
    u16::from_be_bytes([packet[4], packet[5]])
}

// Exchange until quiet, checking every packet `a` emits with `check`.
fn exchange(a: &mut Side, b: &mut Side, now: &mut u64, mut check: impl FnMut(&[u8])) {
    for _ in 0..512 {
        *now += 10;
        let mut work = false;
        if let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            check(&frame);
            input(&mut b.0, &mut b.1, b.2, *now + 1, &frame, 0);
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            input(&mut a.0, &mut a.1, a.2, *now + 3, &frame, 0);
            work = true;
        }
        if !work {
            return;
        }
    }
    panic!("wire exchange did not quiesce");
}

// An existing and a future TCP connection on a disabled IPv4 route through
// a forwarder: every segment (data, ACK, SYN) leaves without DF, with a
// fresh nonzero Identification and a recomputed checksum, at most 576
// octets without an owner value and at most the owner's value with one. A
// DF-set packet fails the submission barrier. The DF-clear ACKed data never
// raises search_low; re-enabling restores DF without stale size proof.
#[test]
fn disabled_ipv4_route_clears_df_and_applies_the_sending_limit_to_tcp() {
    for (estimate, limit) in [(None, 576), (Some(1400), 1400)] {
        let cfg = config(4);
        let (local, remote) = addresses(false);
        let identity = 9900 + u64::from(limit);
        let mut a = managed_identified(local, identity, cfg.clone());
        let mut b = managed(remote, identity + 1, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let tcp = a
            .1
            .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
        let mut now = 0;
        pump(&mut a, &mut b, &mut now);
        b.1.accept(listener).unwrap();
        let before = a.1.path_mtu_info(tcp).unwrap().unwrap();
        // With the owner value above search_low, its DF-clear deliveries
        // would raise it if they counted as size proof.
        if estimate.is_some() {
            assert!(before.search_low < limit);
        }
        let route = a.0.binding(tcp).unwrap().snapshot.key().route();
        now += 10;
        set_route(&mut a, route, disabled(estimate), now);
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().failed, 0);
        assert_eq!(
            a.0.binding(tcp).unwrap().snapshot.ip_packet_budget(),
            Ok(limit)
        );

        // The barrier refuses a DF-set packet on the disabled route.
        a.1.write(tcp, &[7; 6000]).unwrap();
        now += 10;
        let (attempt, _, frame) = selected(&mut a.1, now).unwrap();
        assert_ne!(frame[6] & 0x40, 0, "the codec encodes DF");
        assert!(frame.len() <= limit as usize);
        let context = a.0.egress_context(&mut a.1, attempt).unwrap();
        assert!(a.0.clears_dont_fragment(context));
        let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
        let refused = a
            .0
            .submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
                panic!("a DF-set packet is never submitted on a disabled route")
            })
            .err()
            .unwrap();
        assert_eq!(refused.error, Error::Obsolete);
        a.0.cancel_submission(refused.ticket);
        assert!(a.1.reject_unsubmitted(attempt).unwrap());

        // Everything the embedding then submits goes without DF.
        let mut identifiers = Vec::new();
        let mut largest = 0;
        exchange(&mut a, &mut b, &mut now, |frame| {
            assert!(frame.len() <= limit as usize, "{} > {limit}", frame.len());
            largest = largest.max(frame.len());
            identifiers.push(assert_df_clear(frame));
        });
        assert_eq!(largest, limit as usize, "data segments fill the limit");
        assert!(!identifiers.contains(&0));
        let mut unique = identifiers.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), identifiers.len(), "no Identification repeats");
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
        // DF-clear deliveries are no unfragmented-size evidence.
        let after = a.1.path_mtu_info(tcp).unwrap().unwrap();
        assert_eq!(after.search_low, before.search_low);

        // A future connection is created under the limit, SYN included.
        let second = a
            .1
            .connect_with_path_provider(
                now,
                SocketAddr::new(local.ip(), 1001),
                remote,
                options(&cfg, 0),
                &mut a.0,
            )
            .unwrap();
        let mut syn = true;
        exchange(&mut a, &mut b, &mut now, |frame| {
            if syn {
                syn = false;
                assert_eq!(frame[9], 6);
            }
            assert_df_clear(frame);
        });
        b.1.accept(listener).unwrap();
        a.1.write(second, &[9; 4000]).unwrap();
        exchange(&mut a, &mut b, &mut now, |frame| {
            assert!(frame.len() <= limit as usize);
            assert_df_clear(frame);
        });
        let progress = a.1.send_progress(second).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);

        // Re-enabling restores DF (atomic datagrams, Identification 0);
        // search_low grows again only through DF-set deliveries made after
        // it, never from the DF-clear ones before.
        set_route(
            &mut a,
            route,
            AdminPolicy {
                discovery_disabled: false,
                estimate,
            },
            now,
        );
        assert_eq!(a.0.service_changes(&mut a.1, now).unwrap().failed, 0);
        a.1.write(tcp, &[3; 3000]).unwrap();
        let mut proven = 0;
        exchange(&mut a, &mut b, &mut now, |frame| {
            assert_ne!(frame[6] & 0x40, 0, "DF again");
            assert_eq!(&frame[4..6], &[0, 0]);
            proven = proven.max(frame.len() as u32);
        });
        let progress = a.1.send_progress(tcp).unwrap();
        assert_eq!(progress.acknowledged, progress.queued_end);
        let search_low = a.1.path_mtu_info(tcp).unwrap().unwrap().search_low;
        assert!(search_low <= proven.max(before.search_low), "{search_low} > {proven}");
    }
}

// Without an available identifier a DF-clear packet cannot be built: the
// rewrite is refused and leaves the bytes untouched, so the embedding holds
// the packet (never sending a reused value) and retries.
#[test]
fn df_clear_rewrite_backpressures_without_touching_the_packet() {
    let cfg = config(2);
    let (local, _) = addresses(false);
    let mut a = managed_limited(local, 9950, cfg.clone(), false, None, None, |p, mut l| {
        l.datagrams.identifiers = IdentifierLimits {
            lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
            ipv4_tuples: 1,
            ipv6_leases: 1,
        };
        (p, l, 1)
    });
    // An atomic IPv4 TCP packet as the codec encodes it: DF, Identification 0.
    let mut frame = vec![0; 40];
    frame[..20].copy_from_slice(&[
        0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    let checksum = ntcp_ip_common::checksum(&frame[..20]);
    frame[10..12].copy_from_slice(&checksum.to_be_bytes());
    let original = frame.clone();
    // Not started: unavailable.
    assert_eq!(
        a.0.lease_df_clear(5, &mut frame),
        Err(IdentifierBackpressure::Unavailable)
    );
    assert_eq!(frame, original);
    a.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0);
        Ok(())
    }));
    a.0.start_identifiers(Continuity::Fresh).unwrap();
    // Then every lease is distinct and nonzero (a leased 0 is skipped)
    // until the RFC 6864 ceiling of the tuple holds the packet.
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let mut copy = original.clone();
        match a.0.lease_df_clear(MDL, &mut copy) {
            Ok(id) => {
                assert_ne!(id, 0);
                assert_eq!(assert_df_clear(&copy), id);
                assert!(seen.insert(id), "Identification {id} repeated");
            }
            Err(IdentifierBackpressure::Exhausted { .. }) => break,
            Err(other) => panic!("{other:?}"),
        }
        assert!(seen.len() < 65536);
    }
    assert!(seen.len() >= 65536 - 512);
    let mut copy = original.clone();
    assert!(a.0.lease_df_clear(MDL + 1, &mut copy).is_err());
    assert_eq!(copy, original);
    // One MDL later identifiers are available again.
    assert!(a.0.lease_df_clear(2 * MDL + 1, &mut copy).is_ok());
}

// The inverse rewrite for a held packet that no longer needs DF clear
// restores exactly the atomic encoding (DF set, Identification 0, valid
// checksum) of a whole IPv4 datagram, and touches nothing else: a packet
// that already has DF, an IPv4 fragment (MF or an offset) and IPv6.
#[test]
fn restore_atomic_header_inverts_the_df_clear_rewrite_of_whole_datagrams_only() {
    let mut atomic = vec![0; 40];
    atomic[..20].copy_from_slice(&[
        0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    let checksum = ntcp_ip_common::checksum(&atomic[..20]);
    atomic[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut untouched = atomic.clone();
    assert!(!Host::restore_atomic_header(&mut untouched));
    assert_eq!(untouched, atomic);
    let mut cleared = atomic.clone();
    cleared[4..6].copy_from_slice(&12544u16.to_be_bytes());
    crate::emitter::clear_dont_fragment(&mut cleared);
    assert_eq!(assert_df_clear(&cleared), 12544);
    let mut restored = cleared.clone();
    assert!(Host::restore_atomic_header(&mut restored));
    assert_eq!(restored, atomic);
    for (byte, value) in [(6, 0x20), (7, 0x01)] {
        let mut fragment = cleared.clone();
        fragment[byte] |= value;
        let before = fragment.clone();
        assert!(!Host::restore_atomic_header(&mut fragment));
        assert_eq!(fragment, before);
    }
    let mut ipv6 = vec![0x60; 48];
    assert!(!Host::restore_atomic_header(&mut ipv6));
    assert_eq!(ipv6, vec![0x60; 48]);
}

const UDP: UdpLimits = UdpLimits {
    flows: 2,
    receive_datagrams: 1,
    max_payload: 4000,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};

fn udp_side(identity: u64) -> Side {
    let (local, _) = addresses(false);
    let mut side = managed_limited(local, identity, config(2), false, None, None, |p, mut l| {
        l.datagrams = DatagramLimits {
            max_fragments: 8,
            identifiers: IdentifierLimits {
                lifetime_seconds: 120,
                ipv4_tuples: 2,
                ipv6_leases: 2,
            },
            connectionless: ConnectionlessSizing {
                ipv4: 1280,
                ipv6: 1280,
            },
            peer_reassembly_ipv4: None,
            peer_reassembly_ipv6: None,
            adjunct: AdjunctLimits::default(),
        };
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        (p, l, 1)
    });
    side.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0x33);
        Ok(())
    }));
    side.0.start_identifiers(Continuity::Fresh).unwrap();
    side
}

fn udp_send(
    a: &mut Side,
    now: u64,
    flow: UdpFlowId,
    send: UdpSend,
    payload: &[u8],
) -> (Result<DatagramReport, DatagramError>, Vec<Vec<u8>>) {
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    let result = a.0.udp_send_datagram(
        &a.1,
        now,
        flow,
        None,
        Some(send),
        payload,
        &mut packet,
        |_, bytes| {
            sent.push(bytes.to_vec());
            BackendOutcome::Submitted
        },
    );
    (result, sent)
}

// Host UDP on a disabled IPv4 route: whole datagrams and source fragments
// go without DF (fragments keep MF, offsets and the one Identification of
// their datagram) under the 576-octet forwarder limit, which
// udp_datagram_limits reports; Probe is refused; re-enabling restores DF on
// every packet and fragment.
#[test]
fn disabled_ipv4_route_clears_df_on_udp_datagrams_and_source_fragments() {
    let refuse = UdpSend {
        mode: UdpSendMode::Refuse,
        peer_capability: None,
    };
    let fragment = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    };
    let probe = UdpSend {
        mode: UdpSendMode::Probe,
        peer_capability: None,
    };
    let mut a = udp_side(9960);
    let (local, remote) = addresses(false);
    let remote = SocketAddr::new(remote.ip(), 7);
    let flow = a.0.udp_open(&a.1, local, Some(remote), UdpOptions { dscp: 0, hop_limit: 64 }).unwrap();
    let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
    let route = a.0.paths().path_snapshot(path).unwrap().key().route();
    set_route(&mut a, route, disabled(None), 10);
    let limits = a.0.udp_datagram_limits(&a.1, flow, None, Some(refuse)).unwrap();
    assert_eq!(limits.max_payload, 576 - 28);
    let limits = a.0.udp_datagram_limits(&a.1, flow, None, Some(fragment)).unwrap();
    assert_eq!(limits.effective_size, 576);
    assert_eq!(
        a.0.udp_datagram_limits(&a.1, flow, None, Some(probe)).unwrap().max_payload,
        0
    );
    assert_eq!(
        udp_send(&mut a, 20, flow, probe, &[1; 100]).0.err(),
        Some(DatagramError::DiscoveryDisabled)
    );
    assert_eq!(
        udp_send(&mut a, 20, flow, refuse, &[1; 549]).0.err(),
        Some(DatagramError::TooBig { max_payload: 548 })
    );
    let (result, sent) = udp_send(&mut a, 30, flow, refuse, &[2; 548]);
    let report = result.unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].len(), 576);
    let whole = assert_df_clear(&sent[0]);
    assert_ne!(whole, 0);
    assert_eq!(report.identification, Some(u32::from(whole)));
    assert_eq!(u16::from_be_bytes([sent[0][6], sent[0][7]]) & 0x3fff, 0);

    let (result, sent) = udp_send(&mut a, 40, flow, fragment, &[3; 1500]);
    let report = result.unwrap();
    assert_eq!(report.fragments, sent.len());
    assert!(sent.len() >= 3);
    let mut offset = 0;
    for (index, packet) in sent.iter().enumerate() {
        assert!(packet.len() <= 576);
        let id = assert_df_clear(packet);
        assert_eq!(Some(u32::from(id)), report.identification);
        assert_ne!(id, whole);
        let flags = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(flags & 0x2000 != 0, index + 1 != sent.len(), "MF");
        assert_eq!(usize::from(flags & 0x1fff) * 8, offset);
        offset += packet.len() - 20;
    }
    assert_eq!(offset, 8 + 1500);

    // Re-enabled: DF on whole datagrams and on every fragment again.
    set_route(
        &mut a,
        route,
        AdminPolicy {
            discovery_disabled: false,
            estimate: None,
        },
        50,
    );
    let (result, sent) = udp_send(&mut a, 60, flow, refuse, &[4; 1000]);
    assert_eq!(result.unwrap().identification, None);
    assert_ne!(sent[0][6] & 0x40, 0);
    let (result, sent) = udp_send(&mut a, 70, flow, fragment, &[5; 3000]);
    assert!(result.is_ok());
    assert!(sent.len() > 1);
    for packet in &sent {
        assert_ne!(packet[6] & 0x40, 0, "an enabled route keeps DF on fragments");
    }
}

fn udp_send_whole(
    a: &mut Side,
    now: u64,
    flow: UdpFlowId,
    payload: &[u8],
) -> (Result<UdpSent, UdpSendError>, Vec<Vec<u8>>) {
    let mut packet = vec![0; 8192];
    let mut sent = Vec::new();
    let result = a.0.udp_send(&a.1, now, flow, None, payload, &mut packet, |_, bytes| {
        sent.push(bytes.to_vec());
        BackendOutcome::Submitted
    });
    (result, sent)
}

// The T9 whole-datagram API on a disabled IPv4 route: without an
// identifier (an entropy failure) nothing is submitted (identifier
// backpressure, its evidence reservation released); afterwards each
// datagram leaves without DF with
// its own nonzero leased Identification and a valid header checksum,
// within the 576-octet forwarder sending limit. Re-enabled, it is atomic
// again: DF set and Identification 0.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.1
//= type=test
//= reason=T7 PathService stores shared IP estimates, T8 Host binds actual native/TUN TCP factories and T9 Host ICMP dispatch processes correlated Datagram Too Big messages. T10 lets packetization layers respond: TCP connections receive each shared change by budget application in Host::service_changes, and Host UDP flows read their payload limit (Host::udp_path_limits) and change notifications (Host::udp_path_change) to resize. Host::udp_send sends each UDP datagram unfragmented, with DF except on an owner-flagged route (UdpSendError::TooBig reports the allowable payload); T13's Host::udp_send_datagram adds an explicit per-flow default and per-send mode: Fragment source-fragments a datagram larger than the connectionless effective size within the peer reassembly guarantee or a stated capability (every IPv4 fragment keeps DF and carries an Identification from the Host allocator), Refuse keeps udp_send's contract, and Probe sends one unfragmented datagram above the estimate. The integration/rfc_host fragment and fragment-ptb cases show datagram users that do not resize served by intentional source fragmentation on a real path (tun_echo replies and a driven Host UDP flow, refragmented at 1280 after a real router PTB). IPv4 TCP sets DF by default; native sockets configured with IP_MTU_DISCOVER=IP_PMTUDISC_DONT clear it on ordinary output, each such packet carrying an Identification leased from the same allocator, while their PLPMTUD probes keep DF. T12's owner route or path discovery disable (1191-093, the user's recorded decision B) leaves DF clear on every Host::udp_send and Host::udp_send_datagram UDP datagram and source fragment of the flagged IPv4 route, each with a leased Identification, under the RFC 1122 section 3.3.3 sending limit, so a datagram protocol that relies on fragmentation in the network has that DF-clear choice; the owner sets that flag with the ntcp-pathctl utility through the opt-in local control socket of the native runtime or tun_echo (T12 stage 6). The integration/rfc_host admin cases show it on the wire: after the ntcp-pathctl utility disables discovery on tun_echo's IPv4 path to one destination, every packet to it, source fragments of UDP replies included, leaves with DF clear and its own nonzero leased Identification, at most 576 octets through the Forwarder route or at most the owner's administrative value when one is set, while another destination through the same route keeps DF on its packets and fragments. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
//# We therefore believe that the IP layer should store PMTU information and that the ICMP layer should process received Datagram Too Big messages. The packetization layers must still be able to respond to changes in the Path MTU, by changing the size of the datagrams they send, and must also be able to specify that datagrams are sent with the DF bit set. We do not want the IP layer to simply set the DF bit in every packet, since it is possible that a packetization layer, perhaps a UDP application outside the kernel, is unable to change its datagram size. Protocols involving intentional fragmentation, while inelegant, are sometimes successful (NFS being the primary example), and we do not want to break such protocols.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=The suggested route flag is set through Host::administration and by the ntcp-pathctl utility. Outside flagged routes IPv4 packets carry DF (the atomic encoder and every source fragment) except the application-requested IP_PMTUDISC_DONT TCP output, each with an Identification leased from the Host allocator. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling holds output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). A DF-clear datagram is non-atomic, so such a route needs exactly these leased Identifications (RFC 6864). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases): after ntcp-pathctl disables discovery on an IPv4 route or path of tun_echo or the native runtime, every captured packet, TCP control segments and UDP source fragments included, has DF clear and its own nonzero leased Identification, at most 576 octets through a Forwarder route or at most the administrative value when one is set, while another destination through the same route keeps DF on its packets and fragments. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
//# The former can be accomplished by associating a flag with the routing entry; when a packet is sent via a route with this flag set, the IP layer leaves the DF bit clear no matter what the upper layer requests.
fn disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams() {
    let mut a = udp_side(9980);
    let (local, remote) = addresses(false);
    let remote = SocketAddr::new(remote.ip(), 7);
    let flow = a.0.udp_open(&a.1, local, Some(remote), UdpOptions { dscp: 0, hop_limit: 64 }).unwrap();
    let path = a.0.udp_path_limits(&a.1, flow, None).unwrap().path;
    let route = a.0.paths().path_snapshot(path).unwrap().key().route();
    let (result, sent) = udp_send_whole(&mut a, 5, flow, &[1; 1000]);
    assert_eq!(result, Ok(UdpSent::Submitted(1028)));
    assert_ne!(sent[0][6] & 0x40, 0, "an enabled route keeps DF");
    assert_eq!(u16::from_be_bytes([sent[0][4], sent[0][5]]), 0);

    set_route(&mut a, route, disabled(None), 10);
    assert_eq!(
        udp_send_whole(&mut a, 20, flow, &[2; 549]).0,
        Err(UdpSendError::TooBig { max_payload: 548 })
    );
    a.0.set_entropy(std::boxed::Box::new(|_: &mut [u8]| Err(EntropyError)));
    let (result, sent) = udp_send_whole(&mut a, 20, flow, &[2; 548]);
    assert_eq!(
        result,
        Err(UdpSendError::Backpressure(IdentifierBackpressure::Entropy))
    );
    assert!(sent.is_empty());
    a.0.set_entropy(std::boxed::Box::new(|out: &mut [u8]| {
        out.fill(0x33);
        Ok(())
    }));
    let mut seen = Vec::new();
    for (now, len) in [(MDL, 548), (MDL + 1, 100)] {
        let (result, sent) = udp_send_whole(&mut a, now, flow, &vec![3; len]);
        assert_eq!(result, Ok(UdpSent::Submitted(28 + len)));
        assert_eq!(sent.len(), 1);
        let id = assert_df_clear(&sent[0]);
        assert_ne!(id, 0);
        assert!(!seen.contains(&id), "one Identification per datagram");
        seen.push(id);
        assert_eq!(u16::from_be_bytes([sent[0][6], sent[0][7]]) & 0x3fff, 0);
    }

    set_route(
        &mut a,
        route,
        AdminPolicy {
            discovery_disabled: false,
            estimate: None,
        },
        MDL + 2,
    );
    let (result, sent) = udp_send_whole(&mut a, MDL + 3, flow, &[4; 1000]);
    assert_eq!(result, Ok(UdpSent::Submitted(1028)));
    assert_ne!(sent[0][6] & 0x40, 0);
    assert_eq!(u16::from_be_bytes([sent[0][4], sent[0][5]]), 0);
}

// Route isolation of the IPv4 policy: with a more specific neighbor route
// through the same link and next hop, disabling discovery on the default
// route leaves DF clear (with leased Identifications) on the fragments of a
// flow through it, under the 576-octet forwarder limit, while a flow
// through the neighbor route keeps DF on every source fragment at its own
// unchanged size. Disabling the neighbor instead reverses it.
#[test]
fn disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments() {
    let fragment = UdpSend {
        mode: UdpSendMode::Fragment,
        peer_capability: Some(4000),
    };
    let mut a = udp_side(9980);
    let (local, remote) = addresses(false);
    let remote = SocketAddr::new(remote.ip(), 7);
    let defaulted = a.0.udp_open(&a.1, local, Some(remote), UdpOptions { dscp: 0, hop_limit: 64 }).unwrap();
    let path = a.0.udp_path_limits(&a.1, defaulted, None).unwrap().path;
    let default_route = a.0.paths().path_snapshot(path).unwrap().key().route();
    let definition = a.0.paths().route_administration(default_route).unwrap().definition;
    let neighbor_route = a
        .0
        .add_route(path::Route {
            destination: path::IpPrefix::new("203.0.113.0".parse().unwrap(), 24).unwrap(),
            ..definition
        })
        .unwrap();
    let neighbor_peer = SocketAddr::new("203.0.113.7".parse().unwrap(), 7);
    let neighbor = a.0.udp_open(&a.1, local, Some(neighbor_peer), UdpOptions { dscp: 0, hop_limit: 64 }).unwrap();
    let neighbor_path = a.0.udp_path_limits(&a.1, neighbor, None).unwrap().path;
    assert_eq!(a.0.paths().path_snapshot(neighbor_path).unwrap().key().route(), neighbor_route);
    let mut now = 10;
    for (disabled_route, (off, on)) in [
        (default_route, (defaulted, neighbor)),
        (neighbor_route, (neighbor, defaulted)),
    ] {
        set_route(&mut a, disabled_route, disabled(None), now);
        let (result, sent) = udp_send(&mut a, now + 1, off, fragment, &[6; 1500]);
        let report = result.unwrap();
        assert!(sent.len() >= 3);
        for packet in &sent {
            assert!(packet.len() <= 576);
            assert_eq!(Some(u32::from(assert_df_clear(packet))), report.identification);
        }
        let (result, sent) = udp_send(&mut a, now + 2, on, fragment, &[7; 3000]);
        let report = result.unwrap();
        assert!(sent.len() > 1);
        for packet in &sent {
            assert!(packet.len() <= 1280);
            assert_ne!(packet[6] & 0x40, 0, "the neighbor route keeps DF on fragments");
            assert_eq!(ntcp_ip_common::checksum(&packet[..20]), 0);
        }
        assert!(report.identification.is_some());
        set_route(
            &mut a,
            disabled_route,
            AdminPolicy {
                discovery_disabled: false,
                estimate: None,
            },
            now + 3,
        );
        now += 10;
    }
}
