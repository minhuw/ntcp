// Host-derived receive MSS offers through the real managed factories: the
// least of reassembly capacity, the largest live link enabled for the family
// (at the smaller of its MTU and physical receive capacity) and the family
// wire limit, less the IP and TCP base headers.
use super::*;

#[derive(Clone, Copy)]
struct Link {
    mtu: u32,
    max_ip_packet: usize,
    ipv4: bool,
    ipv6: bool,
}
const fn link(mtu: u32, max_ip_packet: usize, ipv4: bool, ipv6: bool) -> Link {
    Link {
        mtu,
        max_ip_packet,
        ipv4,
        ipv6,
    }
}
const DUAL_1500: Link = link(1500, 65575, true, true);

fn reassembly(datagram: usize) -> ReassemblyLimits {
    ReassemblyLimits {
        assemblies: 1,
        fragments: 65575usize.div_ceil(8),
        buffered_bytes: 65575 + 8,
        ipv4_datagram: datagram.min(65535),
        ipv6_datagram: datagram.max(1500),
        ipv4_timeout_seconds: 60,
    }
}

// A Host whose first link carries the source and the default route; every
// further link only exists (and may be the largest).
fn side(
    local: SocketAddr,
    identity: u64,
    cfg: &EndpointConfig,
    links: &[Link],
    reassembly: Option<ReassemblyLimits>,
) -> ((Host, Endpoint, IngressContext), Vec<IngressContext>) {
    let (paths, mut limits) = managed_limits(cfg, 4, 2, 2, 4, 1).unwrap();
    if let Some(reassembly) = reassembly {
        limits.reassembly = reassembly;
    }
    let mut host = Host::new(
        ContextId::new(identity),
        paths,
        limits,
        cfg.connection.timebase,
        [1; 16],
    )
    .unwrap();
    let contexts: Vec<_> = links
        .iter()
        .enumerate()
        .map(|(n, l)| {
            host.register_link(
                InterfaceKey(n as u64 + 1),
                l.mtu,
                ReceiveCapabilities {
                    max_ip_packet: l.max_ip_packet,
                    ipv4: if l.ipv4 {
                        Ipv4Receive::Enabled {
                            interpretation: true,
                            source_routes: false,
                        }
                    } else {
                        Ipv4Receive::Disabled
                    },
                    ipv6: if l.ipv6 {
                        Ipv6Receive::BaseHeader
                    } else {
                        Ipv6Receive::Disabled
                    },
                    gro: true,
                },
                Forwarding::Forwarder(ForwarderId(9)),
            )
            .unwrap()
        })
        .collect();
    host.register_source(
        ScopedAddress::new(local.ip(), None).unwrap(),
        contexts[0].link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new(
            if local.is_ipv4() { "0.0.0.0" } else { "::" }
                .parse()
                .unwrap(),
            0,
        )
        .unwrap(),
        source: None,
        dscp: None,
        link: contexts[0].link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    })
    .unwrap();
    let mut endpoint = Endpoint::new(cfg.clone(), [identity as u8; 32], 0, |_| true).unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint.enable_output_reservations_with_capacity(1).unwrap();
    let first = contexts[0];
    ((host, endpoint, first), contexts)
}

// The MSS option of an emitted SYN or SYN-ACK, decoded from its bytes.
fn offered(frame: &[u8]) -> Option<u16> {
    let (source, destination, base) = if frame[0] >> 4 == 4 {
        let a: [u8; 4] = frame[12..16].try_into().unwrap();
        let b: [u8; 4] = frame[16..20].try_into().unwrap();
        (IpAddr::from(a), IpAddr::from(b), usize::from(frame[0] & 15) * 4)
    } else {
        let a: [u8; 16] = frame[8..24].try_into().unwrap();
        let b: [u8; 16] = frame[24..40].try_into().unwrap();
        (IpAddr::from(a), IpAddr::from(b), 40)
    };
    let segment = ntcp::wire::parse(
        IpMetadata {
            source,
            destination,
        },
        &frame[base..],
    )
    .unwrap();
    assert_ne!(segment.header.flags & ntcp::wire::SYN, 0);
    segment.options.mss
}

fn active_offer(
    side: &mut (Host, Endpoint, IngressContext),
    local: SocketAddr,
    remote: SocketAddr,
    options: ManagedOpenOptions,
    now: u64,
) -> (ConnectionId, u16) {
    let id = side
        .1
        .connect_with_path_provider(now, local, remote, options, &mut side.0)
        .unwrap();
    let syn = emit(&mut side.0, &mut side.1, now + 1).unwrap();
    (id, offered(&syn).unwrap())
}

fn base(v6: bool) -> u32 {
    if v6 { 60 } else { 40 }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Managed connections send the MSS this paragraph describes. T13 supplies the host capacity: Host::reassembly_capacity states, per family and per Host context, EMTU_R (RFC 1122 section 3.3.2: the largest complete IP datagram, header included, that the configured, storage-backed reassembly engine accepts) and MMS_R (EMTU_R - 20 for IPv4, EMTU_R - 40 for IPv6). This paragraph calls the largest reassemblable datagram MMS_R, so its host MMS_R-40 is EMTU_R - 40, that is RFC 1122's MMS_R less TCP's 20-octet header for IPv4; the TCP payload unit (MSS) differs from both EMTU_R and MMS_R. T16 derives the managed receive MSS inside every Host factory transaction (active, Fast Open, passive child and TIME-WAIT replacement): Host::receive_ip_capability takes the least of EMTU_R (no term while reassembly is disabled), the largest live link enabled for the family at the smaller of its current MTU and physical receive capacity (the permitted maximum connected-link choice: a multi-homed Host counts its largest link, not the selected route's) and the family wire limit, less the IP and TCP base headers, so 65495 is offered exactly when an actual 65535-octet IPv4 link and matching reassembly support it; only user and advertised caps reduce it, a discovered send PMTU never does, and the offer is frozen once committed in its SYN or SYN-ACK. Host factory tests (ntcp-host src/tests/receive_capability.rs) cover both families, unequal links with per-link family enablement, link addition, removal and MTU change, new listener children after a topology change, separate contexts and source replacement, reassembly below and above the links and disabled, physical capacity below a link MTU, the 65535-octet IPv4 link and rejection without a capability. The supplied managed embeddings keep no static receive sizing: native SYN and SYN-ACK offers follow the Host's link (ntcp-socket packet_tests.rs) and tun_echo's equal Host::receive_ip_capability (tun_echo_pmtu_tests.rs). On the wire, the integration/rfc_host mss case's production-factory driver (src/bin/two_link.rs) owns two TUNs of unequal MTU with genuine reassembly and routes over the smaller: in both families the captured SYN-ACK and SYN offers over the smaller link equal the larger link's derivation, also for connections opened after real downstream PTBs lowered the send PMTU. Raw Endpoints keep their documented caller-supplied receive limits as an explicit legacy contract, on which this closure does not rest. The optional link-derived choice is not itself a required feature.
//# in the MSS option. The MSS option should be 40 octets less than the size of the largest
//# datagram the host is able to reassemble (MMS_R, as defined in [1]); in many cases, this
//# will be the architectural limit of 65495 (65535 - 40) octets. A host MAY send an MSS
//# value derived from the MTU of its connected network (the maximum MTU over its connected
//# networks, for a multi-homed host); this should not cause problems for PMTU Discovery,
//# and may dissuade a broken peer from sending enormous datagrams.
#[test]
fn offer_is_largest_family_link_capped_by_physical_reassembly_and_wire_limits() {
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        // (links, reassembly, expected complete datagram)
        let cases: [(&[Link], Option<usize>, u32); 7] = [
            // Unequal MTUs; the larger enables only IPv4.
            (&[DUAL_1500, link(9000, 65575, true, false)], None, if v6 { 1500 } else { 9000 }),
            // The larger enables only IPv6.
            (&[DUAL_1500, link(4000, 65575, false, true)], None, if v6 { 4000 } else { 1500 }),
            // A backend that cannot receive its own MTU does not overstate it.
            (&[DUAL_1500, link(9000, 3000, true, true)], None, 3000),
            // Reassembly below the largest link.
            (&[DUAL_1500, link(9000, 65575, true, true)], Some(4096), 4096),
            // Reassembly above the largest link.
            (&[DUAL_1500], Some(8192), 1500),
            // The family wire limit below a jumbo link and reassembly.
            (
                &[DUAL_1500, link(70000, 65575, true, true)],
                Some(65575),
                if v6 { 65575 } else { 65535 },
            ),
            // Smaller-cap control: one octet below the largest link.
            (
                &[DUAL_1500, link(65534, 65575, true, true)],
                Some(65575),
                65534,
            ),
        ];
        for (links, limit, datagram) in cases {
            let mut a = side(local, 31, &cfg, links, limit.map(reassembly)).0;
            // The cases without a limit run with reassembly disabled.
            assert_eq!(a.0.reassembly_capacity(v6).is_none(), limit.is_none());
            let capability = a.0.receive_ip_capability(v6).unwrap();
            assert_eq!(capability.ip_packet(), datagram);
            assert_eq!(capability.context(), ContextId::new(31));
            // config.mss (1460, the send and allocation ceiling) does not
            // limit the managed offer.
            let (_, mss) = active_offer(&mut a, local, remote, options(&cfg, 0), 0);
            assert_eq!(u32::from(mss), datagram - base(v6), "{v6} {datagram}");
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Managed receive offers derive from Host::receive_ip_capability, never above the maximum MTU of the connected links enabled for the family (each counted at the smaller of its current MTU and physical receive capacity), nor above EMTU_R or the family wire limit. User disposition (decision A, 2026-11-04, recorded): 65495 is advertised only when this uncapped derivation supports it, that is with an actual 65535-octet IPv4 link and matching reassembly capacity; this paragraph's warning against unnecessary use of such a large MSS is read as not covering that capability-backed use, so no 65494 or other substitute ceiling applies, and any smaller link, physical receive or reassembly capacity gives a smaller offer. Host factory tests (ntcp-host src/tests/receive_capability.rs) offer 65495 on a 65535-octet IPv4 link with 65535-octet reassembly and 64960, 65494 and 65494 with 65000-octet reassembly, a 65534-octet physical receive capacity and a 65534-octet link; a smaller validated send PMTU leaves the offer unchanged. Raw Endpoint offers keep their configured receive_ip_payload_limit and MSS caps as an explicit legacy contract. No sign-bit bug is alleged.
//# Note: At the moment, we see no reason to send an MSS greater than the maximum MTU of the
//# connected networks, and we recommend that hosts do not use 65495. It is quite possible
//# that some IP implementations have sign-bit bugs that would be tickled by unnecessary use
//# of such a large MSS.
// RFC 1191 section 3.1's architectural 65495 is offered when an actual
// 65535-octet IPv4 link and matching reassembly support it; any smaller
// capability gives a smaller offer, and no other ceiling substitutes.
#[test]
fn ipv4_65535_link_with_matching_reassembly_offers_65495_and_smaller_caps_do_not() {
    let cfg = config(4);
    let (local, remote) = addresses(false);
    for (mtu, max_ip_packet, limit, mss) in [
        (65535, 65535, 65535, 65495),
        (65535, 65535, 65000, 64960),
        (65535, 65534, 65535, 65494),
        (65534, 65535, 65535, 65494),
    ] {
        let mut a = side(
            local,
            32,
            &cfg,
            &[link(mtu, max_ip_packet, true, false)],
            Some(reassembly(limit)),
        )
        .0;
        assert_eq!(a.0.reassembly_capacity(false).unwrap().emtu_r, limit as u32);
        assert_eq!(active_offer(&mut a, local, remote, options(&cfg, 0), 0).1, mss);
    }
}

#[test]
fn user_and_advertised_caps_compose_with_derived_offer() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let mut cfg = config(4);
        let links = [DUAL_1500, link(9000, 65575, true, true)];
        let derived = 9000 - base(v6) as u16;
        let mut a = side(local, 33, &cfg, &links, None).0;
        let mut open = options(&cfg, 0);
        open.transport.user_mss = Some(3000);
        assert_eq!(active_offer(&mut a, local, remote, open, 0).1, 3000);

        // A user MSS set before the SYN commits composes with the stored
        // capability; once committed, the offer no longer changes.
        let mut a = side(local, 33, &cfg, &links, None).0;
        let id =
            a.1.connect_with_path_provider(10, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        a.1.set_user_mss(id, Some(2000)).unwrap();
        assert_eq!(offered(&emit(&mut a.0, &mut a.1, 11).unwrap()), Some(2000));
        a.1.set_user_mss(id, Some(500)).unwrap();
        let retry = a.1.next_deadline().unwrap();
        a.1.on_timeout(retry, 8).unwrap();
        assert_eq!(offered(&emit(&mut a.0, &mut a.1, retry).unwrap()), Some(2000));
        // Clearing it before commitment restores the derivation, not config.mss.
        let mut a = side(local, 33, &cfg, &links, None).0;
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        a.1.set_user_mss(id, Some(2000)).unwrap();
        a.1.set_user_mss(id, None).unwrap();
        let syn = emit(&mut a.0, &mut a.1, 1).unwrap();
        assert_eq!(offered(&syn), Some(derived));

        cfg.connection.advertised_mss = Some(4000);
        let mut b = side(local, 34, &cfg, &links, None).0;
        assert_eq!(active_offer(&mut b, local, remote, options(&cfg, 0), 0).1, 4000);
        // config.mss below the derivation still does not limit the offer.
        cfg.connection.advertised_mss = None;
        cfg.connection.mss = 1000;
        let mut c = side(local, 35, &cfg, &links, None).0;
        let (id, mss) = active_offer(&mut c, local, remote, options(&cfg, 0), 0);
        assert_eq!(mss, derived);
        assert!(c.1.transport_info(id).unwrap().mss <= 1000);
    }
}

// Every new connection reads current link facts; a committed offer stays
// frozen across SYN retransmission, link changes and a lower validated send
// PMTU, which never shrinks it.
#[test]
fn new_connections_follow_link_changes_and_committed_offers_stay_frozen() {
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, _) = side(local, 41, &cfg, &[DUAL_1500], None);
        // A lower validated send PMTU on the selected path.
        learn(&mut a.0, local, remote, 0, if v6 { 1280 } else { 1100 });
        let (first, mss) = active_offer(&mut a, local, remote, options(&cfg, 0), 0);
        assert_eq!(u32::from(mss), 1500 - base(v6));
        assert!(a.1.transport_info(first).unwrap().mss < 1500 - base(v6));

        // Link addition: a larger link (no route uses it).
        let big = a
            .0
            .register_link(
                InterfaceKey(7),
                9000,
                ReceiveCapabilities {
                    max_ip_packet: 65575,
                    ipv4: Ipv4Receive::Enabled {
                        interpretation: false,
                        source_routes: false,
                    },
                    ipv6: Ipv6Receive::BaseHeader,
                    gro: false,
                },
                Forwarding::Forwarder(ForwarderId(9)),
            )
            .unwrap();
        let retry = a.1.next_deadline().unwrap();
        a.1.on_timeout(retry, 8).unwrap();
        let again = emit(&mut a.0, &mut a.1, retry).unwrap();
        assert_eq!(offered(&again), Some(mss), "frozen across SYN retransmission");
        let second = SocketAddr::new(remote.ip(), 9001);
        let (_, grown) = active_offer(&mut a, local, second, options(&cfg, 0), retry + 1);
        assert_eq!(u32::from(grown), 9000 - base(v6));

        // MTU change of that link.
        a.0.set_link_mtu(big.link(), 4000).unwrap();
        let third = SocketAddr::new(remote.ip(), 9002);
        let (_, changed) = active_offer(&mut a, local, third, options(&cfg, 0), retry + 2);
        assert_eq!(u32::from(changed), 4000 - base(v6));

        // Removal.
        a.0.remove_link(big).unwrap();
        assert_eq!(
            a.0.receive_ip_capability(v6).unwrap().ip_packet(),
            1500
        );
    }
}

#[test]
fn passive_fast_open_and_time_wait_children_derive_current_offers() {
    for v6 in [false, true] {
        let mut cfg = config(2);
        cfg.reuse_time_wait = true;
        cfg.connection.timestamps = false;
        let (local, remote) = addresses(v6);
        let (mut a, contexts) = side(
            local,
            51,
            &cfg,
            &[DUAL_1500, link(9000, 65575, true, true)],
            None,
        );
        let mut b = managed(remote, 52, cfg.clone());
        let listener = a.1.listen(local, 2).unwrap();
        let peer =
            b.1.connect_with_path_provider(0, remote, local, options(&cfg, 0), &mut b.0)
                .unwrap();
        let syn = emit(&mut b.0, &mut b.1, 1).unwrap();
        input(&mut a.0, &mut a.1, a.2, 2, &syn, 0);
        let synack = emit(&mut a.0, &mut a.1, 3).unwrap();
        assert_eq!(offered(&synack).map(u32::from), Some(9000 - base(v6)));
        input(&mut b.0, &mut b.1, b.2, 4, &synack, 0);
        let mut now = 10;
        pump(&mut a, &mut b, &mut now);
        let old = a.1.accept(listener).unwrap();

        // TIME-WAIT replacement after a link MTU change uses the new facts.
        a.1.shutdown(old).unwrap();
        pump(&mut a, &mut b, &mut now);
        b.1.shutdown(peer).unwrap();
        pump(&mut a, &mut b, &mut now);
        assert_eq!(a.1.state(old).unwrap(), State::TimeWait);
        a.1.release(old).unwrap();
        b.1.release(peer).unwrap();
        a.0.collect(&a.1).unwrap();
        b.0.collect(&b.1).unwrap();
        a.0.set_link_mtu(contexts[1].link(), 6000).unwrap();
        now += 1_000_000;
        b.1.connect_with_path_provider(now, remote, local, options(&cfg, 0), &mut b.0)
            .unwrap();
        let syn = emit(&mut b.0, &mut b.1, now + 1).unwrap();
        input(&mut a.0, &mut a.1, a.2, now + 2, &syn, 0);
        let current = a.1.connection_id(Tuple { local, remote }).unwrap();
        assert_ne!(current, old);
        let synack = emit(&mut a.0, &mut a.1, now + 3).unwrap();
        assert_eq!(offered(&synack).map(u32::from), Some(6000 - base(v6)));

        // Fast Open active open.
        let (mut c, _) = side(
            local,
            53,
            &cfg,
            &[DUAL_1500, link(5000, 65575, true, true)],
            None,
        );
        c.1.enable_fast_open().unwrap();
        c.1.connect_fast_open_with_path_provider(
            0,
            local,
            remote,
            &[7; 100],
            options(&cfg, 0),
            None,
            FastOpenClientPolicy::ApplicationProtected,
            &mut c.0,
        )
        .unwrap();
        let syn = emit(&mut c.0, &mut c.1, 1).unwrap();
        assert_eq!(offered(&syn).map(u32::from), Some(5000 - base(v6)));
    }
}

// A new child of an existing listener reads the link facts current at its
// own SYN.
#[test]
fn listener_children_after_topology_change_use_current_links() {
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, contexts) = side(
            local,
            61,
            &cfg,
            &[DUAL_1500, link(9000, 65575, true, true)],
            None,
        );
        a.1.listen(local, 4).unwrap();
        let mut b = managed(remote, 62, cfg.clone());
        let mut offers = Vec::new();
        for (n, change) in [None, Some(3000), Some(0)].into_iter().enumerate() {
            match change {
                Some(0) => a.0.remove_link(contexts[1]).unwrap(),
                Some(mtu) => a.0.set_link_mtu(contexts[1].link(), mtu).unwrap(),
                None => {}
            }
            let now = 10 * n as u64;
            let from = SocketAddr::new(remote.ip(), 2000 + n as u16);
            b.1.connect_with_path_provider(now, from, local, options(&cfg, 0), &mut b.0)
                .unwrap();
            let syn = emit(&mut b.0, &mut b.1, now + 1).unwrap();
            input(&mut a.0, &mut a.1, a.2, now + 2, &syn, 0);
            let synack = emit(&mut a.0, &mut a.1, now + 3).unwrap();
            offers.push(offered(&synack).unwrap() as u32 + base(v6));
        }
        assert_eq!(offers, [9000, 3000, 1500]);
    }
}

// Without a receive capability for the family, or with one below the base
// headers and one payload octet, nothing is constructed and nothing stays
// acquired; a capability of another context or family is refused too.
#[test]
fn missing_or_mismatched_capability_rejects_construction_without_leaks() {
    struct Swapped<'a> {
        host: &'a mut Host,
        receive: ntcp::ReceiveIpCapability,
    }
    impl PathProvider for Swapped<'_> {
        type Error = Error;
        fn prepare(&mut self, request: PathFactoryRequest) -> Result<ntcp::PreparedFactory, Error> {
            let mut prepared = self.host.prepare(request)?;
            prepared.receive = self.receive;
            Ok(prepared)
        }
        fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId) {
            self.host.commit(prepared, connection);
        }
        fn cancel(&mut self, prepared: PreparedPath) {
            self.host.cancel(prepared);
        }
    }
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        for only in [
            // The only link enables just the other family.
            link(1500, 65575, v6, !v6),
            // Physically unable to receive the base headers and one octet.
            link(1500, base(v6) as usize, true, true),
        ] {
            let (mut a, _) = side(local, 71, &cfg, &[only], None);
            assert_eq!(a.0.receive_ip_capability(v6), Err(Error::Unsupported));
            assert_eq!(
                a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0),
                Err(ManagedError::Provider(Error::Unsupported))
            );
            assert_eq!(a.0.binding_count(), 0);
            assert_eq!(a.0.paths().usage().clients, 0);
            assert!(a.1.connection_id(Tuple { local, remote }).is_none());
        }
        let (mut a, _) = side(local, 72, &cfg, &[DUAL_1500], None);
        for receive in [
            ntcp::ReceiveIpCapability::new(ContextId::new(73), v6, 1500).unwrap(),
            ntcp::ReceiveIpCapability::new(ContextId::new(72), !v6, 1500).unwrap(),
        ] {
            let mut provider = Swapped {
                host: &mut a.0,
                receive,
            };
            assert_eq!(
                a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut provider),
                Err(ManagedError::Endpoint(EndpointError::Connection(
                    ntcp::Error::InvalidArgument
                )))
            );
            assert_eq!(a.0.binding_count(), 0);
            assert_eq!(a.0.paths().usage().clients, 0);
        }
        assert_eq!(
            active_offer(&mut a, local, remote, options(&cfg, 0), 0).1 as u32,
            1500 - base(v6)
        );
    }
}

// Separate Host contexts derive from their own links; a replaced source
// generation or a different source address takes a new connection, which
// derives the current offer while the existing one keeps its own.
#[test]
fn separate_contexts_and_source_replacement_derive_per_connection() {
    let cfg = config(4);
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, contexts) = side(
            local,
            81,
            &cfg,
            &[DUAL_1500, link(9000, 65575, true, true)],
            None,
        );
        let (mut b, _) = side(local, 82, &cfg, &[DUAL_1500], None);
        let (first, mss) = active_offer(&mut a, local, remote, options(&cfg, 0), 0);
        assert_eq!(u32::from(mss), 9000 - base(v6));
        assert_eq!(
            u32::from(active_offer(&mut b, local, remote, options(&cfg, 0), 0).1),
            1500 - base(v6)
        );
        assert_eq!(a.0.receive_ip_capability(v6).unwrap().context(), ContextId::new(81));
        assert_eq!(b.0.receive_ip_capability(v6).unwrap().context(), ContextId::new(82));

        a.0.set_link_mtu(contexts[1].link(), 2000).unwrap();
        let source = a.0.binding(first).unwrap().snapshot.key().source();
        a.0.remove_source_owner(source, contexts[0].link()).unwrap();
        let replacement = a
            .0
            .register_source(ScopedAddress::new(local.ip(), None).unwrap(), contexts[0].link())
            .unwrap();
        assert_ne!(replacement, source);
        let other_ip: IpAddr = if v6 {
            "2001:db8::3".parse().unwrap()
        } else {
            "192.0.2.3".parse().unwrap()
        };
        a.0.register_source(ScopedAddress::new(other_ip, None).unwrap(), contexts[0].link())
            .unwrap();
        // The existing connection keeps its committed offer on its new
        // source generation.
        let retry = a.1.next_deadline().unwrap();
        a.1.on_timeout(retry, 8).unwrap();
        assert_eq!(offered(&emit(&mut a.0, &mut a.1, retry).unwrap()), Some(mss));
        assert_eq!(a.0.binding(first).unwrap().snapshot.key().source(), replacement);
        let same = SocketAddr::new(local.ip(), 1001);
        let (_, renewed) = active_offer(&mut a, same, remote, options(&cfg, 0), retry + 1);
        assert_eq!(u32::from(renewed), 2000 - base(v6));
        let changed = SocketAddr::new(other_ip, 1000);
        let (_, moved) = active_offer(&mut a, changed, remote, options(&cfg, 0), retry + 2);
        assert_eq!(u32::from(moved), 2000 - base(v6));
    }
}
