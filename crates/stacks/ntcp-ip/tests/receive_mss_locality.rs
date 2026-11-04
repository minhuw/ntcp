use ntcp::{
    AddressValidation, ConnectionConfig, Endpoint, EndpointConfig, InitialWindow, PmtudConfig,
    Tuple, wire,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn endpoint(config: ConnectionConfig, address: IpAddr, secret: u8) -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            connection: config,
            ..Default::default()
        },
        [secret; 32],
        0,
        move |request| match request {
            AddressValidation::Bind { local } | AddressValidation::Open { local, .. } => {
                local == address
            }
            AddressValidation::Incoming { destination, .. } => destination == address,
            AddressValidation::Route { source, .. } => source == address,
        },
    )
    .unwrap()
}

fn frame(endpoint: &mut Endpoint, now: u64) -> Vec<u8> {
    let mut bytes = vec![0; 10000];
    let tx = endpoint
        .poll_transmit(now, &mut bytes[20..], 64)
        .unwrap()
        .packet
        .expect("wire packet");
    let n = ntcp_ip::encode(&mut bytes, tx, 0).unwrap();
    bytes.truncate(n);
    let p = ntcp_ip::parse(&bytes, false).unwrap();
    assert_eq!(wire::checksum(p.ip, p.payload).unwrap(), 0);
    bytes
}

fn input(endpoint: &mut Endpoint, bytes: &[u8], now: u64) {
    let p = ntcp_ip::parse(bytes, false).unwrap();
    endpoint.input(now, p.ip, p.payload).unwrap();
}

// The fixture's authoritative topology is a /24 on each endpoint. The second
// case is routable through 192.0.2.254 and 198.51.100.254; the harness carries
// frames across that modeled path. Endpoint's address policy accepts only its
// own address. TCP receives neither a subnet mask nor a routing-table lookup.
//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=The receive offer is captured without routing-locality input: a managed connection's from its Host's per-family receive capability, a raw Endpoint's from configured receive ceilings, both intersected with user/advertised caps. Public Endpoint tests use authoritative single-address policies and equivalent /24 local/routed topologies, compare actual codec SYN/SYNACK offers above536 under four identical configurations, and retain receive capability after validated lower send-PMTU feedback in both directions. The continuation's host receive sizing and the connected-network note are covered separately at1191-024/025.
//# Moreover, doing this prevents PMTU Discovery from discovering PMTUs larger than 576, so hosts SHOULD no longer lower the value they send

//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Managed connections send the MSS this paragraph describes. T13 supplies the host capacity: Host::reassembly_capacity states, per family and per Host context, EMTU_R (RFC 1122 section 3.3.2: the largest complete IP datagram, header included, that the configured, storage-backed reassembly engine accepts) and MMS_R (EMTU_R - 20 for IPv4, EMTU_R - 40 for IPv6). This paragraph calls the largest reassemblable datagram MMS_R, so its host MMS_R-40 is EMTU_R - 40, that is RFC 1122's MMS_R less TCP's 20-octet header for IPv4; the TCP payload unit (MSS) differs from both EMTU_R and MMS_R. T16 derives the managed receive MSS inside every Host factory transaction (active, Fast Open, passive child and TIME-WAIT replacement): Host::receive_ip_capability takes the least of EMTU_R (no term while reassembly is disabled), the largest live link enabled for the family at the smaller of its current MTU and physical receive capacity (the permitted maximum connected-link choice: a multi-homed Host counts its largest link, not the selected route's) and the family wire limit, less the IP and TCP base headers, so 65495 is offered exactly when an actual 65535-octet IPv4 link and matching reassembly support it; only user and advertised caps reduce it, a discovered send PMTU never does, and the offer is frozen once committed in its SYN or SYN-ACK. Host factory tests (ntcp-host src/tests/receive_capability.rs) cover both families, unequal links with per-link family enablement, link addition, removal and MTU change, new listener children after a topology change, separate contexts and source replacement, reassembly below and above the links and disabled, physical capacity below a link MTU, the 65535-octet IPv4 link and rejection without a capability. The supplied managed embeddings keep no static receive sizing: native SYN and SYN-ACK offers follow the Host's link (ntcp-socket packet_tests.rs) and tun_echo's equal Host::receive_ip_capability (tun_echo_pmtu_tests.rs). On the wire, the integration/rfc_host mss case's production-factory driver (src/bin/two_link.rs) owns two TUNs of unequal MTU with genuine reassembly and routes over the smaller: in both families the captured SYN-ACK and SYN offers over the smaller link equal the larger link's derivation, also for connections opened after real downstream PTBs lowered the send PMTU. Raw Endpoints keep their documented caller-supplied receive limits as an explicit legacy contract, on which this closure does not rest. The optional link-derived choice is not itself a required feature.
//# in the MSS option. The MSS option should be 40 octets less than the size of the largest datagram the host is able to reassemble (MMS_R, as defined in [1]); in many cases, this will be the architectural limit of 65495 (65535 - 40) octets. A host MAY send an MSS value derived from the MTU of its connected network (the maximum MTU over its connected networks, for a multi-homed host); this should not cause problems for PMTU Discovery, and may dissuade a broken peer from sending enormous datagrams.
#[test]
fn equivalent_local_and_routed_peers_keep_active_and_passive_receive_mss() {
    let local: SocketAddr = "192.0.2.1:40000".parse().unwrap();
    for (user_mss, advertised_mss, receive_limit, expected) in [
        (None, None, 6020, 4096),
        (Some(3000), None, 6020, 3000),
        (None, Some(2800), 6020, 2800),
        (Some(3000), Some(2800), 2420, 2400),
    ] {
        let config = ConnectionConfig {
            mss: 4096,
            user_mss,
            advertised_mss,
            receive_ip_payload_limit: receive_limit,
            pmtud: Some(PmtudConfig::new(9000)),
            initial_window: InitialWindow::Iw10,
            nagle: false,
            delayed_ack_us: 0,
            ..Default::default()
        };
        let mut offers = Vec::new();
        for (remote_ip, same_subnet) in [
            (Ipv4Addr::new(192, 0, 2, 2), true),
            (Ipv4Addr::new(198, 51, 100, 2), false),
        ] {
            let remote = SocketAddr::new(remote_ip.into(), 8080);
            let IpAddr::V4(local_ip) = local.ip() else {
                unreachable!()
            };
            assert_eq!(
                local_ip.octets()[..3] == remote_ip.octets()[..3],
                same_subnet
            );
            let mut a = endpoint(config.clone(), local.ip(), 1);
            let mut b = endpoint(config.clone(), remote.ip(), 2);
            let listener = b.listen(remote, 4).unwrap();
            let id = a.connect(0, local, remote).unwrap();
            let syn = frame(&mut a, 1);
            let p = ntcp_ip::parse(&syn, false).unwrap();
            assert_eq!((p.ip.source, p.ip.destination), (local.ip(), remote.ip()));
            let tcp = wire::parse(p.ip, p.payload).unwrap();
            assert_eq!(tcp.header.flags & (wire::SYN | wire::ACK), wire::SYN);
            let active_offer = tcp.options.mss.unwrap();
            input(&mut b, &syn, 1);
            let synack = frame(&mut b, 2);
            let p = ntcp_ip::parse(&synack, false).unwrap();
            assert_eq!((p.ip.source, p.ip.destination), (remote.ip(), local.ip()));
            let tcp = wire::parse(p.ip, p.payload).unwrap();
            assert_eq!(
                tcp.header.flags & (wire::SYN | wire::ACK),
                wire::SYN | wire::ACK
            );
            let passive_offer = tcp.options.mss.unwrap();
            assert_eq!((active_offer, passive_offer), (expected, expected));
            assert!(expected > 536);
            offers.push((active_offer, passive_offer));
            input(&mut a, &synack, 2);
            input(&mut b, &frame(&mut a, 3), 3);
            let peer = b.accept(listener).unwrap();
            // A validated report about actual output lowers each direction's
            // send PMTU while retaining its already committed receive offer.
            for (sender, sender_id, source, destination) in
                [(&mut a, id, local, remote), (&mut b, peer, remote, local)]
            {
                sender.write(sender_id, &[0x5a; 10000]).unwrap();
                let data = frame(sender, 4);
                let p = ntcp_ip::parse(&data, false).unwrap();
                let tcp = wire::parse(p.ip, p.payload).unwrap();
                assert!(data.len() > 576);
                assert!(
                    sender
                        .pmtu_feedback(
                            5,
                            Tuple {
                                local: source,
                                remote: destination
                            },
                            tcp.header.sequence,
                            data.len() as u32,
                            20,
                            576,
                        )
                        .unwrap()
                );
                assert_eq!(
                    sender
                        .path_mtu_info(sender_id)
                        .unwrap()
                        .unwrap()
                        .current_mtu,
                    576
                );
                assert_eq!(
                    sender.transport_info(sender_id).unwrap().advertised_mss,
                    u32::from(expected)
                );
            }
        }
        assert_eq!(
            offers[0], offers[1],
            "equivalent configuration across /24 boundaries"
        );
    }
}
