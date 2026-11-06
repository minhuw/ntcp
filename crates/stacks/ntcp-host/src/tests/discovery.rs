// Neighbor Discovery through the Host: an ND-capable port's addresses under
// DAD, NS/NA ingress by `Host::receive`, control output by
// `neighbor_output` and its completion, and `service_neighbors`.
use super::*;
use alloc::boxed::Box;
use core::net::Ipv6Addr;
use ntcp_icmp::{NeighborAdvertisement, NeighborSolicitation};

const SECOND: u64 = 1_000_000;
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 0xa];

fn own() -> Ipv6Addr {
    "fe80::1".parse().unwrap()
}
fn peer() -> Ipv6Addr {
    "fe80::a".parse().unwrap()
}
fn receive() -> ReceiveCapabilities {
    ReceiveCapabilities {
        max_ip_packet: 1500,
        ipv4: Ipv4Receive::Disabled,
        ipv6: Ipv6Receive::Extensions,
        gro: false,
    }
}
fn nd_host(dad_transmits: u8) -> (Host, LinkId) {
    nd_host_with(NdPort {
        dad_transmits,
        ..NdPort::new(OWN)
    })
}
fn nd_host_with(port: NdPort) -> (Host, LinkId) {
    let cfg = config(1);
    let (paths, mut limits) = managed_limits(&cfg, 1, 2, 2, 2, 0).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 2,
        pending_packets: 2,
        addresses: 2,
        answers: 2,
    };
    let mut host = Host::new(ContextId::new(41), paths, limits, cfg.connection.timebase).unwrap();
    // ReachableTime and DAD delays need entropy.
    assert_eq!(
        host.register_neighbor_port(InterfaceKey(1), 1500, receive(), port)
            .map(|_| ()),
        Err(Error::Entropy)
    );
    host.set_entropy(Box::new(|out: &mut [u8]| {
        out.fill(0);
        out[0] = 0x80;
        Ok(())
    }));
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, receive(), port)
        .unwrap();
    (host, context.link())
}
// One ND packet as it arrives: `hop_limit`, optionally in an atomic
// fragment.
fn packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop_limit: u8,
    message: &[u8],
    atomic: bool,
) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(source),
        destination: IpAddr::V6(destination),
    };
    let extra = if atomic { 8 } else { 0 };
    let mut out = vec![0; 40 + extra + message.len()];
    out[40 + extra..].copy_from_slice(message);
    let header = ntcp_ip6::Header {
        ip,
        hop_limit,
        dscp: 0,
        ecn: 0,
    };
    if atomic {
        out[40..48].copy_from_slice(&[58, 0, 0, 0, 0, 0, 0, 7]);
        ntcp_ip6::encode_datagram(&mut out, header, 44, 8 + message.len()).unwrap_err();
        // A Fragment header is an extension header the encoder refuses to
        // emit; write the base header by hand.
        out[0] = 0x60;
        out[4..6].copy_from_slice(&((8 + message.len()) as u16).to_be_bytes());
        out[6] = 44;
        out[7] = hop_limit;
        out[8..24].copy_from_slice(&source.octets());
        out[24..40].copy_from_slice(&destination.octets());
    } else {
        ntcp_ip6::encode_datagram(&mut out, header, 58, message.len()).unwrap();
    }
    out
}
fn solicitation(source: Ipv6Addr, destination: Ipv6Addr, ns: NeighborSolicitation) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(source),
        destination: IpAddr::V6(destination),
    };
    let mut message = [0; 32];
    let len = ntcp_icmp::encode_solicitation(ip, ns, &mut message).unwrap();
    message[..len].to_vec()
}
fn advertisement(destination: Ipv6Addr, na: NeighborAdvertisement) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(peer()),
        destination: IpAddr::V6(destination),
    };
    let mut message = [0; 32];
    let len = ntcp_icmp::encode_advertisement(ip, na, &mut message).unwrap();
    message[..len].to_vec()
}
fn input(host: &mut Host, link: LinkId, now: Instant, frame: &[u8]) -> Result<bool, Error> {
    let context = host.ingress_context(link).unwrap();
    let mut out = [0; 1500];
    host.receive(context, now, frame, false, &mut out)
        .map(|r| matches!(r, Received::Neighbor))
}
// The next ND transmission: link-layer destination and decoded message.
fn output(
    host: &mut Host,
    link: LinkId,
    now: Instant,
) -> Option<(
    [u8; 6],
    ntcp::IpMetadata,
    ntcp_icmp::NeighborMessage,
    NeighborTicket,
)> {
    let mut out = [0; 128];
    let transmit = host.neighbor_output(link, now, &mut out).unwrap()?;
    let frame = &out[..transmit.len];
    assert_eq!(frame[7], 255);
    let packet = ntcp_ip6::parse(frame).unwrap();
    let message = ntcp_icmp::decode_neighbor(packet.ip, 255, packet.payload).unwrap();
    Some((transmit.destination, packet.ip, message, transmit.ticket))
}
fn owned(host: &Host, link: LinkId) -> bool {
    host.paths()
        .local_source(
            ScopedAddress::new(IpAddr::V6(own()), Some(link)).unwrap(),
            link,
        )
        .is_ok()
}

#[test]
fn dad_publishes_the_address_only_after_its_final_probe() {
    let (mut host, link) = nd_host(1);
    // ND-capable ports never publish an IPv6 source at once.
    assert_eq!(
        host.register_source(
            ScopedAddress::new(IpAddr::V6(own()), Some(link)).unwrap(),
            link
        ),
        Err(Error::Unsupported)
    );
    assert_eq!(
        host.add_neighbor_address(link, own()),
        Ok(AddressState::Tentative)
    );
    assert!(!owned(&host, link));
    // Nothing is probed before the groups are joined.
    assert!(output(&mut host, link, 10 * SECOND).is_none());
    host.neighbor_membership_ready(link, own(), 0).unwrap();
    assert!(output(&mut host, link, SECOND / 2 - 1).is_none());
    let (mac, ip, message, ticket) = output(&mut host, link, SECOND / 2).unwrap();
    let group: Ipv6Addr = "ff02::1:ff00:1".parse().unwrap();
    assert_eq!(mac, [0x33, 0x33, 0xff, 0, 0, 1]);
    assert_eq!(
        (ip.source, ip.destination),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6(group))
    );
    assert_eq!(
        message,
        ntcp_icmp::NeighborMessage::Solicitation(NeighborSolicitation {
            target: own(),
            source_link_layer: None,
        })
    );
    // A blocked probe neither counts nor completes DAD.
    host.complete_neighbor_output(ticket, BackendOutcome::WouldBlock, SECOND / 2)
        .unwrap();
    assert_eq!(host.service_neighbors(10 * SECOND).assigned, 0);
    let (.., ticket) = output(&mut host, link, SECOND).unwrap();
    host.complete_neighbor_output(ticket, BackendOutcome::Submitted, SECOND)
        .unwrap();
    assert!(output(&mut host, link, SECOND).is_none());
    assert_eq!(host.next_neighbor_deadline(), Some(2 * SECOND));
    assert_eq!(host.service_neighbors(2 * SECOND - 1).assigned, 0);
    assert!(!owned(&host, link));
    assert_eq!(host.service_neighbors(2 * SECOND).assigned, 1);
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Assigned)
    );
    assert!(owned(&host, link));
}

#[test]
fn tentative_addresses_are_never_answered_and_fail_on_duplicates() {
    let (mut host, link) = nd_host(1);
    host.add_neighbor_address(link, own()).unwrap();
    host.neighbor_membership_ready(link, own(), 0).unwrap();
    let group = ntcp_ethernet::solicited_node(own());
    // A resolution solicitation for the tentative address is ignored.
    let ns = NeighborSolicitation {
        target: own(),
        source_link_layer: Some(PEER),
    };
    let frame = packet(peer(), group, 255, &solicitation(peer(), group, ns), false);
    assert_eq!(input(&mut host, link, 0, &frame), Ok(true));
    assert_eq!(host.neighbor(link, peer()), None);
    // Another node's DAD probe for it fails DAD; the address stays unusable.
    let dad = NeighborSolicitation {
        target: own(),
        source_link_layer: None,
    };
    let unspecified = Ipv6Addr::UNSPECIFIED;
    let frame = packet(
        unspecified,
        group,
        255,
        &solicitation(unspecified, group, dad),
        false,
    );
    assert_eq!(input(&mut host, link, 0, &frame), Ok(true));
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Duplicate)
    );
    assert!(output(&mut host, link, 10 * SECOND).is_none());
    // The owner's next pass reports the failure, once.
    let failed = NeighborReport {
        assigned: 0,
        duplicates: 1,
        first_error: None,
    };
    assert_eq!(host.service_neighbors(10 * SECOND), failed);
    assert_eq!(
        host.service_neighbors(10 * SECOND),
        NeighborReport::default()
    );
    assert!(!owned(&host, link));

    // A valid advertisement for a tentative address fails it as well.
    let (mut host, link) = nd_host(1);
    host.add_neighbor_address(link, own()).unwrap();
    let all_nodes = ntcp_ethernet::IPV6_ALL_NODES;
    let claim = NeighborAdvertisement {
        router: false,
        solicited: false,
        override_: true,
        target: own(),
        target_link_layer: Some(PEER),
    };
    let frame = packet(
        peer(),
        all_nodes,
        255,
        &advertisement(all_nodes, claim),
        false,
    );
    assert_eq!(input(&mut host, link, 0, &frame), Ok(true));
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Duplicate)
    );
    assert_eq!(host.service_neighbors(0).duplicates, 1);
}

#[test]
fn assigned_addresses_answer_solicitations_and_learn_the_sender() {
    let (mut host, link) = nd_host(0);
    assert_eq!(
        host.add_neighbor_address(link, own()),
        Ok(AddressState::Assigned)
    );
    assert!(owned(&host, link));
    let group = ntcp_ethernet::solicited_node(own());
    let ns = NeighborSolicitation {
        target: own(),
        source_link_layer: Some(PEER),
    };
    let message = solicitation(peer(), group, ns);
    // Not Neighbor Discovery: a forwarded (Hop Limit 254) message, and one
    // in an atomic fragment (RFC 6980).
    let forwarded = packet(peer(), group, 254, &message, false);
    assert_eq!(
        input(&mut host, link, 0, &forwarded),
        Err(Error::Codec(ntcp_ip::Error::Invalid))
    );
    let fragmented = packet(peer(), group, 255, &message, true);
    assert_eq!(
        input(&mut host, link, 0, &fragmented),
        Err(Error::Codec(ntcp_ip::Error::FragmentationUnsupported))
    );
    // A group of no configured address is not this host's.
    let other = ntcp_ethernet::solicited_node("fe80::77".parse().unwrap());
    let elsewhere = packet(peer(), other, 255, &solicitation(peer(), other, ns), false);
    assert_eq!(
        input(&mut host, link, 0, &elsewhere),
        Err(Error::Path(path::Error::NoRoute))
    );
    assert_eq!(
        (
            host.neighbor(link, peer()),
            output(&mut host, link, 0).is_none()
        ),
        (None, true)
    );

    let frame = packet(peer(), group, 255, &message, false);
    assert_eq!(host.next_neighbor_deadline(), None);
    assert_eq!(input(&mut host, link, 0, &frame), Ok(true));
    assert_eq!(
        host.neighbor(link, peer()),
        Some((NeighborState::Stale, Some(PEER), false))
    );
    // The queued answer is due at once, though a STALE entry has no timer.
    assert_eq!(host.next_neighbor_deadline(), Some(0));
    let (mac, ip, message, ticket) = output(&mut host, link, 0).unwrap();
    assert_eq!(mac, PEER);
    assert_eq!(
        (ip.source, ip.destination),
        (IpAddr::V6(own()), IpAddr::V6(peer()))
    );
    assert_eq!(
        message,
        ntcp_icmp::NeighborMessage::Advertisement(NeighborAdvertisement {
            router: false,
            solicited: true,
            override_: true,
            target: own(),
            target_link_layer: Some(OWN),
        })
    );
    host.complete_neighbor_output(ticket, BackendOutcome::Submitted, 0)
        .unwrap();
    assert!(output(&mut host, link, 0).is_none());
    assert_eq!(host.next_neighbor_deadline(), None);

    // Another node's DAD probe for an assigned address is answered to
    // all-nodes, unsolicited.
    let unspecified = Ipv6Addr::UNSPECIFIED;
    let dad = NeighborSolicitation {
        target: own(),
        source_link_layer: None,
    };
    let frame = packet(
        unspecified,
        group,
        255,
        &solicitation(unspecified, group, dad),
        false,
    );
    assert_eq!(input(&mut host, link, 0, &frame), Ok(true));
    let (mac, ip, message, _) = output(&mut host, link, 0).unwrap();
    assert_eq!(mac, [0x33, 0x33, 0, 0, 0, 1]);
    assert_eq!(ip.destination, IpAddr::V6(ntcp_ethernet::IPV6_ALL_NODES));
    assert!(matches!(
        message,
        ntcp_icmp::NeighborMessage::Advertisement(NeighborAdvertisement {
            solicited: false,
            ..
        })
    ));
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Assigned)
    );
}

type Side = (Host, Endpoint, IngressContext);

// A Host whose only port is ND-capable, owning `local` (DAD disabled
// administratively; DAD itself is exercised above) with an on-link route
// to its /64.
fn on_link_side(cfg: &EndpointConfig, local: SocketAddr) -> Side {
    on_link_side_with(cfg, local, IcmpOutputLimits::default())
}
fn on_link_side_with(cfg: &EndpointConfig, local: SocketAddr, output: IcmpOutputLimits) -> Side {
    let (paths, limits) = managed_limits(cfg, 1, 2, 2, 2, 0).unwrap();
    let (paths, mut limits) = managed_icmp_output_limits(paths, limits, output).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 2,
        pending_packets: 2,
        addresses: 1,
        answers: 1,
    };
    let mut host = Host::new(ContextId::new(43), paths, limits, cfg.connection.timebase).unwrap();
    host.set_entropy(Box::new(|out: &mut [u8]| {
        out.fill(0);
        out[0] = 0x80;
        Ok(())
    }));
    let port = NdPort {
        dad_transmits: 0,
        ..NdPort::new(OWN)
    };
    let receive = ReceiveCapabilities {
        max_ip_packet: 65575,
        ..receive()
    };
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, receive, port)
        .unwrap();
    let IpAddr::V6(address) = local.ip() else {
        panic!()
    };
    assert_eq!(
        host.add_neighbor_address(context.link(), address),
        Ok(AddressState::Assigned)
    );
    host.add_route(path::Route {
        destination: path::IpPrefix::new("2001:db8::".parse().unwrap(), 64).unwrap(),
        source: None,
        dscp: None,
        link: context.link(),
        next_hop: path::NextHop::OnLink,
        metric: 0,
    })
    .unwrap();
    let owned = local.ip();
    let mut endpoint = Endpoint::new(cfg.clone(), [43; 32], 0, move |request| match request {
        ntcp::AddressValidation::Bind { local } | ntcp::AddressValidation::Open { local, .. } => {
            local == owned
        }
        ntcp::AddressValidation::Incoming { destination, .. } => destination == owned,
        ntcp::AddressValidation::Route { source, .. } => source == owned,
    })
    .unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    (host, endpoint, context)
}

// Output from an ND-capable side: the attempt's IPv6 next hop is resolved
// first, and a held attempt is not submitted (it stays reserved, untouched)
// until `neighbor_wake` releases it.
fn emit_resolved(a: &mut Side, now: u64, held: &mut Option<Vec<u8>>) -> Option<([u8; 6], Vec<u8>)> {
    let (attempt, packet, frame) = match held.take() {
        Some(frame) => {
            let Some(NeighborWake::Retry { attempt, .. }) = a.0.neighbor_wake() else {
                *held = Some(frame);
                return None;
            };
            let packet = a.1.transmit_attempt_packet(attempt).unwrap();
            (attempt, packet, frame)
        }
        None => selected(&mut a.1, now)?,
    };
    let context = a.0.egress_context(&mut a.1, attempt).unwrap();
    let owner = Owner::Tcp(packet.connection.unwrap());
    let mac = match a.0.resolve_neighbor(context, owner, now).unwrap() {
        NeighborHop::Resolved(mac) => mac,
        NeighborHop::Held => {
            *held = Some(frame);
            return None;
        }
    };
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    let submitted =
        a.0.submit(&mut a.1, now, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    a.0.collect(&a.1).unwrap();
    Some((mac, frame))
}

// RFC 8201 section 3: an on-link destination still gets Path MTU Discovery.
// The on-link route's next hop is the destination itself, resolved by NS/NA
// before the SYN leaves; a PTB correlated with a data segment then lowers
// the path estimate to 1280 while the 1500 first-hop fact stays.
#[test]
//= https://www.rfc-editor.org/rfc/rfc8201#section-3
//= type=test
//= reason=No same-link bypass: PathService::select resolves an on-link route's next hop to the destination itself and keys, estimates and correlates that path exactly as a gateway path, so on-link destinations get the same shared estimate, Packet Too Big processing and PLPMTUD; the Host resolves the next hop by bounded host Neighbor Discovery (Host::resolve_neighbor holds output until an NS/NA exchange maps it), which changes no Path MTU state. Host test on_link_route_resolves_by_neighbor_discovery_and_keeps_pmtud: an on-link route is resolved by NS/NA before the SYN leaves and a downstream PTB correlated with a definitely submitted data segment lowers the path estimate to 1280 while the 1500 first-hop fact stays; core wire test ipv6_same_prefix_proxy_wire_path_does_not_bypass_downstream_ptb: 1500-to-1280 feedback, bounded repair and real receiver progress for a same-/64 peer. Namespace evidence (T19, AC-22; integration/rfc_host nd-proxy cases): the native runtime selects a destination inside its /64 through its on-link route, and a Linux router answers its Neighbor Solicitation for that destination, which lies behind it, as an NDP proxy (proxy_ndp with ip -6 neigh add proxy); no native segment precedes the solicited proxy NA and every segment carries the router's MAC with the destination's IPv6 address. After the router's downstream link falls from 1500 to 1280 its kernel-generated PTB (MTU 1280, valid checksum, Icmp6OutPktTooBigs rising by the PTBs captured) quotes a captured native packet larger than 1280, the dropped range is repaired in packets of at most 1280 octets, complete bidirectional hashed streams reach EOF with the native runtime as client and as server, the 1500-octet first-hop MTU stays, and existing and new sockets report 1280 through IPV6_MTU. The black-hole variant (the router's outgoing PTBs dropped by an owned nft rule) still delivers the stream through connection-local PLPMTUD fallback without a shared-estimate change, and the gateway variant shows the same PTB processing through an io.gateway route resolved by NS/NA.
//# Note that Path MTU Discovery must be performed even in cases where a node "thinks" a destination is attached to the same link as itself, as it might have a PMTU lower than the link MTU. In a situation such as when a neighboring router acts as proxy [ND] for some destination, the destination can appear to be directly connected, but it is in fact more than one hop away.
fn on_link_route_resolves_by_neighbor_discovery_and_keeps_pmtud() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = on_link_side(&cfg, local);
    let mut b = managed(remote, 44, cfg.clone());
    let link = a.2.link();
    let listener = b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut held = None;
    assert!(emit_resolved(&mut a, 1, &mut held).is_none());
    let IpAddr::V6(target) = remote.ip() else {
        panic!()
    };
    assert_eq!(
        a.0.neighbor(link, target).map(|n| n.0),
        Some(NeighborState::Incomplete)
    );
    // The resolution solicitation, multicast to the target's group, from
    // the assigned address with its link-layer address.
    let (mac, ip, message, ticket) = output(&mut a.0, a.2.link(), 1).unwrap();
    let group = ntcp_ethernet::solicited_node(target);
    assert_eq!(Some(mac), ntcp_ethernet::ipv6_multicast_mac(group));
    assert_eq!((ip.source, ip.destination), (local.ip(), IpAddr::V6(group)));
    assert_eq!(
        message,
        ntcp_icmp::NeighborMessage::Solicitation(NeighborSolicitation {
            target,
            source_link_layer: Some(OWN),
        })
    );
    a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, 1)
        .unwrap();
    // Waiting for resolution is not a transmission: nothing was submitted.
    assert!(emit_resolved(&mut a, 2, &mut held).is_none());
    let na = NeighborAdvertisement {
        router: false,
        solicited: true,
        override_: true,
        target,
        target_link_layer: Some(PEER),
    };
    let ip = ntcp::IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let mut answer = [0; 32];
    let len = ntcp_icmp::encode_advertisement(ip, na, &mut answer).unwrap();
    let IpAddr::V6(own_address) = local.ip() else {
        panic!()
    };
    let frame = packet(target, own_address, 255, &answer[..len], false);
    assert_eq!(input(&mut a.0, link, 3, &frame), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Reachable, Some(PEER), false))
    );
    // The held SYN leaves at the learned address, and the handshake
    // completes over the resolved neighbor.
    let mut now = 10;
    let mut data = None;
    for _ in 0..64 {
        now += 10;
        let mut work = false;
        if let Some((mac, frame)) = emit_resolved(&mut a, now, &mut held) {
            assert_eq!(mac, PEER);
            // The data segment is lost beyond the first hop: it stays
            // outstanding for the PTB that quotes it.
            if frame.len() > 1300 {
                data = Some(frame);
                break;
            }
            b.0.input_ip(
                &mut b.1,
                b.2,
                now + 1,
                &frame,
                RxPacketMetadata::default(),
                0,
                None,
            )
            .unwrap();
            work = true;
        }
        if let Some(frame) = emit(&mut b.0, &mut b.1, now + 2) {
            a.0.input_ip(
                &mut a.1,
                a.2,
                now + 3,
                &frame,
                RxPacketMetadata::default(),
                0,
                None,
            )
            .unwrap();
            work = true;
        }
        if a.1.state(id) == Ok(State::Established) && data.is_none() && !work {
            a.1.write(id, &[7; 1400]).unwrap();
        } else if !work {
            break;
        }
    }
    assert!(b.1.accept(listener).is_ok());
    let data = data.expect("a full-sized data segment");
    let report = super::dispatch::ptb(&data, 1280);
    let outcome = a.0.input_icmp(&mut a.1, a.2, now, &report, None).unwrap();
    assert!(matches!(
        outcome,
        IcmpDispatch::Completed(IcmpOutcome::Tcp {
            report: TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. }),
            ..
        })
    ));
    let snapshot = a.0.binding(id).unwrap().snapshot;
    let path = a.0.paths().path_snapshot(snapshot.path()).unwrap();
    assert_eq!(path.learned_mtu(), Some(1280));
    assert_eq!(snapshot.first_hop_mtu(), 1500);
    assert_eq!(
        snapshot.key().next_hop(),
        ResolvedNextHop::Address(ScopedAddress::new(remote.ip(), None).unwrap())
    );
    // ReachableTime (30 s with this entropy) after the handshake's own
    // confirmation passes: STALE. A new
    // cumulative acknowledgment of the definitely submitted data segment on
    // the still-authoritative path confirms the neighbor that carried it.
    let later = now + 30 * SECOND;
    a.0.service_neighbors(later);
    assert_eq!(
        a.0.neighbor(link, target).map(|n| n.0),
        Some(NeighborState::Stale)
    );
    b.0.input_ip(
        &mut b.1,
        b.2,
        later,
        &data,
        RxPacketMetadata::default(),
        0,
        None,
    )
    .unwrap();
    let ack = emit(&mut b.0, &mut b.1, later + 1).expect("an acknowledgment");
    a.0.input_ip(
        &mut a.1,
        a.2,
        later + 2,
        &ack,
        RxPacketMetadata::default(),
        0,
        None,
    )
    .unwrap();
    a.0.collect(&a.1).unwrap();
    assert_eq!(
        a.0.neighbor(link, target).map(|n| n.0),
        Some(NeighborState::Reachable)
    );
}

const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 0xb];

// A Neighbor Solicitation for `target` from `source`, to its solicited-node
// group, as it arrives.
fn ns_frame(source: Ipv6Addr, target: Ipv6Addr, source_link_layer: Option<[u8; 6]>) -> Vec<u8> {
    let group = ntcp_ethernet::solicited_node(target);
    let ns = NeighborSolicitation {
        target,
        source_link_layer,
    };
    packet(source, group, 255, &solicitation(source, group, ns), false)
}
// A Neighbor Advertisement of its target from `source`, as it arrives.
fn na_frame(source: Ipv6Addr, destination: Ipv6Addr, na: NeighborAdvertisement) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(source),
        destination: IpAddr::V6(destination),
    };
    let mut message = [0; 32];
    let len = ntcp_icmp::encode_advertisement(ip, na, &mut message).unwrap();
    packet(source, destination, 255, &message[..len], false)
}
fn v6_of(address: SocketAddr) -> Ipv6Addr {
    let IpAddr::V6(address) = address.ip() else {
        panic!()
    };
    address
}

// An on-link side whose SYN to the remote is held (its frame in the
// returned slot) while the remote's address, the returned target, is
// resolved.
fn resolving() -> (Side, ntcp::ConnectionId, Option<Vec<u8>>, Ipv6Addr) {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = on_link_side(&cfg, local);
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut held = None;
    assert!(emit_resolved(&mut a, 1, &mut held).is_none());
    let target = v6_of(remote);
    assert_eq!(
        a.0.neighbor(a.2.link(), target).map(|n| n.0),
        Some(NeighborState::Incomplete)
    );
    (a, id, held, target)
}

// RFC 4861 section 7.3.3 (no solicitation to a neighbor within RetransTimer
// of another): a resolution solicitation whose submission is Unknown may be
// on the wire, so it is not offered again before RetransTimer, and it
// counts toward MAX_MULTICAST_SOLICIT; failure follows one RetransTimer
// after the final one. Certainly unsent ones consume nothing.
#[test]
fn unknown_resolution_solicitations_are_spaced_and_counted() {
    let (mut a, id, _held, _) = resolving();
    let mut now = 1;
    for attempt in 0..3 {
        let (.., ticket) = output(&mut a.0, a.2.link(), now).expect("a solicitation");
        if attempt == 1 {
            // WouldBlock and NotSubmitted leave it due at once.
            a.0.complete_neighbor_output(ticket, BackendOutcome::WouldBlock, now)
                .unwrap();
            let (.., ticket) = output(&mut a.0, a.2.link(), now).expect("still due");
            a.0.complete_neighbor_output(ticket, BackendOutcome::NotSubmitted, now)
                .unwrap();
            let (.., ticket) = output(&mut a.0, a.2.link(), now).expect("still due");
            a.0.complete_neighbor_output(ticket, BackendOutcome::Unknown, now)
                .unwrap();
        } else {
            a.0.complete_neighbor_output(ticket, BackendOutcome::Unknown, now)
                .unwrap();
        }
        assert!(output(&mut a.0, a.2.link(), now).is_none());
        assert!(output(&mut a.0, a.2.link(), now + SECOND - 1).is_none());
        assert_eq!(a.0.next_neighbor_deadline(), Some(now + SECOND));
        a.0.service_neighbors(now + SECOND - 1);
        assert!(a.0.neighbor_wake().is_none());
        now += SECOND;
    }
    // Three possibly sent: no fourth, and failure a full RetransTimer
    // after the third.
    assert!(output(&mut a.0, a.2.link(), now).is_none());
    a.0.service_neighbors(now);
    assert_eq!(
        a.0.neighbor(a.2.link(), "2001:db8::2".parse().unwrap()),
        None
    );
    assert!(matches!(
        a.0.neighbor_wake(),
        Some(NeighborWake::Unreachable {
            owner: Owner::Tcp(owner),
            advice: Advice::NetworkError(ntcp::NetworkError::SoftUnreachable),
            ..
        }) if owner == id
    ));
}

// RFC 4862 section 5.4.2: an Unknown DAD probe does not complete DAD (only
// definitely submitted probes count), but the next one waits RetransTimer.
#[test]
fn unknown_dad_probes_are_spaced_but_not_counted() {
    let (mut host, link) = nd_host(1);
    host.add_neighbor_address(link, own()).unwrap();
    host.neighbor_membership_ready(link, own(), 0).unwrap();
    let start = SECOND / 2;
    let (.., ticket) = output(&mut host, link, start).unwrap();
    host.complete_neighbor_output(ticket, BackendOutcome::Unknown, start)
        .unwrap();
    assert!(output(&mut host, link, start + SECOND - 1).is_none());
    assert_eq!(host.service_neighbors(start + SECOND).assigned, 0);
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Tentative)
    );
    // Certainly unsent probes consume nothing and start no spacing.
    let next = start + SECOND;
    for outcome in [BackendOutcome::WouldBlock, BackendOutcome::NotSubmitted] {
        let (.., ticket) = output(&mut host, link, next).unwrap();
        host.complete_neighbor_output(ticket, outcome, next)
            .unwrap();
        assert_eq!(host.service_neighbors(next + 2 * SECOND).assigned, 0);
    }
    let (.., ticket) = output(&mut host, link, next).unwrap();
    host.complete_neighbor_output(ticket, BackendOutcome::Submitted, next)
        .unwrap();
    assert!(output(&mut host, link, next + 10 * SECOND).is_none());
    assert_eq!(host.service_neighbors(next + SECOND - 1).assigned, 0);
    assert_eq!(host.service_neighbors(next + SECOND).assigned, 1);
    assert!(owned(&host, link));
}

// RFC 4862 section 5.4.3: on a port that loops back multicast, the own copy
// of a possibly sent DAD probe is expected and does not fail DAD; one
// solicitation beyond the expected number still does.
#[test]
fn unknown_dad_probe_expects_its_looped_copy() {
    let (mut host, link) = nd_host_with(NdPort {
        loops_back_multicast: true,
        ..NdPort::new(OWN)
    });
    host.add_neighbor_address(link, own()).unwrap();
    host.neighbor_membership_ready(link, own(), 0).unwrap();
    let (.., ticket) = output(&mut host, link, SECOND / 2).unwrap();
    host.complete_neighbor_output(ticket, BackendOutcome::Unknown, SECOND / 2)
        .unwrap();
    let probe = ns_frame(Ipv6Addr::UNSPECIFIED, own(), None);
    assert_eq!(input(&mut host, link, SECOND / 2, &probe), Ok(true));
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Tentative)
    );
    assert_eq!(input(&mut host, link, SECOND / 2, &probe), Ok(true));
    assert_eq!(
        host.neighbor_address_state(link, own()),
        Some(AddressState::Duplicate)
    );
}

// Answers end on Unknown or NotSubmitted (the solicitor retransmits) and
// stay queued on WouldBlock. The answer queue is bounded: a solicitation
// arriving while every slot is occupied is not answered, and the next one
// is once a slot frees.
#[test]
fn bounded_answers_end_unless_blocked() {
    let (mut host, link) = nd_host(0);
    host.add_neighbor_address(link, own()).unwrap();
    let solicitors: [Ipv6Addr; 3] = [
        peer(),
        "fe80::b".parse().unwrap(),
        "fe80::c".parse().unwrap(),
    ];
    let ns = |source| ns_frame(source, own(), Some(PEER));
    // Two slots: the third solicitation finds both occupied.
    for source in solicitors {
        assert_eq!(input(&mut host, link, 0, &ns(source)), Ok(true));
    }
    let answered = |ip: ntcp::IpMetadata| ip.destination;
    let (_, ip, _, ticket) = output(&mut host, link, 0).unwrap();
    assert_eq!(answered(ip), IpAddr::V6(solicitors[0]));
    host.complete_neighbor_output(ticket, BackendOutcome::WouldBlock, 0)
        .unwrap();
    let (_, ip, _, ticket) = output(&mut host, link, 0).unwrap();
    assert_eq!(answered(ip), IpAddr::V6(solicitors[0]));
    host.complete_neighbor_output(ticket, BackendOutcome::Unknown, 0)
        .unwrap();
    let (_, ip, _, ticket) = output(&mut host, link, 0).unwrap();
    assert_eq!(answered(ip), IpAddr::V6(solicitors[1]));
    host.complete_neighbor_output(ticket, BackendOutcome::NotSubmitted, 0)
        .unwrap();
    // The third solicitation was never queued.
    assert!(output(&mut host, link, 0).is_none());
    // Its retransmission is answered now that slots are free.
    assert_eq!(input(&mut host, link, 1, &ns(solicitors[2])), Ok(true));
    let (mac, ip, _, ticket) = output(&mut host, link, 1).unwrap();
    assert_eq!((mac, answered(ip)), (PEER, IpAddr::V6(solicitors[2])));
    host.complete_neighbor_output(ticket, BackendOutcome::Submitted, 1)
        .unwrap();
    assert!(output(&mut host, link, 1).is_none());
}

// RFC 4861 section 7.2.3 through Host::receive: a unicast-source
// solicitation with a Source Link-Layer Address creates a STALE entry that
// output uses at once (starting DELAY), and draws an answer; a different
// address in a later one updates the entry to STALE, which the next output
// uses.
#[test]
fn solicitation_source_address_creates_and_updates_stale() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = on_link_side(&cfg, local);
    let link = a.2.link();
    let (own_address, target) = (v6_of(local), v6_of(remote));
    a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
        .unwrap();
    let frame = ns_frame(target, own_address, Some(PEER));
    assert_eq!(input(&mut a.0, link, 1, &frame), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Stale, Some(PEER), false))
    );
    let (mac, ip, message, ticket) = output(&mut a.0, a.2.link(), 1).unwrap();
    assert_eq!((mac, ip.destination), (PEER, remote.ip()));
    assert!(matches!(
        message,
        ntcp_icmp::NeighborMessage::Advertisement(NeighborAdvertisement {
            solicited: true,
            ..
        })
    ));
    a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, 1)
        .unwrap();
    let mut held = None;
    let (mac, _) = emit_resolved(&mut a, 2, &mut held).expect("the SYN");
    assert_eq!(mac, PEER);
    assert_eq!(
        a.0.neighbor(link, target).map(|n| n.0),
        Some(NeighborState::Delay)
    );
    // Neither a resolution nor a probe solicitation was needed.
    assert!(output(&mut a.0, a.2.link(), 2).is_none());

    let frame = ns_frame(target, own_address, Some(OTHER));
    assert_eq!(input(&mut a.0, link, 3, &frame), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Stale, Some(OTHER), false))
    );
    // The retransmitted SYN goes to the updated address.
    let resent = (1..100).find_map(|step| {
        let now = 3 + step * SECOND / 10;
        a.1.on_timeout(now, 32).unwrap();
        emit_resolved(&mut a, now, &mut held)
    });
    assert_eq!(resent.map(|(mac, _)| mac), Some(OTHER));
}

// RFC 4861 section 7.2.5 through Host::receive: an advertisement without a
// Target Link-Layer Address leaves an INCOMPLETE Ethernet entry and its held
// packet alone; a solicited one with it resolves the entry and releases
// the packet. Afterwards an unsolicited Override = 0 advertisement of a
// different address turns REACHABLE into STALE keeping the cached address
// (and is ignored by STALE), while Override = 1 replaces it (STALE).
#[test]
fn advertisements_resolve_and_update_through_receive() {
    let (mut a, _id, mut held, target) = resolving();
    let link = a.2.link();
    let own_address: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let na = |solicited, override_, target_link_layer| NeighborAdvertisement {
        router: false,
        solicited,
        override_,
        target,
        target_link_layer,
    };
    let frame = na_frame(target, own_address, na(true, true, None));
    assert_eq!(input(&mut a.0, link, 2, &frame), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Incomplete, None, false))
    );
    assert!(emit_resolved(&mut a, 3, &mut held).is_none());
    assert!(held.is_some());

    let frame = na_frame(target, own_address, na(true, false, Some(PEER)));
    assert_eq!(input(&mut a.0, link, 4, &frame), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Reachable, Some(PEER), false))
    );
    let (mac, _) = emit_resolved(&mut a, 5, &mut held).expect("the released SYN");
    assert_eq!(mac, PEER);
    assert!(held.is_none() && a.0.neighbor_wake().is_none());

    let all_nodes = ntcp_ethernet::IPV6_ALL_NODES;
    let keep = na_frame(target, all_nodes, na(false, false, Some(OTHER)));
    assert_eq!(input(&mut a.0, link, 6, &keep), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Stale, Some(PEER), false))
    );
    assert_eq!(input(&mut a.0, link, 7, &keep), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Stale, Some(PEER), false))
    );
    let replace = na_frame(target, all_nodes, na(false, true, Some(OTHER)));
    assert_eq!(input(&mut a.0, link, 8, &replace), Ok(true));
    assert_eq!(
        a.0.neighbor(link, target),
        Some((NeighborState::Stale, Some(OTHER), false))
    );
}

// Host ICMP output on an ND-capable port (RFC 4443 section 4.2's Echo
// responder; RFC 4861 sections 7.2.2 and 7.3.3).
const ICMP_OUTPUT: IcmpOutputLimits = IcmpOutputLimits {
    messages: 2,
    message_bytes: 1280,
    hop_limit: 64,
};
fn icmp_side() -> (Side, Ipv6Addr) {
    let cfg = config(2);
    let (local, _) = addresses(true);
    (on_link_side_with(&cfg, local, ICMP_OUTPUT), v6_of(local))
}
fn echo_request(source: Ipv6Addr, destination: Ipv6Addr, sequence: u16) -> Vec<u8> {
    let ip = ntcp::IpMetadata {
        source: IpAddr::V6(source),
        destination: IpAddr::V6(destination),
    };
    let mut message = [0; 16];
    let n = ntcp_icmp::encode_echo(
        ip,
        ntcp_icmp::EchoKind::Request,
        7,
        sequence,
        &mut message,
        8,
    )
    .unwrap();
    packet(source, destination, 64, &message[..n], false)
}
fn echo_in(a: &mut Side, now: u64, frame: &[u8]) {
    a.0.input_ip(
        &mut a.1,
        a.2,
        now,
        frame,
        RxPacketMetadata::default(),
        0,
        None,
    )
    .unwrap();
}
// One `icmp_output` pass: the Ethernet destination and IPv6 destination of
// what it submitted, if anything.
fn icmp_drain(a: &mut Side, now: u64) -> Option<(Option<[u8; 6]>, IpAddr)> {
    let mut packet = vec![0; 4096];
    let mut sent = None;
    let _ = a.0.icmp_output(now, &mut packet, |egress, bytes| {
        let ip = ntcp_ip6::parse(bytes).unwrap().ip;
        sent = Some((egress.link_layer, ip.destination));
        BackendOutcome::Submitted
    });
    sent
}

// An Echo Request from a peer whose solicitation created a STALE entry is
// answered at once to the cached address, which starts DELAY.
#[test]
fn echo_replies_use_the_cached_neighbor_mapping() {
    let (mut a, own_address) = icmp_side();
    let link = a.2.link();
    let peer: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let frame = ns_frame(peer, own_address, Some(PEER));
    assert_eq!(input(&mut a.0, link, 1, &frame), Ok(true));
    let (.., ticket) = output(&mut a.0, a.2.link(), 1).unwrap();
    a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, 1)
        .unwrap();
    echo_in(&mut a, 2, &echo_request(peer, own_address, 1));
    assert_eq!(a.0.icmp_output_pending(), 1);
    assert_eq!(icmp_drain(&mut a, 3), Some((Some(PEER), IpAddr::V6(peer))));
    assert_eq!(
        a.0.neighbor(link, peer).map(|n| n.0),
        Some(NeighborState::Delay)
    );
    assert_eq!(a.0.icmp_output_pending(), 0);
}

// A message to an unresolved next hop solicits it and is held, while one
// to another (cached) next hop goes out; the advertisement then releases
// the held message to the resolved address.
#[test]
fn icmp_output_to_an_unresolved_neighbor_is_held_without_blocking_others() {
    let (mut a, own_address) = icmp_side();
    let link = a.2.link();
    let (unresolved, cached): (Ipv6Addr, Ipv6Addr) = (
        "2001:db8::2".parse().unwrap(),
        "2001:db8::3".parse().unwrap(),
    );
    echo_in(&mut a, 1, &echo_request(unresolved, own_address, 1));
    let frame = ns_frame(cached, own_address, Some(OTHER));
    assert_eq!(input(&mut a.0, link, 1, &frame), Ok(true));
    let (.., ticket) = output(&mut a.0, a.2.link(), 1).unwrap();
    a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, 1)
        .unwrap();
    echo_in(&mut a, 1, &echo_request(cached, own_address, 2));
    assert_eq!(
        icmp_drain(&mut a, 2),
        Some((Some(OTHER), IpAddr::V6(cached)))
    );
    assert_eq!(a.0.icmp_output_pending(), 1);
    assert_eq!(
        a.0.neighbor(link, unresolved).map(|n| n.0),
        Some(NeighborState::Incomplete)
    );
    // Held, not resubmitted, while it is resolved.
    assert_eq!(icmp_drain(&mut a, 3), None);
    let (mac, ip, message, ticket) = output(&mut a.0, a.2.link(), 3).expect("the solicitation");
    assert_eq!(mac, [0x33, 0x33, 0xff, 0, 0, 2]);
    assert_eq!(ip.source, IpAddr::V6(own_address));
    assert!(matches!(
        message,
        ntcp_icmp::NeighborMessage::Solicitation(NeighborSolicitation { target, .. })
            if target == unresolved
    ));
    a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, 3)
        .unwrap();
    let na = NeighborAdvertisement {
        router: false,
        solicited: true,
        override_: true,
        target: unresolved,
        target_link_layer: Some(PEER),
    };
    let frame = na_frame(unresolved, own_address, na);
    assert_eq!(input(&mut a.0, link, 4, &frame), Ok(true));
    assert_eq!(
        icmp_drain(&mut a, 5),
        Some((Some(PEER), IpAddr::V6(unresolved)))
    );
    assert_eq!(a.0.icmp_output_pending(), 0);
    assert_eq!(a.0.icmp_output_counters().unsent, 0);
}

// When resolution fails the held message is discarded, counted unsent,
// and nothing is submitted for it.
#[test]
fn failed_resolution_discards_held_icmp_output() {
    let (mut a, own_address) = icmp_side();
    let peer: Ipv6Addr = "2001:db8::2".parse().unwrap();
    echo_in(&mut a, 1, &echo_request(peer, own_address, 1));
    assert_eq!(icmp_drain(&mut a, 1), None);
    let mut now = 1;
    for _ in 0..3 {
        let (.., ticket) = output(&mut a.0, a.2.link(), now).expect("a solicitation");
        a.0.complete_neighbor_output(ticket, BackendOutcome::Submitted, now)
            .unwrap();
        now += SECOND;
        a.0.service_neighbors(now);
    }
    assert_eq!(a.0.neighbor(a.2.link(), peer), None);
    assert_eq!(a.0.icmp_output_pending(), 0);
    assert_eq!(a.0.icmp_output_counters().unsent, 1);
    assert_eq!(icmp_drain(&mut a, now), None);
    // No pending slot stays behind: both can hold output again.
    assert!(a.0.neighbor_wake().is_none());
}
