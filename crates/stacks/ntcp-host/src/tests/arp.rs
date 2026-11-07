// ARP resolution of IPv4 next hops through the Host's neighbor calls: port
// registration and addresses, held transport output released by a reply,
// replies to requests for the port's address, resolution failure as
// Address Unreachable advice, and storage that defaults to nothing.
use super::*;
use alloc::boxed::Box;
use core::net::Ipv4Addr;
use ntcp_arp::{Arp, Operation};

type Side = (Host, Endpoint, IngressContext);

const SECOND: u64 = 1_000_000;
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);

fn receive() -> ReceiveCapabilities {
    ReceiveCapabilities {
        max_ip_packet: 1500,
        ipv4: Ipv4Receive::Enabled {
            interpretation: false,
            source_routes: false,
        },
        ipv6: Ipv6Receive::Disabled,
        gro: false,
    }
}
fn ipv4_limits() -> NeighborLimits {
    NeighborLimits {
        entries: 2,
        pending_packets: 2,
        addresses: 1,
        answers: 1,
    }
}
fn entropy() -> Entropy {
    Box::new(|out: &mut [u8]| {
        out.fill(0);
        out[0] = 0x80;
        Ok(())
    })
}
fn arp_host(cfg: &EndpointConfig, ipv4: NeighborLimits) -> Host {
    let (paths, mut limits) = managed_limits(cfg, 1, 1, 1, 2, 0).unwrap();
    limits.ipv4_neighbors = ipv4;
    let mut host = Host::new(ContextId::new(51), paths, limits, cfg.connection.timebase).unwrap();
    host.set_entropy(entropy());
    host
}
// 192.0.2.1/24 on an ARP port, default route through 192.0.2.254.
fn side() -> Side {
    let cfg = config(1);
    let mut host = arp_host(&cfg, ipv4_limits());
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, receive(), NdPort::new(OWN))
        .unwrap();
    let link = context.link();
    // Its IPv4 addresses are ARP's too, so only the neighbor call adds them.
    assert_eq!(
        host.register_source(ScopedAddress::new(IpAddr::V4(LOCAL), None).unwrap(), link),
        Err(Error::Unsupported)
    );
    assert_eq!(
        host.add_neighbor_address(link, LOCAL),
        Ok(AddressState::Assigned)
    );
    for (prefix, length, next_hop) in [
        (
            Ipv4Addr::UNSPECIFIED,
            0,
            path::NextHop::Gateway(ScopedAddress::new(IpAddr::V4(GATEWAY), None).unwrap()),
        ),
        (Ipv4Addr::new(192, 0, 2, 0), 24, path::NextHop::OnLink),
    ] {
        host.add_route(path::Route {
            destination: path::IpPrefix::new(IpAddr::V4(prefix), length).unwrap(),
            source: None,
            dscp: None,
            link,
            next_hop,
            metric: 0,
        })
        .unwrap();
    }
    let owned = IpAddr::V4(LOCAL);
    let mut endpoint = Endpoint::new(cfg.clone(), [51; 32], 0, move |request| match request {
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
fn connect(side: &mut Side, remote: &str) -> ConnectionId {
    let cfg = config(1);
    side.1
        .connect_with_path_provider(
            0,
            "192.0.2.1:1000".parse().unwrap(),
            remote.parse().unwrap(),
            options(&cfg, 0),
            &mut side.0,
        )
        .unwrap()
}
// The next ARP transmission: Ethernet destination, body and ticket.
fn output(host: &mut Host, link: LinkId, now: u64) -> Option<([u8; 6], Arp, NeighborTicket)> {
    let mut out = [0; 64];
    let transmit = host.neighbor_output(link, now, &mut out).unwrap()?;
    assert_eq!(transmit.ethertype, ntcp_ethernet::ETHERTYPE_ARP);
    assert_eq!(transmit.len, ntcp_arp::ARP_LEN);
    let arp = ntcp_arp::parse(&out[..transmit.len]).unwrap();
    Some((transmit.destination, arp, transmit.ticket))
}
fn body(arp: Arp) -> [u8; 28] {
    let mut out = [0; 28];
    ntcp_arp::encode(&mut out, &arp).unwrap();
    out
}
fn request_for(own: Ipv4Addr) -> Arp {
    Arp {
        operation: Operation::Request,
        sender_mac: OWN,
        sender_ip: own,
        target_mac: [0; 6],
        target_ip: GATEWAY,
    }
}

#[test]
fn held_syn_is_released_by_the_gateway_reply() {
    let mut side = side();
    let link = side.2.link();
    connect(&mut side, "198.51.100.7:80");
    let (attempt, packet, frame) = selected(&mut side.1, 0).unwrap();
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let owner = Owner::Tcp(packet.connection.unwrap());
    // Off-link: the gateway is resolved, never the destination.
    assert_eq!(
        side.0.resolve_neighbor(context, owner, 0),
        Ok(NeighborHop::Held)
    );
    assert_eq!(
        side.0.resolve_neighbor(context, owner, 0),
        Ok(NeighborHop::Held)
    );
    assert!(side.0.neighbor_wake().is_none());
    assert_eq!(side.0.next_neighbor_deadline(), Some(0));
    let (destination, arp, ticket) = output(&mut side.0, link, 0).unwrap();
    assert_eq!(destination, ntcp_ethernet::BROADCAST);
    assert_eq!(arp, request_for(LOCAL));
    side.0
        .complete_neighbor_output(ticket, BackendOutcome::Submitted, 0)
        .unwrap();
    assert!(output(&mut side.0, link, 0).is_none());
    assert_eq!(side.0.next_neighbor_deadline(), Some(SECOND));
    assert_eq!(side.0.arp_counters().requests_sent, 1);
    // The reply releases the held attempt for a retry.
    let reply = Arp {
        operation: Operation::Reply,
        sender_mac: GATEWAY_MAC,
        sender_ip: GATEWAY,
        target_mac: OWN,
        target_ip: LOCAL,
    };
    side.0
        .receive_arp(side.2, SECOND / 2, &body(reply))
        .unwrap();
    assert_eq!(
        side.0.neighbor_wake(),
        Some(NeighborWake::Retry { owner, attempt })
    );
    assert!(side.0.neighbor_wake().is_none());
    assert_eq!(
        side.0.resolve_neighbor(context, owner, SECOND / 2),
        Ok(NeighborHop::Resolved(GATEWAY_MAC))
    );
    let ticket = side.0.submission_ticket(&mut side.1, context).unwrap();
    let submitted = side
        .0
        .submit(&mut side.1, SECOND / 2, ticket, context, &frame, 0, |_| {
            BackendOutcome::Submitted
        })
        .unwrap();
    assert!(submitted == Submission::Submitted);
    assert_eq!(
        side.0.ipv4_neighbor(link, GATEWAY),
        Some((ArpState::Reachable, Some(GATEWAY_MAC)))
    );
    assert_eq!(
        side.0.next_neighbor_deadline(),
        Some(SECOND / 2 + 30 * SECOND)
    );
}

#[test]
fn requests_for_the_port_address_are_answered_and_others_are_not() {
    let mut side = side();
    let link = side.2.link();
    let peer = Ipv4Addr::new(192, 0, 2, 9);
    let peer_mac = [2, 0, 0, 0, 0, 9];
    let request = |target| Arp {
        operation: Operation::Request,
        sender_mac: peer_mac,
        sender_ip: peer,
        target_mac: [0; 6],
        target_ip: target,
    };
    side.0
        .receive_arp(side.2, 0, &body(request(Ipv4Addr::new(192, 0, 2, 3))))
        .unwrap();
    assert!(output(&mut side.0, link, 0).is_none());
    // Ethernet padding after the body is ignored.
    let mut padded = [0; 46];
    padded[..28].copy_from_slice(&body(request(LOCAL)));
    side.0.receive_arp(side.2, 0, &padded).unwrap();
    let (destination, arp, ticket) = output(&mut side.0, link, 0).unwrap();
    assert_eq!(destination, peer_mac);
    assert_eq!(
        arp,
        Arp {
            operation: Operation::Reply,
            sender_mac: OWN,
            sender_ip: LOCAL,
            target_mac: peer_mac,
            target_ip: peer,
        }
    );
    side.0
        .complete_neighbor_output(ticket, BackendOutcome::Submitted, 0)
        .unwrap();
    assert!(output(&mut side.0, link, 0).is_none());
    assert_eq!(side.0.arp_counters().replies_sent, 1);
    // The requester was learned, unconfirmed.
    assert_eq!(
        side.0.ipv4_neighbor(link, peer),
        Some((ArpState::Stale, Some(peer_mac)))
    );
    assert_eq!(
        side.0.receive_arp(side.2, 0, &[0; 27]),
        Err(Error::Codec(ntcp_ip::Error::Truncated))
    );
}

#[test]
fn unanswered_requests_end_in_address_unreachable_advice() {
    let mut side = side();
    let link = side.2.link();
    connect(&mut side, "192.0.2.77:80");
    let (attempt, packet, _) = selected(&mut side.1, 0).unwrap();
    let context = side.0.egress_context(&mut side.1, attempt).unwrap();
    let owner = Owner::Tcp(packet.connection.unwrap());
    assert_eq!(
        side.0.resolve_neighbor(context, owner, 0),
        Ok(NeighborHop::Held)
    );
    for second in 0..3 {
        let now = second * SECOND;
        side.0.service_neighbors(now);
        let (destination, arp, ticket) = output(&mut side.0, link, now).unwrap();
        assert_eq!(destination, ntcp_ethernet::BROADCAST);
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 0, 2, 77));
        side.0
            .complete_neighbor_output(ticket, BackendOutcome::Submitted, now)
            .unwrap();
        assert!(side.0.neighbor_wake().is_none());
    }
    assert_eq!(side.0.next_neighbor_deadline(), Some(3 * SECOND));
    side.0.service_neighbors(3 * SECOND - 1);
    assert!(side.0.neighbor_wake().is_none());
    side.0.service_neighbors(3 * SECOND);
    assert_eq!(
        side.0.neighbor_wake(),
        Some(NeighborWake::Unreachable {
            owner,
            attempt,
            advice: Advice::NetworkError(ntcp::NetworkError::SoftUnreachable),
        })
    );
    assert!(output(&mut side.0, link, 3 * SECOND).is_none());
    assert_eq!(side.0.next_neighbor_deadline(), None);
    assert_eq!(side.0.arp_counters().resolution_failures, 1);
    assert_eq!(side.0.arp_counters().requests_sent, 3);
}

#[test]
fn ipv4_resolution_needs_its_own_storage() {
    let cfg = config(1);
    // By default an IPv4-only neighbor port is an ND port as before, which
    // needs Neighbor Discovery storage.
    let mut host = arp_host(&cfg, NeighborLimits::default());
    assert_eq!(
        host.register_neighbor_port(InterfaceKey(1), 1500, receive(), NdPort::new(OWN))
            .map(|_| ()),
        Err(Error::Capacity)
    );
    // A port registered without ARP storage keeps refusing IPv4 next hops.
    let (paths, mut limits) = managed_limits(&cfg, 1, 1, 1, 2, 0).unwrap();
    limits.neighbors = NeighborLimits {
        entries: 1,
        ..ipv4_limits()
    };
    let mut host = Host::new(ContextId::new(52), paths, limits, cfg.connection.timebase).unwrap();
    host.set_entropy(entropy());
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, receive(), NdPort::new(OWN))
        .unwrap();
    assert_eq!(
        host.add_neighbor_address(context.link(), LOCAL),
        Err(Error::InvalidContext)
    );
    assert_eq!(
        host.receive_arp(context, 0, &body(request_for(GATEWAY))),
        Err(Error::Unsupported)
    );
    assert!(
        host.neighbor_output(context.link(), 0, &mut [0; 64])
            .unwrap()
            .is_none()
    );
    // ARP storage registers no Neighbor Discovery port for IPv4 alone.
    let mut host = arp_host(&cfg, ipv4_limits());
    let context = host
        .register_neighbor_port(InterfaceKey(1), 1500, receive(), NdPort::new(OWN))
        .unwrap();
    assert_eq!(
        host.add_neighbor_address(context.link(), LOCAL),
        Ok(AddressState::Assigned)
    );
    assert_eq!(
        host.add_neighbor_address(context.link(), LOCAL),
        Err(Error::Path(path::Error::Duplicate))
    );
    // A permanent mapping resolves at once and is never replaced.
    let link = context.link();
    assert_eq!(
        host.add_static_neighbor(link, IpAddr::V6("fe80::1".parse().unwrap()), GATEWAY_MAC, 0),
        Err(Error::Unsupported)
    );
    assert_eq!(
        host.add_static_neighbor(link, IpAddr::V4(LOCAL), GATEWAY_MAC, 0),
        Err(Error::Unsupported)
    );
    host.add_static_neighbor(link, IpAddr::V4(GATEWAY), GATEWAY_MAC, 0)
        .unwrap();
    let mut reply = request_for(GATEWAY);
    reply.sender_mac = [2, 0, 0, 0, 0, 0x77];
    host.receive_arp(context, 0, &body(reply)).unwrap();
    assert_eq!(
        host.ipv4_neighbor(link, GATEWAY),
        Some((ArpState::Permanent, Some(GATEWAY_MAC)))
    );
    assert_eq!(host.next_neighbor_deadline(), None);
}
