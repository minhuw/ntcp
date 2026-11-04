use super::*;
use std::println;

// Counts provider transactions while delegating to the real Host authority.
struct Counting<'a> {
    host: &'a mut Host,
    prepared: usize,
}
impl PathProvider for Counting<'_> {
    type Error = Error;
    fn prepare(&mut self, request: PathFactoryRequest) -> Result<ntcp::PreparedFactory, Error> {
        self.prepared += 1;
        self.host.prepare(request)
    }
    fn commit(&mut self, prepared: PreparedPath, connection: ConnectionId) {
        self.host.commit(prepared, connection);
    }
    fn cancel(&mut self, prepared: PreparedPath) {
        self.host.cancel(prepared);
    }
}

fn syn(ip: IpMetadata, port: u16) -> Vec<u8> {
    let mut tcp = vec![0; 20];
    let len = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: port,
            destination_port: 8080,
            sequence: 1,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut tcp,
    )
    .unwrap();
    tcp.truncate(len);
    tcp
}
fn ipv4_frame(ip: IpMetadata, tcp: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
        panic!()
    };
    let mut frame = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0];
    frame[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    let sum = ntcp_ip::checksum(&frame);
    frame[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(tcp);
    frame
}
fn usage(host: &Host) -> (usize, usize, usize, usize) {
    let usage = host.paths().usage();
    (
        host.binding_count(),
        host.lease_count(),
        usage.paths,
        usage.clients,
    )
}
fn core_input(
    peer: &mut (Host, Endpoint, IngressContext),
    now: u64,
    ip: IpMetadata,
    tcp: &[u8],
) -> (Result<ntcp::InputDisposition, ManagedError<Error>>, usize) {
    let mut provider = Counting {
        host: &mut peer.0,
        prepared: 0,
    };
    let result = peer.1.input_with_path_provider(
        now,
        ip,
        0,
        Ipv4Options::default(),
        tcp,
        RxPacketMetadata::default(),
        12,
        &mut provider,
    );
    (result, provider.prepared)
}

// Managed passive input applies the Endpoint's shared ingress admission
// before any path transaction (RFC 9293 MUST-63/MUST-57).
#[test]
fn rejected_managed_syns_prepare_no_path_and_valid_syn_still_establishes() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut b = managed(remote, 41, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let sources: &[&str] = if v6 {
            &["::", "ff02::1", "fe80::2"]
        } else {
            &["0.0.0.0", "224.0.0.1"]
        };
        let before = usage(&b.0);
        for (index, source) in sources.iter().enumerate() {
            let ip = IpMetadata {
                source: source.parse().unwrap(),
                destination: remote.ip(),
            };
            let tcp = syn(ip, 40000 + index as u16);
            let (result, prepared) = core_input(&mut b, 1, ip, &tcp);
            println!("core SYN from {source}: {result:?}, provider prepares {prepared}");
            assert_eq!(result, Ok(ntcp::InputDisposition::Dropped));
            assert_eq!(prepared, 0);
            if !v6 {
                let host = b.0.input_ip(
                    &mut b.1,
                    b.2,
                    1,
                    &ipv4_frame(ip, &tcp),
                    RxPacketMetadata::default(),
                    12,
                    None,
                );
                println!("framed SYN from {source}: {host:?}");
                assert_eq!(host, Ok(ntcp::InputDisposition::Dropped));
            }
            assert_eq!(usage(&b.0), before);
            assert!(selected(&mut b.1, 2).is_none(), "no SYN-ACK or RST");
        }
        let mut a = managed(local, 42, cfg.clone());
        let id =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 24), &mut a.0)
                .unwrap();
        let mut now = 10;
        pump(&mut a, &mut b, &mut now);
        assert_eq!(a.1.state(id).unwrap(), State::Established);
        b.1.accept(listener).unwrap();
        assert_eq!(b.0.binding_count(), 1);
    }
}

#[test]
fn full_endpoint_backlog_or_uncollected_bindings_do_not_turn_admissible_syns_into_errors() {
    let (local, remote) = addresses(false);
    let second = SocketAddr::new(local.ip(), 1001);
    let request = |a: &mut (Host, Endpoint, IngressContext),
                   from: SocketAddr,
                   cfg: &EndpointConfig,
                   now: u64| {
        a.1.connect_with_path_provider(now, from, remote, options(cfg, 24), &mut a.0)
            .unwrap();
        let frame = emit(&mut a.0, &mut a.1, now + 1).unwrap();
        let packet = ntcp_ip::parse(&frame, false).unwrap();
        (packet.ip, packet.payload.to_vec(), frame)
    };
    // Endpoint slots exhausted by an established flow, then a full backlog.
    for backlog in [false, true] {
        let cfg = config(if backlog { 4 } else { 1 });
        let mut a = managed(local, 51, config(4));
        let mut b = managed(remote, 52, cfg.clone());
        b.1.listen(remote, 1).unwrap();
        let (_, _, first) = request(&mut a, local, &cfg, 0);
        input(&mut b.0, &mut b.1, b.2, 1, &first, 12);
        if !backlog {
            let mut now = 10;
            pump(&mut a, &mut b, &mut now);
        }
        let before = usage(&b.0);
        let (ip, tcp, frame) = request(&mut a, second, &cfg, 5000);
        let (result, prepared) = core_input(&mut b, 6000, ip, &tcp);
        println!("backlog={backlog}: {result:?}, provider prepares {prepared}");
        assert_eq!(result, Ok(ntcp::InputDisposition::Dropped));
        assert_eq!(prepared, 0);
        assert_eq!(
            b.0.input_ip(
                &mut b.1,
                b.2,
                6000,
                &frame,
                RxPacketMetadata::default(),
                12,
                None
            ),
            Ok(ntcp::InputDisposition::Dropped)
        );
        assert_eq!(usage(&b.0), before);
    }
    // Bindings sized max_connections+1 can only be full of uncollected
    // generations once the Endpoint itself has room.
    let cfg = config(1);
    let mut a = managed(local, 53, cfg.clone());
    let mut b = managed(remote, 54, cfg.clone());
    let listener = b.1.listen(remote, 1).unwrap();
    for port in [2000, 2001] {
        let id =
            b.1.connect_with_path_provider(
                0,
                SocketAddr::new(remote.ip(), port),
                local,
                options(&cfg, 12),
                &mut b.0,
            )
            .unwrap();
        b.1.cancel_unsubmitted_open(id).unwrap();
    }
    assert_eq!(b.0.binding_count(), 2);
    let (_, _, frame) = request(&mut a, local, &cfg, 0);
    let result = b.0.input_ip(
        &mut b.1,
        b.2,
        1,
        &frame,
        RxPacketMetadata::default(),
        12,
        None,
    );
    println!("uncollected bindings: {result:?}");
    assert_eq!(result, Ok(ntcp::InputDisposition::Processed));
    assert_eq!(b.0.binding_count(), 1);
    let mut now = 10;
    pump(&mut a, &mut b, &mut now);
    b.1.accept(listener).unwrap();
}

#[test]
fn managed_active_open_keeps_endpoint_admission_errors_and_reserves_no_route_for_owned_sources() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = managed(local, 61, cfg.clone());
        a.1.enable_fast_open().unwrap();
        let unowned: SocketAddr = if v6 {
            "[2001:db8::3]:1000".parse().unwrap()
        } else {
            "192.0.2.3:1000".parse().unwrap()
        };
        let before = usage(&a.0);
        let ordinary =
            a.1.connect_with_path_provider(0, unowned, remote, options(&cfg, 24), &mut a.0);
        let fast_open = a.1.connect_fast_open_with_path_provider(
            0,
            unowned,
            remote,
            &[1; 10],
            options(&cfg, 24),
            None,
            FastOpenClientPolicy::ApplicationProtected,
            &mut a.0,
        );
        println!("unowned source v6={v6}: {ordinary:?} / {fast_open:?}");
        assert_eq!(
            ordinary,
            Err(ManagedError::Endpoint(EndpointError::InvalidAddress))
        );
        assert_eq!(
            fast_open,
            Err(ManagedError::Endpoint(EndpointError::InvalidAddress))
        );
        assert_eq!(usage(&a.0), before);
        assert!(selected(&mut a.1, 1).is_none());
        // An owned, registered source with no matching forwarding route.
        let request =
            a.0.request(local.ip(), remote.ip(), Dscp::new(24).unwrap())
                .unwrap();
        let route = a.0.paths().resolve(request).unwrap().key().route();
        a.0.remove_route(route).unwrap();
        let unrouted =
            a.1.connect_with_path_provider(2, local, remote, options(&cfg, 24), &mut a.0);
        println!("unrouted owned source v6={v6}: {unrouted:?}");
        assert_eq!(
            unrouted,
            Err(ManagedError::Provider(Error::Path(path::Error::NoRoute)))
        );
        assert_eq!(a.0.binding_count(), 0);
    }
}
