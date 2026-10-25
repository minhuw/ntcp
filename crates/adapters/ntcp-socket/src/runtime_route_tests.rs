use super::*;

#[test]
fn owner_native_route_configuration_and_management_affect_real_connection_policies() {
    let mut config = SocketConfig::new("test", "10.73.0.2".parse().unwrap());
    config.tcp.connection.pmtud = Some(ntcp::PmtudConfig::new(1500));
    let remote = "10.73.0.3".parse().unwrap();
    let policy = ntcp::RoutePolicy {
        mtu: Some(640),
        advertised_mss: Some(600),
        initial_search_low: Some(552),
        ..Default::default()
    };
    config.routes.push((remote, policy));
    let mut a = owner_with_config(2, config.tcp.clone());
    a.test_now = Some(1000);
    a.apply_socket_config(&config).unwrap();
    let fd = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(fd, Op::Connect("10.73.0.3:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let Handle::Connection(id) = a.sockets[&fd].handle else {
        panic!()
    };
    let mut bytes = [0; 2048];
    let packet = a
        .endpoint
        .poll_transmit(1000, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    assert_eq!(
        ntcp::wire::parse(packet.ip, &bytes[..packet.len])
            .unwrap()
            .options
            .mss,
        Some(600)
    );
    assert_eq!(
        a.endpoint.path_mtu_info(id).unwrap().unwrap().current_mtu,
        640
    );
    a.execute(
        0,
        Op::SetDestinationRoute(
            remote,
            Some(ntcp::RoutePolicy {
                mtu: Some(1500),
                advertised_mss: Some(1460),
                initial_search_low: Some(552),
                ..Default::default()
            }),
        ),
    )
    .unwrap();
    assert_eq!(
        a.endpoint.path_mtu_info(id).unwrap().unwrap().current_mtu,
        640
    );
    assert_eq!(a.endpoint.transport_info(id).unwrap().advertised_mss, 600);
    let fd = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(fd, Op::Connect("10.73.0.3:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let Handle::Connection(next) = a.sockets[&fd].handle else {
        panic!()
    };
    assert_eq!(
        a.endpoint.transport_info(next).unwrap().advertised_mss,
        1460
    );
    a.endpoint.enable_output_reservations().unwrap();
    let (_, token) = a
        .endpoint
        .poll_reserved_transmit_for(1000, next, &mut bytes, 64)
        .unwrap();
    let before = (
        a.endpoint.path_mtu_info(id).unwrap(),
        a.endpoint.path_mtu_info(next).unwrap(),
        a.endpoint.destination_route(remote.into()),
    );
    a.test_now = Some(2000);
    assert_eq!(
        a.execute(0, Op::SetDestinationRoute(remote, Some(policy)))
            .unwrap_err(),
        EAGAIN
    );
    assert_eq!(
        (
            a.endpoint.path_mtu_info(id).unwrap(),
            a.endpoint.path_mtu_info(next).unwrap(),
            a.endpoint.destination_route(remote.into())
        ),
        before
    );
    assert!(a.endpoint.accept_transmit(1001, token.unwrap()).unwrap());
}
