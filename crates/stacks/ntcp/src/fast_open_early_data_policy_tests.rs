use super::*;
use std::{format, vec};

fn server() -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 32,
            max_listeners: 4,
            connection: ConnectionConfig {
                mss: 1460,
                send_capacity: 8192,
                receive_capacity: 8192,
                nagle: false,
                timestamps: false,
                ..Default::default()
            },
            ..Default::default()
        },
        [42; 32],
        0,
        |_| true,
    )
    .unwrap()
}
fn pair(v6: bool, port: u16) -> (SocketAddr, SocketAddr) {
    if v6 {
        (
            format!("[2001:db8::1]:{port}").parse().unwrap(),
            "[2001:db8::2]:40000".parse().unwrap(),
        )
    } else {
        (
            format!("192.168.0.1:{port}").parse().unwrap(),
            "192.0.2.1:40000".parse().unwrap(),
        )
    }
}
fn inject(
    endpoint: &mut Endpoint,
    local: SocketAddr,
    remote: SocketAddr,
    token: &str,
    payload: &[u8],
) -> ConnectionId {
    inject_flags(endpoint, local, remote, token, payload, wire::SYN)
}

fn inject_flags(
    endpoint: &mut Endpoint,
    local: SocketAddr,
    remote: SocketAddr,
    token: &str,
    payload: &[u8],
    flags: u8,
) -> ConnectionId {
    let ip = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let valid = crate::fast_open::issue(&[42; 32], local.ip(), remote.ip(), 0);
    let raw = match token {
        "absent" => vec![],
        "empty" => vec![34, 2, 1, 1],
        "valid" => {
            let mut v = vec![34, 10];
            v.extend_from_slice(valid.as_bytes());
            v.extend([1, 1]);
            v
        }
        "invalid" => {
            let mut v = vec![34, 10];
            v.extend_from_slice(&[0x7b; 8]);
            v.extend([1, 1]);
            v
        }
        "malformed" => vec![34, 3, 0, 1],
        "duplicate" => vec![34, 2, 34, 2],
        "experimental" => vec![254, 4, 0xf9, 0x89],
        _ => panic!(),
    };
    // A valid unknown TLV allows constructing raw malformed/duplicate kind34
    // bytes without asking the outbound codec to emit prohibited TFO metadata.
    let mut outbound = raw.clone();
    let mut offset = 0;
    while offset < outbound.len() {
        match outbound[offset] {
            0 => break,
            1 => offset += 1,
            _ => {
                if outbound[offset] == 34 {
                    outbound[offset] = 253;
                }
                offset += usize::from(outbound[offset + 1]);
            }
        }
    }
    let mut wire_bytes = vec![0; 128];
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: remote.port(),
            destination_port: local.port(),
            sequence: 100,
            acknowledgment: 0,
            flags,
            window: 8192,
            urgent_pointer: 0,
        },
        &outbound,
        payload,
        &mut wire_bytes,
    )
    .unwrap();
    wire_bytes[20..20 + raw.len()].copy_from_slice(&raw);
    wire_bytes[16..18].fill(0);
    let checksum = wire::checksum(ip, &wire_bytes[..n]).unwrap();
    wire_bytes[16..18].copy_from_slice(&checksum.to_be_bytes());
    endpoint.input(0, ip, &wire_bytes[..n]).unwrap();
    endpoint.connection_id(Tuple { local, remote }).unwrap()
}
fn reply(endpoint: &mut Endpoint) -> (ConnectionId, u32, Option<FastOpenCookie>) {
    let (child, cookie, ack) = response(endpoint);
    (child, ack, cookie)
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-2
//= type=test
//= reason=Default per-listener RequireCookie and independent disabled service/listener state are exercised; choosing protected policy never enables TFO.
//# TCP implementations MUST NOT use TFO by default, but only use TFO if requested explicitly by the application on a per-service-port basis.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
//= type=test
//= reason=Service and listener enablement remain independent of early-data authorization; disabled listeners keep ordinary handshake and no cookie response.
//# FastOpenEnabled: default is off. It MUST be turned on explicitly by the application. When this flag is off, the server does not perform any TFO-related operations and MUST ignore all cookie options.
//= https://www.rfc-editor.org/rfc/rfc7413#section-7.3
//= type=test
//= reason=ApplicationProtected is an explicit host assertion of independent application defenses, not a proof of application security; tests show authorization replaces MAC checks only for this opt-in. Omitted-option wire behavior is a Linux-compatible choice.
//# cookies are not necessary if the server has application-level protection or is immune to these attacks.
#[test]
fn cookie_less_authorization_matrix_ipv4_ipv6() {
    let mut cells = 0;
    for v6 in [false, true] {
        for protected in [false, true] {
            for enabled in [false, true] {
                for token in [
                    "absent",
                    "empty",
                    "valid",
                    "invalid",
                    "malformed",
                    "duplicate",
                    "experimental",
                ] {
                    for data in [b"".as_slice(), b"early".as_slice()] {
                        let mut ep = server();
                        ep.enable_fast_open().unwrap();
                        let (local, remote) = pair(v6, 8080);
                        let listener = ep.listen(local, 8).unwrap();
                        if enabled {
                            ep.set_listener_fast_open(listener, 2).unwrap();
                        }
                        if protected {
                            ep.set_listener_fast_open_early_data_policy(
                                listener,
                                FastOpenEarlyDataPolicy::ApplicationProtected,
                            )
                            .unwrap();
                        }
                        let id = inject(&mut ep, local, remote, token, data);
                        let (_, header, response_cookie) = reply(&mut ep);
                        let app = protected
                            && (matches!(token, "empty" | "valid" | "invalid") || !data.is_empty());
                        let early = enabled && (token == "valid" || app);
                        assert_eq!(
                            header,
                            100 + 1 + if early { data.len() as u32 } else { 0 },
                            "{v6} {protected} {enabled} {token}"
                        );
                        assert_eq!(
                            ep.readable_bytes(id).unwrap(),
                            if early { data.len() } else { 0 }
                        );
                        assert_eq!(
                            ep.transport_info(id).unwrap().syn_data_acked,
                            early && !data.is_empty()
                        );
                        assert_eq!(ep.accept(listener).is_ok(), early);
                        assert_eq!(
                            response_cookie.is_some(),
                            enabled && !protected && matches!(token, "empty" | "valid" | "invalid")
                        );
                        cells += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cells, 112);
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2
//= type=test
//= reason=Application-protected admissions reuse pending plus reset-debt quota; accepting/reading and a reset do not create new admission credit.
//# If this variable goes over a preset system limit, the server MUST disable TFO for all new connection requests until PendingFastOpenRequests drops below the system limit.
#[test]
fn cookieless_accept_and_read_do_not_release_pending_quota_or_reset_debt() {
    for v6 in [false, true] {
        let mut ep = server();
        ep.enable_fast_open().unwrap();
        let (local, mut remote) = pair(v6, 8080);
        let listener = ep.listen(local, 8).unwrap();
        ep.set_listener_fast_open(listener, 1).unwrap();
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
        let first = inject(&mut ep, local, remote, "absent", b"early");
        reply(&mut ep);
        assert_eq!(ep.accept(listener), Ok(first));
        assert_eq!(ep.read(first, &mut [0; 5]), Ok(5));
        remote.set_port(40001);
        let second = inject(&mut ep, local, remote, "absent", b"early");
        assert_eq!(reply(&mut ep).1, 101);
        assert_eq!(ep.readable_bytes(second), Ok(0));
        let remote_first = SocketAddr::new(remote.ip(), 40000);
        let ip = IpMetadata {
            source: remote.ip(),
            destination: local.ip(),
        };
        let mut bytes = [0; 64];
        let n = wire::encode(
            ip,
            wire::Header {
                source_port: remote_first.port(),
                destination_port: local.port(),
                sequence: 106,
                acknowledgment: 0,
                flags: wire::RST,
                window: 0,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut bytes,
        )
        .unwrap();
        ep.input(0, ip, &bytes[..n]).unwrap();
        assert_eq!(ep.state(first), Ok(State::Closed));
        ep.release(first).unwrap();
        remote.set_port(40002);
        let third = inject(&mut ep, local, remote, "absent", b"early");
        assert_eq!(reply(&mut ep).1, 101);
        assert_eq!(ep.readable_bytes(third), Ok(0));
    }
}

#[test]
fn cookieless_policy_is_listener_local_and_revoke_is_future_only() {
    let mut ep = server();
    ep.enable_fast_open().unwrap();
    let (a, mut remote) = pair(false, 8080);
    let (b, _) = pair(false, 8081);
    let listener_a = ep.listen(a, 8).unwrap();
    let listener_b = ep.listen(b, 8).unwrap();
    ep.set_listener_fast_open(listener_a, 2).unwrap();
    ep.set_listener_fast_open(listener_b, 2).unwrap();
    ep.set_listener_fast_open_early_data_policy(
        listener_a,
        FastOpenEarlyDataPolicy::ApplicationProtected,
    )
    .unwrap();
    let first = inject(&mut ep, a, remote, "absent", b"early");
    reply(&mut ep);
    remote.set_port(40001);
    let other = inject(&mut ep, b, remote, "absent", b"early");
    reply(&mut ep);
    assert_eq!(ep.readable_bytes(other), Ok(0));
    assert!(ep.accept(listener_b).is_err());
    ep.set_listener_fast_open_early_data_policy(listener_a, FastOpenEarlyDataPolicy::RequireCookie)
        .unwrap();
    assert_eq!(ep.accept(listener_a), Ok(first));
    assert_eq!(ep.read(first, &mut [0; 5]), Ok(5));
    remote.set_port(40002);
    let next = inject(&mut ep, a, remote, "absent", b"early");
    reply(&mut ep);
    assert_eq!(ep.readable_bytes(next), Ok(0));
    assert!(ep.accept(listener_a).is_err());
    // Reuse an unused listener slot: closing a live listener with children
    // deliberately retains that address until their ownership is settled.
    let mut other = server();
    other.enable_fast_open().unwrap();
    let stale = other.listen(b, 8).unwrap();
    other
        .set_listener_fast_open_early_data_policy(
            stale,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
    other.close_listener(stale).unwrap();
    for _ in 0..32 {
        other.poll_transmit(0, &mut [0; 2048], 64).unwrap();
    }
    let replacement = other.listen(b, 8).unwrap();
    assert_eq!(
        other.set_listener_fast_open_early_data_policy(
            stale,
            FastOpenEarlyDataPolicy::ApplicationProtected
        ),
        Err(EndpointError::InvalidHandle)
    );
    other.set_listener_fast_open(replacement, 2).unwrap();
    remote.set_port(40003);
    let next = inject(&mut other, b, remote, "absent", b"early");
    reply(&mut other);
    assert_eq!(other.readable_bytes(next), Ok(0));
}

#[test]
fn cookieless_reserved_synack_metrics_and_abandon_remain_transactional() {
    for abandon in [false, true] {
        let mut ep = server();
        ep.enable_fast_open().unwrap();
        ep.enable_output_reservations().unwrap();
        let (local, remote) = pair(false, 8080);
        let listener = ep.listen(local, 8).unwrap();
        ep.set_listener_fast_open(listener, 1).unwrap();
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
        let id = inject(&mut ep, local, remote, "absent", b"early");
        let mut bytes = [0; 2048];
        let (output, attempt) = ep
            .poll_reserved_transmit_for(0, id, &mut bytes, 64)
            .unwrap();
        let tx = output.packet.unwrap();
        let attempt = attempt.unwrap();
        // Policy revocation applies to future children, including while this
        // child's output is held for a backend admission decision.
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::RequireCookie,
        )
        .unwrap();
        assert_eq!(
            wire::parse(tx.ip, &bytes[..tx.len])
                .unwrap()
                .header
                .acknowledgment,
            106
        );
        assert!(!ep.transport_info(id).unwrap().syn_data_acked);
        if abandon {
            assert!(ep.abandon_transmit(attempt).unwrap());
            assert!(!ep.accept_transmit(0, attempt).unwrap());
            assert!(!ep.transport_info(id).unwrap().syn_data_acked);
        } else {
            assert!(ep.reject_unsubmitted(attempt).unwrap());
            let (_, retry) = ep
                .poll_reserved_transmit_for(0, id, &mut bytes, 64)
                .unwrap();
            ep.accept_transmit(0, retry.unwrap()).unwrap();
            assert!(ep.transport_info(id).unwrap().syn_data_acked);
            assert_eq!(ep.accept(listener), Ok(id));
        }
    }
}

#[test]
fn cookieless_retransmitted_syn_does_not_requeue_or_redeliver_application_bytes() {
    for v6 in [false, true] {
        let mut ep = server();
        ep.enable_fast_open().unwrap();
        let (local, remote) = pair(v6, 8080);
        let listener = ep.listen(local, 8).unwrap();
        ep.set_listener_fast_open(listener, 1).unwrap();
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
        let id = inject(&mut ep, local, remote, "absent", b"early");
        reply(&mut ep);
        assert_eq!(ep.accept(listener), Ok(id));
        assert_eq!(ep.read(id, &mut [0; 5]), Ok(5));
        let repeated = inject(&mut ep, local, remote, "absent", b"early");
        assert_eq!(id, repeated);
        let (_, header, _) = reply(&mut ep);
        assert_eq!(header, 106);
        assert_eq!(ep.readable_bytes(id), Ok(0));
        assert!(ep.accept(listener).is_err());
        // Revoking future authorization does not erase already-admitted child
        // state or make a repeated SYN allocate a new early quota entry.
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::RequireCookie,
        )
        .unwrap();
        assert_eq!(inject(&mut ep, local, remote, "absent", b"early"), id);
        assert_eq!(reply(&mut ep).1, 106);
        assert_eq!(ep.readable_bytes(id), Ok(0));
    }
}

#[test]
fn protected_policy_setter_does_not_enable_service_or_allocate() {
    let mut ep = server();
    let (local, remote) = pair(false, 8080);
    let listener = ep.listen(local, 8).unwrap();
    let before = ep.buffer_bytes();
    crate::allocation_tests::fail_after(0, || {
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap()
    });
    assert_eq!(ep.buffer_bytes(), before);
    assert!(ep.set_listener_fast_open(listener, 1).is_err());
    let id = inject(&mut ep, local, remote, "absent", b"early");
    reply(&mut ep);
    assert_eq!(ep.readable_bytes(id), Ok(0));
    assert!(ep.accept(listener).is_err());
}

//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Server policy selection does not change the ordinary active-open path: cold client accepts zero initial data and sends a cookie request.
//# To open a TFO connection, the client MUST have obtained a cookie from the server:
#[test]
fn protected_server_policy_does_not_enable_cookieless_client_open() {
    let mut ep = server();
    ep.enable_fast_open().unwrap();
    let (local, remote) = pair(false, 8080);
    let listener = ep.listen(local, 8).unwrap();
    ep.set_listener_fast_open(listener, 1).unwrap();
    ep.set_listener_fast_open_early_data_policy(
        listener,
        FastOpenEarlyDataPolicy::ApplicationProtected,
    )
    .unwrap();
    let (_, accepted) = ep
        .connect_fast_open(0, local, remote, b"client data")
        .unwrap();
    assert_eq!(accepted, 0);
    let mut bytes = [0; 2048];
    let tx = ep.poll_transmit(0, &mut bytes, 64).unwrap().packet.unwrap();
    let (ip, bytes) = (tx.ip, &bytes[..tx.len]);
    let syn = wire::parse(ip, bytes).unwrap();
    assert_eq!(syn.options.fast_open, Some(FastOpenCookie::request()));
    assert!(syn.payload.is_empty());
}

#[test]
fn protected_syn_fin_uses_pending_quota_and_acknowledges_fin() {
    for v6 in [false, true] {
        let mut ep = server();
        ep.enable_fast_open().unwrap();
        let (local, mut remote) = pair(v6, 8080);
        let listener = ep.listen(local, 8).unwrap();
        ep.set_listener_fast_open(listener, 1).unwrap();
        ep.set_listener_fast_open_early_data_policy(
            listener,
            FastOpenEarlyDataPolicy::ApplicationProtected,
        )
        .unwrap();
        let id = inject_flags(&mut ep, local, remote, "absent", b"", wire::SYN | wire::FIN);
        assert_eq!(reply(&mut ep).1, 102);
        assert_eq!(ep.accept(listener), Ok(id));
        assert_eq!(ep.read(id, &mut [0; 1]), Ok(0));
        remote.set_port(40001);
        let blocked = inject(&mut ep, local, remote, "absent", b"early");
        assert_eq!(reply(&mut ep).1, 101);
        assert_eq!(ep.readable_bytes(blocked), Ok(0));
    }
}
