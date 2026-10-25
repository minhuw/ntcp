// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp::wire::{self, FastOpenCookie};

fn policy(byte: u8) -> FastOpenCookiePolicy {
    FastOpenCookiePolicy::LinuxSipHash24(LinuxSipHash24Key::new([byte; 16]))
}
fn set(owner: &mut Owner, id: u64, byte: u8) -> Result<Reply> {
    owner.execute(id, Op::SetFastOpenKey(LinuxSipHash24Key::new([byte; 16])))
}
fn syn(owner: &mut Owner, port: u16, remote_port: u16) {
    let ip = ntcp::IpMetadata {
        source: "192.0.2.1".parse().unwrap(),
        destination: owner.local.into(),
    };
    let mut bytes = [0; 128];
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: remote_port,
            destination_port: port,
            sequence: 100,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 8192,
            urgent_pointer: 0,
        },
        &[34, 2, 1, 1],
        &[],
        &mut bytes,
    )
    .unwrap();
    owner.endpoint.input(0, ip, &bytes[..n]).unwrap();
}
fn response(owner: &mut Owner) -> Option<FastOpenCookie> {
    let mut bytes = [0; 2048];
    let tx = owner
        .endpoint
        .poll_transmit(0, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    wire::parse(tx.ip, &bytes[..tx.len])
        .unwrap()
        .options
        .fast_open
}
fn listener(owner: &mut Owner, port: u16) -> u64 {
    let id = owner.execute(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    owner
        .execute(id, Op::Bind(SocketAddr::new(owner.local.into(), port)))
        .unwrap();
    id
}

#[test]
fn typed_default_staging_rotation_isolation_and_failed_handles() {
    let local = "192.168.0.1".parse().unwrap();
    let mut config = SocketConfig::new("test", local);
    config.fast_open_cookie_policy = policy(1);
    let mut owner =
        Owner::with_config(local, (local, 32), [42; 32], None, config.tcp.clone()).unwrap();
    owner.test_now = Some(0);
    let budget = owner.endpoint.buffer_bytes();
    owner.apply_socket_config(&config).unwrap();
    let a = listener(&mut owner, 8080);
    set(&mut owner, a, 2).unwrap();
    owner.execute(a, Op::Listen(8)).unwrap();
    assert_eq!(owner.endpoint.buffer_bytes(), budget);
    syn(&mut owner, 8080, 40000);
    assert_eq!(response(&mut owner), None); // Policy is not enablement.
    owner
        .execute(a, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    syn(&mut owner, 8080, 40001);
    set(&mut owner, a, 3).unwrap(); // Existing child retains key 2's response.
    let old = response(&mut owner).unwrap();
    syn(&mut owner, 8080, 40002);
    let new = response(&mut owner).unwrap();
    assert_ne!(old, new);
    set(&mut owner, a, 2).unwrap();
    syn(&mut owner, 8080, 40003);
    assert_eq!(response(&mut owner), Some(old));

    let b = listener(&mut owner, 8081);
    owner.execute(b, Op::Listen(8)).unwrap();
    owner
        .execute(b, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    syn(&mut owner, 8081, 40004);
    let inherited = response(&mut owner).unwrap();
    assert_ne!(inherited, old);
    config.fast_open_cookie_policy = policy(2);
    owner.apply_socket_config(&config).unwrap();
    syn(&mut owner, 8081, 40005);
    assert_eq!(response(&mut owner), Some(old));

    let Handle::Listener(handle) = owner.sockets[&a].handle else {
        panic!()
    };
    owner.endpoint.close_listener(handle).unwrap();
    assert_eq!(set(&mut owner, a, 9).unwrap_err(), EBADF);
    // Debug is redacted; verify retained policy by applying it to the live exact listener.
    let retained = owner.sockets[&a].fast_open_cookie_policy.clone();
    let Handle::Listener(handle) = owner.sockets[&b].handle else {
        panic!()
    };
    owner
        .endpoint
        .set_listener_fast_open_cookie_policy(handle, retained)
        .unwrap();
    syn(&mut owner, 8081, 40006);
    assert_eq!(response(&mut owner), Some(old));
    assert_eq!(set(&mut owner, u64::MAX, 9).unwrap_err(), EBADF);

    let active = listener(&mut owner, 8082);
    owner.sockets.get_mut(&active).unwrap().deferred_peer = Some("192.0.2.1:80".parse().unwrap());
    assert_eq!(set(&mut owner, active, 9).unwrap_err(), EINVAL);
    owner.sockets.get_mut(&active).unwrap().deferred_peer = None;
    assert_eq!(
        owner
            .execute(active, Op::Connect("192.0.2.1:80".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    assert_eq!(set(&mut owner, active, 9).unwrap_err(), EINVAL);
    assert!(owner.sockets[&active].fast_open_cookie_policy.is_none());
}

#[test]
fn socket_rotation_keeps_held_synack_and_budget_unchanged() {
    let local = "192.168.0.1".parse().unwrap();
    let mut owner = Owner::with_config(
        local,
        (local, 32),
        [42; 32],
        None,
        SocketConfig::new("test", local).tcp,
    )
    .unwrap();
    owner.test_now = Some(0);
    let id = listener(&mut owner, 8080);
    set(&mut owner, id, 1).unwrap();
    owner
        .execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 8))
        .unwrap();
    owner.execute(id, Op::Listen(8)).unwrap();
    owner.endpoint.enable_output_reservations().unwrap();
    syn(&mut owner, 8080, 40000);
    let mut bytes = [0; 2048];
    let (output, attempt) = owner
        .endpoint
        .poll_reserved_transmit(0, &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    let original = bytes[..tx.len].to_vec();
    let budget = owner.endpoint.buffer_bytes();
    set(&mut owner, id, 2).unwrap();
    assert_eq!(owner.endpoint.buffer_bytes(), budget);
    assert_eq!(&bytes[..tx.len], original);
    assert!(owner.endpoint.reject_unsubmitted(attempt.unwrap()).unwrap());
    let (output, retry) = owner
        .endpoint
        .poll_reserved_transmit_for(0, tx.connection.unwrap(), &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    let first = wire::parse(tx.ip, &original).unwrap();
    let next = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    assert_eq!(first.header, next.header);
    assert_eq!(first.options, next.options);
    assert_eq!(first.payload, next.payload);
    assert!(owner.endpoint.accept_transmit(0, retry.unwrap()).unwrap());
    syn(&mut owner, 8080, 40001);
    let (output, attempt) = owner
        .endpoint
        .poll_reserved_transmit(0, &mut bytes, 64)
        .unwrap();
    let tx = output.packet.unwrap();
    assert_ne!(
        wire::parse(tx.ip, &bytes[..tx.len])
            .unwrap()
            .options
            .fast_open,
        first.options.fast_open
    );
    assert!(owner.endpoint.accept_transmit(0, attempt.unwrap()).unwrap());
}
