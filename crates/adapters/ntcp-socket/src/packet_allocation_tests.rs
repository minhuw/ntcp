// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use crate::packet_test::Options;

fn accepted(owner: &mut Owner, port: u16) -> u64 {
    let listener = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    owner
        .inner
        .execute(listener, Op::Bind(SocketAddr::new(local().into(), port)))
        .unwrap();
    owner.inner.execute(listener, Op::Listen(1)).unwrap();
    let syn = syn_with_options(0, port, &[2, 4, 5, 180, 1, 3, 3, 0]);
    let ip = parse_frame(&syn).unwrap().0;
    let (mut incoming, _) = request(14, 0, 0, syn, 0);
    owner.execute(&mut incoming).unwrap();
    owner.inner.service_egress().unwrap();
    let syn_ack = owner.inner.execute(0, Op::Capture(BYTES)).unwrap();
    input_packet(
        owner,
        ip,
        ntcp::wire::Header {
            source_port: 50000,
            destination_port: port,
            sequence: 1,
            acknowledgment: packet_header(&syn_ack.bytes).sequence.wrapping_add(1),
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        },
        &[],
    );
    owner
        .inner
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64
}

#[test]
fn default_pipeline_large_write_sndbuf_fits_original_budget() {
    // Explicit 32 retains the old ENOBUFS boundary; user capacities are not clamped.
    for (options, expected) in [
        (Options::default(), Ok(())),
        (
            Options {
                egress_capacity: 2,
                ..Options::default()
            },
            Ok(()),
        ),
        (
            Options {
                egress_capacity: 32,
                ..Options::default()
            },
            Err(ENOBUFS),
        ),
    ] {
        let mut owner = Owner {
            inner: SocketOwner::packet_with_options((local(), Profile::Baseline), options).unwrap(),
        };
        owner.inner.test_now = Some(1000);
        assert!(owner.inner.egress.is_some());
        let fd = accepted(&mut owner, 8080);
        let before = owner.endpoint.buffer_bytes();
        assert_eq!(
            owner
                .inner
                .execute(fd, Op::Set(SOL_SOCKET, SO_SNDBUF, 200000))
                .map(|_| ()),
            expected,
        );
        let capacity = if expected.is_ok() { 400000 } else { 65536 };
        assert_eq!(
            owner
                .inner
                .execute(fd, Op::Get(SOL_SOCKET, SO_SNDBUF))
                .unwrap()
                .value,
            capacity
        );
        assert_eq!(
            owner
                .endpoint
                .buffer_capacities(owner.connection(fd).unwrap())
                .unwrap(),
            (capacity as usize, 65535)
        );
        assert!(owner.endpoint.buffer_bytes() <= 32 * 1024 * 1024);
        if expected.is_err() {
            assert_eq!(owner.endpoint.buffer_bytes(), before);
        }
    }
}

#[test]
fn default_egress_keeps_two_held_flows_independent() {
    assert_eq!(Options::default().egress_capacity, 2);
    let mut owner = Owner {
        inner: SocketOwner::packet_with_options(
            (local(), Profile::Baseline),
            // Only shrink the wire queue to force backpressure; use default egress.
            Options {
                queue_capacity: 1,
                ..Options::default()
            },
        )
        .unwrap(),
    };
    owner.inner.test_now = Some(1000);
    let a = accepted(&mut owner, 8080);
    let b = accepted(&mut owner, 8081);
    let aid = owner.connection(a).unwrap();
    let bid = owner.connection(b).unwrap();
    owner.inner.execute(a, Op::Write(vec![7; 4380])).unwrap();
    owner.inner.service_egress().unwrap();
    assert!(owner.endpoint.is_output_reserved(aid));
    owner.inner.execute(b, Op::Write(vec![8; 1460])).unwrap();
    owner.inner.service_egress().unwrap();
    assert!(owner.endpoint.is_output_reserved(aid));
    assert!(owner.endpoint.is_output_reserved(bid));
    let bport = owner.endpoint.tuple(bid).unwrap().local.port();
    let mut progressed = false;
    for _ in 0..4 {
        let packet = owner.inner.execute(0, Op::Capture(BYTES)).unwrap();
        if packet_header(&packet.bytes).source_port == bport {
            assert!(owner.endpoint.is_output_reserved(aid));
            progressed = true;
            break;
        }
        owner.inner.test_now = Some(owner.inner.now() + 1000);
        owner.inner.service_egress().unwrap();
    }
    assert!(progressed, "B must transmit while A still has held output");
}
