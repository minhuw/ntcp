// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Exact-clock counterpart to the realtime ntcp-accounting packetdrill fixture.
#[cfg(feature = "packet-test")]
#[test]
fn sndbuf_accounting_fixture_has_exact_positive_interval_and_valid_acks() {
    use ntcp::wire::{self, ACK, SYN};
    let mut a =
        Owner::packet(crate::packet_profile::profile("upstream,local=192.168.0.1").unwrap())
            .unwrap();
    a.test_now = Some(0);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Connect("192.0.2.1:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let mut bytes = [0; 2048];
    let syn = a
        .endpoint
        .poll_transmit(0, &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn_header = wire::parse(syn.ip, &bytes[..syn.len]).unwrap().header;
    let iss = syn_header.sequence;
    let ip = ntcp::IpMetadata {
        source: syn.ip.destination,
        destination: syn.ip.source,
    };
    let mut incoming = wire::Header {
        source_port: 8080,
        destination_port: syn_header.source_port,
        sequence: 0,
        acknowledgment: iss.wrapping_add(1),
        flags: SYN | ACK,
        window: 10000,
        urgent_pointer: 0,
    };
    let n = wire::encode(
        ip,
        incoming,
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 8],
        &[],
        &mut bytes,
    )
    .unwrap();
    a.test_now = Some(10000);
    a.input(10000, ip, 0, &bytes[..n]).unwrap();
    a.events();
    let Handle::Connection(cid) = a.sockets[&id].handle else {
        panic!()
    };
    let mut frontier = 1;
    fn drain(a: &mut Owner, iss: u32, frontier: &mut u32) {
        for _ in 0..BUDGET {
            let mut bytes = [0; 2048];
            let Some(tx) = a
                .endpoint
                .poll_transmit(a.now(), &mut bytes, BUDGET)
                .unwrap()
                .packet
            else {
                a.events();
                return;
            };
            let packet = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
            if !packet.payload.is_empty() {
                assert_eq!(packet.header.sequence.wrapping_sub(iss), *frontier);
                *frontier += packet.payload.len() as u32;
            }
        }
        panic!("output did not quiesce");
    }
    drain(&mut a, iss, &mut frontier);
    a.execute(id, Op::Set(SOL_SOCKET, SO_SNDBUF, 10000))
        .unwrap();
    let payload = vec![9; 60000];
    let (mut request, rx) = logical_request(
        &mut a,
        id,
        Op::Send(vec![(payload.as_ptr() as usize, payload.len())], 0),
    );
    a.test_now = Some(100000);
    a.endpoint.on_timeout(100000, 0).unwrap(); // Normal owner-loop clock boundary.
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 20000);
    drain(&mut a, iss, &mut frontier);
    assert_eq!(frontier, 10001);
    incoming.sequence = 1;
    incoming.flags = ACK;
    for (now, ack, expected_end, expected_cwnd, done) in [
        (110000, 10001, 28001, 18000, false),
        (120000, 28001, 48001, 26000, false),
        (140000, 48001, 60001, 26000, true),
    ] {
        assert!(ack <= frontier, "ACK must not acknowledge unsent bytes");
        incoming.acknowledgment = iss.wrapping_add(ack);
        let n = wire::encode(ip, incoming, &[], &[], &mut bytes).unwrap();
        a.test_now = Some(now);
        a.input(now, ip, 0, &bytes[..n]).unwrap();
        a.events();
        drain(&mut a, iss, &mut frontier);
        assert_eq!(a.service(&mut request), done);
        drain(&mut a, iss, &mut frontier);
        assert_eq!(frontier, expected_end);
        let info = a.endpoint.transport_info(cid).unwrap();
        assert_eq!(info.cwnd, expected_cwnd);
        if now == 120000 {
            assert_eq!((info.send_used, info.notsent_bytes), (20000, 0));
            assert!(!a.service(&mut request)); // A real blocked writer, not fabricated NOSPACE.
        }
    }
    assert_eq!(rx.try_recv().unwrap().unwrap().value, 60000);
    a.test_now = Some(150000);
    a.execute(id, Op::Ready).unwrap(); // Advance endpoint sampling clock.
    let first = a.endpoint.transport_info(cid).unwrap();
    assert_eq!(
        (
            first.busy_time_us,
            first.sndbuf_limited_us,
            first.rwnd_limited_us
        ),
        (50000, 20000, 0)
    );
    incoming.acknowledgment = iss.wrapping_add(60001);
    let n = wire::encode(ip, incoming, &[], &[], &mut bytes).unwrap();
    a.test_now = Some(170000);
    a.input(170000, ip, 0, &bytes[..n]).unwrap();
    a.events();
    let final_info = a.endpoint.transport_info(cid).unwrap();
    assert_eq!(
        (
            final_info.busy_time_us,
            final_info.sndbuf_limited_us,
            final_info.rwnd_limited_us
        ),
        (70000, 20000, 0)
    );
    assert_eq!(final_info.send_used, 0);
}
