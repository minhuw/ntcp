// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

fn maxseg(o: &mut Owner, id: u64) -> i32 {
    o.execute(id, Op::Get(IPPROTO_TCP, TCP_MAXSEG))
        .unwrap()
        .value
}

#[test]
fn maxseg_wire_offer_negotiation_listener_snapshot_and_clear() {
    for timestamps in [false, true] {
        for pmtud in [false, true] {
            let config = |last| {
                let mut config = SocketConfig::new("test", Ipv4Addr::new(10, 73, 0, last)).tcp;
                config.connection.timestamps = timestamps;
                config.connection.pmtud = pmtud.then(|| ntcp::PmtudConfig::new(1500));
                config
            };
            let mut a = owner_with_config(2, config(2));
            let mut b = owner_with_config(3, config(3));
            let listener = new(&mut b, SOCK_NONBLOCK);
            b.execute(listener, Op::Bind("10.73.0.3:16379".parse().unwrap()))
                .unwrap();
            b.execute(listener, Op::Listen(16)).unwrap();
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 1100))
                .unwrap();
            let client = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(maxseg(&mut a, client), 1460);
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 1200))
                .unwrap();
            assert_eq!(maxseg(&mut a, client), 1200);
            assert_eq!(
                a.execute(client, Op::Connect("10.73.0.3:16379".parse().unwrap()))
                    .unwrap_err(),
                EINPROGRESS
            );
            for reverse in [false, true] {
                let (from, to, offer) = if reverse {
                    (&mut b, &mut a, 1100)
                } else {
                    (&mut a, &mut b, 1200)
                };
                let mut out = [0; 1500];
                let tx = from
                    .endpoint
                    .poll_transmit(from.now(), &mut out, BUDGET)
                    .unwrap()
                    .packet
                    .unwrap();
                let segment = ntcp::wire::parse(tx.ip, &out[..tx.len]).unwrap();
                assert_eq!(segment.options.mss, Some(offer));
                to.input(to.now(), tx.ip, tx.dscp << 2 | tx.ecn, &out[..tx.len])
                    .unwrap();
            }
            // Future listener changes cannot rewrite an already created child's offer.
            b.execute(listener, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 900))
                .unwrap();
            pump(&mut a, &mut b);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            let overhead = if timestamps { 12 } else { 0 };
            assert_eq!(maxseg(&mut a, client), 1100 - overhead);
            assert_eq!(maxseg(&mut b, server), 1100 - overhead);
            let info = b.execute(server, Op::Transport(1)).unwrap().bytes;
            assert_eq!(u32::from_ne_bytes(info[84..88].try_into().unwrap()), 1100);
            for invalid in [-1, 1, 87, 32768, i32::MAX] {
                assert_eq!(
                    b.execute(server, Op::Set(IPPROTO_TCP, TCP_MAXSEG, invalid))
                        .unwrap_err(),
                    EINVAL
                );
                assert_eq!(maxseg(&mut b, server), 1100 - overhead);
            }
            b.execute(server, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 300))
                .unwrap();
            assert_eq!(maxseg(&mut b, server), 300 - overhead);
            let info = b.execute(server, Op::Transport(1)).unwrap().bytes;
            assert_eq!(u32::from_ne_bytes(info[84..88].try_into().unwrap()), 1100);
            // A cap affects packetization, not the measured path MTU.
            let Handle::Connection(cid) = b.sockets[&server].handle else {
                panic!()
            };
            if pmtud {
                assert_eq!(
                    b.endpoint.path_mtu_info(cid).unwrap().unwrap().current_mtu,
                    1240
                );
            }
            b.execute(server, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 0))
                .unwrap();
            assert_eq!(maxseg(&mut b, server), 1200 - overhead);
            b.execute(server, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 300))
                .unwrap();
            b.execute(server, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1))
                .unwrap();
            b.execute(server, Op::Write(vec![7; 1000])).unwrap();
            let mut total = 0;
            for _ in 0..16 {
                let mut out = [0; 1500];
                let Some(tx) = b
                    .endpoint
                    .poll_transmit(b.now(), &mut out, BUDGET)
                    .unwrap()
                    .packet
                else {
                    break;
                };
                let segment = ntcp::wire::parse(tx.ip, &out[..tx.len]).unwrap();
                assert!(segment.payload.len() <= (300 - overhead) as usize);
                total += segment.payload.len();
            }
            assert!(total > 0);
        }
    }
}

#[cfg(feature = "packet-test")]
#[test]
fn packet_marks_are_per_flow_and_unmarked_packets_restore_zero() {
    let mut o = Owner::packet((
        Ipv4Addr::new(192, 0, 2, 1),
        crate::packet_profile::Profile::Baseline,
    ))
    .unwrap();
    let marked = new(&mut o, SOCK_NONBLOCK);
    let unmarked = new(&mut o, SOCK_NONBLOCK);
    o.execute(marked, Op::Set(SOL_SOCKET, SO_MARK, -1)).unwrap();
    assert_eq!(
        o.execute(marked, Op::Get(SOL_SOCKET, SO_MARK))
            .unwrap()
            .value,
        -1
    );
    for id in [marked, unmarked] {
        assert_eq!(
            o.execute(id, Op::Connect("192.0.2.2:9000".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
    }
    o.service_egress().unwrap();
    let mut marks: Vec<_> = o
        .packets
        .as_mut()
        .unwrap()
        .output
        .drain(..)
        .map(|(_, mark)| mark)
        .collect();
    marks.sort();
    assert_eq!(marks, [0, u32::MAX]);
    // Changing the option affects future submissions, not queued captures.
    o.execute(marked, Op::Set(SOL_SOCKET, SO_MARK, 0)).unwrap();
    o.test_now = o.endpoint.next_deadline();
    o.endpoint.on_timeout(o.now(), BUDGET).unwrap();
    o.service_egress().unwrap();
    let captures = &o.packets.as_ref().unwrap().output;
    assert!(!captures.is_empty());
    assert!(captures.iter().all(|&(_, mark)| mark == 0));
}

#[test]
fn backend_without_marks_rejects_nonzero_without_committing() {
    let mut o = owner(2);
    let id = new(&mut o, SOCK_NONBLOCK);
    assert_eq!(
        o.execute(id, Op::Set(SOL_SOCKET, SO_MARK, 666))
            .unwrap_err(),
        EOPNOTSUPP
    );
    assert_eq!(
        o.execute(id, Op::Get(SOL_SOCKET, SO_MARK)).unwrap().value,
        0
    );
}
