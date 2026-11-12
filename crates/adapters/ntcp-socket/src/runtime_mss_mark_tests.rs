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

// Submits `from`'s output to its backend and delivers every accepted packet
// to `to`: each packet's TCP header and the mark it left with.
#[cfg(feature = "packet-test")]
fn exchange(from: &mut Owner, to: &mut Owner) -> Vec<(ntcp::wire::Header, u32, Vec<u8>)> {
    from.service_egress().unwrap();
    let mut result = Vec::new();
    for (reply, mark) in from.packets.as_mut().unwrap().output.drain(..) {
        let p = crate::ip::parse(&reply.bytes).unwrap();
        let header = ntcp::wire::parse(p.ip, p.payload).unwrap().header;
        result.push((header, mark, reply.bytes));
    }
    for (_, _, bytes) in &result {
        to.packets.as_mut().unwrap().inject(bytes.clone()).unwrap();
    }
    to.receive_batch(&mut vec![0; 65535]).unwrap();
    result
}

// A connection's packets carry its socket's SO_MARK, a child's inherited
// from its listener; once released into TIME-WAIT, its record's ACKs keep
// the mark the connection had (Linux's tw_mark, tcp_time_wait), whatever
// marks later sockets set; a reply for no socket carries none (Linux's
// control socket, tcp_v4_send_reset without a socket).
#[cfg(feature = "packet-test")]
#[test]
fn time_wait_record_acks_keep_the_connections_mark() {
    use crate::packet_profile::Profile;
    use ntcp::wire::{ACK, FIN, RST, SYN};
    let mut a = Owner::packet((Ipv4Addr::new(192, 0, 2, 1), Profile::Baseline)).unwrap();
    let mut b = Owner::packet((Ipv4Addr::new(192, 0, 2, 2), Profile::Baseline)).unwrap();
    let listener = new(&mut b, SOCK_NONBLOCK);
    b.execute(listener, Op::Set(SOL_SOCKET, SO_MARK, 7))
        .unwrap();
    b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
        .unwrap();
    b.execute(listener, Op::Listen(4)).unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b);
    let synack = exchange(&mut b, &mut a);
    assert_eq!(
        synack.iter().map(|p| (p.0.flags, p.1)).collect::<Vec<_>>(),
        [(SYN | ACK, 7)]
    );
    exchange(&mut a, &mut b);
    let server = b
        .execute(listener, Op::Accept(SOCK_NONBLOCK))
        .unwrap()
        .value as u64;
    assert_eq!(
        b.execute(server, Op::Get(SOL_SOCKET, SO_MARK))
            .unwrap()
            .value,
        7
    );
    let Handle::Connection(cid) = b.sockets[&server].handle else {
        panic!()
    };
    // The server closes first, under a mark set on the connection.
    b.execute(server, Op::Set(SOL_SOCKET, SO_MARK, 9)).unwrap();
    b.execute(server, Op::Close).unwrap();
    let fin = exchange(&mut b, &mut a);
    assert_eq!(
        fin.iter()
            .map(|p| (p.0.flags & FIN, p.1))
            .collect::<Vec<_>>(),
        [(FIN, 9)]
    );
    exchange(&mut a, &mut b);
    a.execute(client, Op::Close).unwrap();
    let peer_fin = exchange(&mut a, &mut b);
    assert_eq!(peer_fin.len(), 1);
    assert_ne!(peer_fin[0].0.flags & FIN, 0);
    let last_ack = exchange(&mut b, &mut a);
    assert_eq!(
        last_ack
            .iter()
            .map(|p| (p.0.flags, p.1))
            .collect::<Vec<_>>(),
        [(ACK, 9)]
    );
    // The owner loop releases the closed descriptor's connection; only its
    // TIME-WAIT record remains.
    assert_eq!(b.endpoint.state(cid), Ok(State::TimeWait));
    b.endpoint.release(cid).unwrap();
    assert!(!b.endpoint.connection_exists(cid));
    assert_eq!(b.endpoint.time_wait_connections(), 1);
    // A later socket's mark is its own and leaves the record's alone.
    let later = new(&mut b, SOCK_NONBLOCK);
    b.execute(later, Op::Set(SOL_SOCKET, SO_MARK, 11)).unwrap();
    assert_eq!(
        b.execute(later, Op::Connect("192.0.2.1:9000".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let syn = exchange(&mut b, &mut a);
    assert_eq!(
        syn.iter().map(|p| (p.0.flags, p.1)).collect::<Vec<_>>(),
        [(SYN, 11)]
    );
    // The repeated FIN reaches the record, which ACKs it on the stateless
    // lane with the connection's mark.
    b.packets
        .as_mut()
        .unwrap()
        .inject(peer_fin[0].2.clone())
        .unwrap();
    b.receive_batch(&mut vec![0; 65535]).unwrap();
    let record_ack = exchange(&mut b, &mut a);
    assert_eq!(
        record_ack
            .iter()
            .map(|p| (p.0.flags, p.0.destination_port, p.1))
            .collect::<Vec<_>>(),
        [(ACK, peer_fin[0].0.source_port, 9)]
    );
    // A reset for no socket leaves unmarked.
    let stray = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(stray, Op::Connect("192.0.2.2:9001".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    exchange(&mut a, &mut b);
    let reset = exchange(&mut b, &mut a);
    assert_eq!(
        reset
            .iter()
            .map(|p| (p.0.flags & RST, p.1))
            .collect::<Vec<_>>(),
        [(RST, 0)]
    );
}
