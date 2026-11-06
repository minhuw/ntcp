// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::timestamp_tests::{timestamp_records, timestamp_set};
use super::*;
use crate::timestamping as ts;
use ntcp::wire::{self, ACK, PSH, SYN};

struct Fixture {
    owner: Owner,
    id: u64,
    cid: ConnectionId,
    ip: ntcp::IpMetadata,
    incoming: wire::Header,
    iss: u32,
}

fn fixture() -> Fixture {
    fixture_with_window(2000)
}

fn fixture_with_window(window: u16) -> Fixture {
    let settings = crate::packet_profile::profile("upstream,local=192.168.0.1").unwrap();
    let mut a = Owner::packet(settings).unwrap();
    a.test_now = Some(0);
    let id = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(id, Op::Connect("192.0.2.1:8080".parse().unwrap()))
            .unwrap_err(),
        EINPROGRESS
    );
    let mut bytes = [0; 2048];
    let tx = a
        .endpoint
        .poll_transmit(0, &mut bytes, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
    let iss = syn.header.sequence;
    let syn_timestamp = syn.options.timestamps.unwrap().0;
    let incoming = wire::Header {
        source_port: 8080,
        destination_port: syn.header.source_port,
        sequence: 0,
        acknowledgment: iss.wrapping_add(1),
        flags: SYN | ACK,
        window,
        urgent_pointer: 0,
    };
    let ip = ntcp::IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let mut options = [
        2, 4, 3, 232, 4, 2, 8, 10, 0, 0, 2, 188, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    options[12..16].copy_from_slice(&syn_timestamp.to_be_bytes());
    let n = wire::encode(ip, incoming, &options, &[], &mut bytes).unwrap();
    a.test_now = Some(10000);
    a.input(10000, ip, 0, &bytes[..n]).unwrap();
    a.events();
    let Handle::Connection(cid) = a.sockets[&id].handle else {
        panic!()
    };
    let mut f = Fixture {
        owner: a,
        id,
        cid,
        ip,
        incoming,
        iss,
    };
    assert!(drain(&mut f).is_empty()); // Pure handshake ACK has no payload.
    f.owner
        .execute(id, Op::Set(SOL_SOCKET, SO_SNDBUF, 1000))
        .unwrap();
    assert_eq!(
        f.owner
            .execute(id, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value,
        4608
    );
    timestamp_set(
        &mut f.owner,
        id,
        ts::TX_SCHED | ts::TX_SOFTWARE | ts::TX_ACK | ts::SOFTWARE | ts::OPT_ID,
    );
    let info = f.owner.endpoint.transport_info(cid).unwrap();
    // SO_SNDBUF stays the logical capacity B; admission rounds it down to
    // whole 988-octet segments (RFC 1191 section 6.4): C = 4 * 988.
    assert_eq!(
        (info.mss, info.max_send_window, info.send_capacity, info.send_space),
        (988, u32::from(window), 4608, 3952)
    );
    f
}

fn drain(f: &mut Fixture) -> Vec<(u32, usize, bool)> {
    let mut packets = Vec::new();
    for _ in 0..BUDGET {
        let mut bytes = [0; 2048];
        let pair = ClockPair::sample(&mut f.owner).unwrap();
        let Some(tx) = f
            .owner
            .endpoint
            .poll_transmit(f.owner.now(), &mut bytes, BUDGET)
            .unwrap()
            .packet
        else {
            f.owner.events();
            return packets;
        };
        let p = wire::parse(tx.ip, &bytes[..tx.len]).unwrap();
        if !p.payload.is_empty() {
            packets.push((
                p.header.sequence.wrapping_sub(f.iss),
                p.payload.len(),
                p.header.flags & PSH != 0,
            ));
        }
        let frame = ip_packet(&f.owner, tx, &bytes[..tx.len]);
        f.owner.timestamp_packet(tx.tx_timestamp, &frame);
        f.owner.drain_timestamps(pair);
        f.owner
            .software_transmitted(tx.tx_timestamp, timestamps::realtime());
    }
    panic!("output did not quiesce");
}

fn ack(f: &mut Fixture, now: u64, data: u32) {
    let header = wire::Header {
        sequence: 1,
        acknowledgment: f.iss.wrapping_add(1 + data),
        flags: ACK,
        window: 92,
        ..f.incoming
    };
    let mut bytes = [0; 2048];
    let peer_ts = 800u32.to_be_bytes();
    let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    options[4..8].copy_from_slice(&peer_ts);
    let n = wire::encode(f.ip, header, &options, &[], &mut bytes).unwrap();
    f.owner.test_now = Some(now);
    f.owner.input(now, f.ip, 0, &bytes[..n]).unwrap();
    f.owner.events();
    let current = ClockPair::sample(&mut f.owner).unwrap();
    f.owner.drain_timestamps(current);
}

#[test]
fn timestamp_partial_actual_admission_and_first_flight() {
    let mut f = fixture();
    let bytes = vec![0x55; 10000];
    let n = f
        .owner
        .execute(
            f.id,
            Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0),
        )
        .unwrap()
        .value;
    assert_eq!(n, 3952);
    let before = f.owner.endpoint.transport_info(f.cid).unwrap();
    assert_eq!((before.send_used, before.notsent_bytes), (3952, 3952));
    let packets = drain(&mut f);
    assert_eq!(
        packets.iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(),
        [(1, 988), (989, 988), (1977, 24)]
    );
    let after = f.owner.endpoint.transport_info(f.cid).unwrap();
    assert_eq!((after.send_used, after.notsent_bytes), (3952, 1952));
    assert!(timestamp_records(&f.owner, f.id).is_empty());
}

#[test]
fn timestamp_partial_controlled_prefix_tracks_last_byte_and_all_phases() {
    let mut f = fixture();
    // Counterfactual admission only: request the Linux-sized prefix explicitly.
    // The real socket still has SO_SNDBUF4608 and unlimited NOTSENT_LOWAT.
    let bytes = vec![0x55; 2964];
    assert_eq!(
        f.owner
            .execute(
                f.id,
                Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0)
            )
            .unwrap()
            .value,
        2964
    );
    let initial = drain(&mut f);
    assert_eq!(
        initial.iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(),
        [(1, 988), (989, 988)]
    );
    assert!(timestamp_records(&f.owner, f.id).is_empty());
    ack(&mut f, 20000, 1976);
    let tail = drain(&mut f);
    assert_eq!(tail, [(1977, 988, true)]);
    let first = timestamp_records(&f.owner, f.id);
    assert_eq!(first.len(), 2, "{first:?}");
    assert!(first.iter().all(|r| r.1 == 2963 && r.2 > 0 && r.4 > 0));
    assert!(first.iter().any(|r| r.0 == 0));
    assert!(first.iter().any(|r| r.0 == 1));
    ack(&mut f, 30000, 2964);
    let last = timestamp_records(&f.owner, f.id);
    assert_eq!(last.len(), 3, "{last:?}");
    assert!(last.iter().all(|r| r.1 == 2963 && r.2 > 0 && r.4 > 0));
    assert_eq!(last.iter().filter(|r| r.0 == 2).count(), 1);
    let info = f.owner.endpoint.transport_info(f.cid).unwrap();
    assert!((5000..=20000).contains(&info.rtt_us.unwrap()));
    assert_eq!(info.send_used, 0);
}

#[test]
fn timestamp_partial_native_accounting_fixture_keeps_all_phases() {
    let mut f = fixture_with_window(2 * 988);
    let bytes = vec![0x55; 10000];
    assert_eq!(
        f.owner
            .execute(
                f.id,
                Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0)
            )
            .unwrap()
            .value,
        3952
    );
    assert_eq!(drain(&mut f), [(1, 988, false), (989, 988, true)]);
    assert!(timestamp_records(&f.owner, f.id).is_empty());
    ack(&mut f, 20000, 1976);
    assert_eq!(
        drain(&mut f),
        [(1977, 988, false), (2965, 988, true)]
    );
    let first = timestamp_records(&f.owner, f.id);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|r| r.1 == 3951 && r.2 > 0 && r.4 > 0));
    ack(&mut f, 30000, 3952);
    let last = timestamp_records(&f.owner, f.id);
    assert_eq!(last.len(), 3);
    assert!(last.iter().all(|r| r.1 == 3951 && r.2 > 0 && r.4 > 0));
    for stage in 0..3 {
        assert_eq!(last.iter().filter(|r| r.0 == stage).count(), 1);
    }
}

// Writable readiness follows the rounded admission ceiling C, not the
// SO_SNDBUF capacity B that getsockopt keeps reporting.
#[test]
fn writable_readiness_agrees_with_rounded_admission() {
    let mut f = fixture();
    let writable = |f: &mut Fixture| f.owner.execute(f.id, Op::Ready).unwrap().value & EPOLLOUT != 0;
    let room = |f: &Fixture| f.owner.endpoint.send_admission_room(f.cid, None).unwrap();
    let bytes = vec![0x55; 10000];
    let send = |f: &mut Fixture| {
        f.owner
            .execute(f.id, Op::Send(vec![(bytes.as_ptr() as usize, bytes.len())], 0))
            .map(|r| r.value)
    };
    assert_eq!(send(&mut f).unwrap(), 3952);
    drain(&mut f);
    let info = f.owner.endpoint.transport_info(f.cid).unwrap();
    assert!(info.send_used < info.send_capacity);
    assert_eq!(room(&f), 0);
    assert!(!writable(&mut f));
    assert_eq!(send(&mut f), Err(EAGAIN));
    // A partial ACK drains below C and reopens both together.
    ack(&mut f, 20000, 988);
    assert_eq!(room(&f), 988);
    assert!(writable(&mut f));
    assert_eq!(send(&mut f).unwrap(), 988);
    assert!(!writable(&mut f));
    // A live resize keeps reporting B and moves C with it.
    f.owner
        .execute(f.id, Op::Set(SOL_SOCKET, SO_SNDBUF, 3000))
        .unwrap();
    assert_eq!(
        f.owner
            .execute(f.id, Op::Get(SOL_SOCKET, SO_SNDBUF))
            .unwrap()
            .value,
        6000
    );
    let info = f.owner.endpoint.transport_info(f.cid).unwrap();
    assert_eq!((info.send_capacity, info.send_space), (6000, 5928));
    assert_eq!(room(&f), 5928 - 3952);
    assert!(writable(&mut f));
}
