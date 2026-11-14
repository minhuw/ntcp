// Every reason the Endpoint records a discard for, triggered by the segment
// or the output that draws it, and nothing else recorded with it.
use super::*;

// The reasons `f` recorded at `e`, once per discard, in counter order.
fn recorded(e: &mut Endpoint, f: impl FnOnce(&mut Endpoint)) -> Vec<DropReason> {
    let before = e.drop_counts();
    f(e);
    let after = e.drop_counts();
    assert_eq!(after.total(), e.drops().total());
    DropReason::ALL
        .iter()
        .flat_map(|&r| core::iter::repeat_n(r, (after[r] - before[r]) as usize))
        .collect()
}

fn cfg() -> EndpointConfig {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg
}

fn ab() -> IpMetadata {
    IpMetadata {
        source: addresses().0.ip(),
        destination: addresses().1.ip(),
    }
}

// A client `a` and the server `b` it is connected to, after the client sent
// four octets that the server took. `next` is a pure ACK of the client's
// that the server accepts: RCV.NXT, the client's ACK and its last TSval.
struct Pair {
    a: Endpoint,
    b: Endpoint,
    client: ConnectionId,
    server: ConnectionId,
    next: wire::Header,
    ts: (u32, u32),
}

fn pair_with(cfg: EndpointConfig) -> Pair {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 1_000);
    let server = b.accept(listener).unwrap();
    assert_eq!(a.write(client, b"data").unwrap(), 4);
    let sent = packets(&mut a, 2_000);
    assert_eq!(sent.len(), 1);
    let segment = wire::parse(sent[0].0, &sent[0].1).unwrap();
    let mut next = segment.header;
    next.sequence = next.sequence.wrapping_add(4);
    next.flags = wire::ACK;
    let ts = segment.options.timestamps.unwrap();
    deliver(&mut b, 2_000, sent);
    pump(&mut a, &mut b, 2_000);
    Pair {
        a,
        b,
        client,
        server,
        next,
        ts,
    }
}

fn pair() -> Pair {
    pair_with(cfg())
}

fn segment(header: wire::Header, ts: Option<(u32, u32)>, payload: &[u8]) -> Vec<u8> {
    let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Some((value, echo)) = ts {
        options[4..8].copy_from_slice(&value.to_be_bytes());
        options[8..].copy_from_slice(&echo.to_be_bytes());
    }
    let mut bytes = vec![0; 32 + payload.len()];
    let len = wire::encode(
        ab(),
        header,
        if ts.is_some() { &options } else { &[] },
        payload,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}

impl Pair {
    // The reasons the server recorded for `bytes`.
    fn to_b(&mut self, bytes: &[u8]) -> Vec<DropReason> {
        recorded(&mut self.b, |b| {
            b.input(3_000, ab(), bytes).unwrap();
        })
    }
    fn with(&mut self, f: impl FnOnce(&mut wire::Header), payload: &[u8]) -> Vec<DropReason> {
        let mut header = self.next;
        f(&mut header);
        let bytes = segment(header, Some(self.ts), payload);
        self.to_b(&bytes)
    }
}

#[test]
fn the_template_segment_is_taken_without_a_discard() {
    let mut p = pair();
    assert_eq!(p.with(|_| {}, &[]), []);
    assert_eq!(p.with(|_| {}, b"more"), []);
}

#[test]
fn no_socket() {
    let mut p = pair();
    assert_eq!(p.with(|h| h.destination_port = 9, &[]), [DropReason::NoSocket]);
}

#[test]
fn tcp_csum() {
    let mut p = pair();
    let mut bytes = segment(p.next, Some(p.ts), b"x");
    bytes[16] ^= 0xff;
    assert_eq!(p.to_b(&bytes), [DropReason::TcpCsum]);
    assert_eq!(p.b.checksum_errors(), 1);
}

#[test]
fn pkt_too_small() {
    let mut p = pair();
    let bytes = segment(p.next, Some(p.ts), &[]);
    assert_eq!(p.to_b(&bytes[..12]), [DropReason::PktTooSmall]);
}

#[test]
fn tcp_invalid_option() {
    let mut p = pair();
    let mut bytes = vec![0; 24];
    let len = wire::encode(ab(), p.next, &[1, 1, 1, 1], &[], &mut bytes).unwrap();
    // A SACK option of length 1 in place of the NOPs, its checksum taken
    // as the device's verified one.
    bytes[20..24].copy_from_slice(&[1, 1, 5, 1]);
    let metadata = crate::RxPacketMetadata {
        tcp_checksum_verified: true,
        ..Default::default()
    };
    let r = recorded(&mut p.b, |b| {
        b.input_with_metadata(3_000, ab(), 0, Ipv4Options::default(), &bytes[..len], metadata)
            .unwrap();
    });
    assert_eq!(r, [DropReason::TcpInvalidOption]);
}

#[test]
fn pkt_too_big() {
    let mut p = pair();
    assert_eq!(p.to_b(&vec![0; 70_000]), [DropReason::PktTooBig]);
}

#[test]
fn ip_invalid_source_and_destination() {
    let mut p = pair();
    let bytes = segment(p.next, Some(p.ts), &[]);
    let multicast = "224.0.0.1".parse().unwrap();
    for (ip, reason) in [
        (
            IpMetadata {
                source: multicast,
                ..ab()
            },
            DropReason::IpInvalidSource,
        ),
        (
            IpMetadata {
                destination: multicast,
                ..ab()
            },
            DropReason::IpInvalidDest,
        ),
    ] {
        let r = recorded(&mut p.b, |b| {
            assert_eq!(b.input(3_000, ip, &bytes), Ok(InputDisposition::Dropped));
        });
        assert_eq!(r, [reason]);
    }
}

#[test]
fn address_policy() {
    let mut p = pair();
    let bytes = segment(p.next, Some(p.ts), &[]);
    let ip = IpMetadata {
        source: "198.51.100.1".parse().unwrap(),
        ..ab()
    };
    let r = recorded(&mut p.b, |b| {
        b.input(3_000, ip, &bytes).unwrap();
    });
    assert_eq!(r, [DropReason::AddressPolicy]);
}

#[test]
fn ip_source_route_refused_and_ip_inhdr() {
    let mut p = pair();
    let bytes = segment(p.next, Some(p.ts), &[]);
    let route = completed_route(&[9]);
    let r = recorded(&mut p.b, |b| {
        b.input_with_ipv4_options(3_000, ab(), 0, route, &bytes)
            .unwrap();
    });
    assert_eq!(r, [DropReason::IpSourceRouteRefused]);
    // IPv4 options on an IPv6 packet.
    let ip = IpMetadata {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    };
    let r = recorded(&mut p.b, |b| {
        b.input_with_ipv4_options(3_000, ip, 0, route, &bytes)
            .unwrap();
    });
    assert_eq!(r, [DropReason::IpInhdr]);
}

#[test]
fn a_listener_drops_resets_acks_and_segments_without_syn() {
    let mut p = pair();
    let other = |h: &mut wire::Header, flags| {
        h.source_port = 41_000;
        h.flags = flags;
    };
    assert_eq!(
        p.with(|h| other(h, wire::RST), &[]),
        [DropReason::TcpReset]
    );
    assert_eq!(
        p.with(|h| other(h, wire::ACK), &[]),
        [DropReason::TcpFlags]
    );
    assert_eq!(
        p.with(|h| other(h, wire::FIN), &[]),
        [DropReason::TcpFlags]
    );
}

// SYNs from `count` ports of the client's address, delivered to `b`
// without their answers reaching the client.
fn syns(b: &mut Endpoint, count: u16) -> Vec<DropReason> {
    let mut a = Endpoint::new(cfg(), [7; 32], 0, test_policy).unwrap();
    let (local, remote) = addresses();
    for n in 0..count {
        let mut local = local;
        local.set_port(42_000 + n);
        a.connect(0, local, remote).unwrap();
    }
    let sent = packets(&mut a, 0);
    assert_eq!(sent.len(), usize::from(count));
    recorded(b, |b| deliver(b, 0, sent))
}

#[test]
fn tcp_syn_queue_overflow() {
    let mut b = Endpoint::new(cfg(), [2; 32], 0, test_policy).unwrap();
    b.listen(addresses().1, 0).unwrap();
    assert_eq!(syns(&mut b, 2), [DropReason::TcpSynQueueOverflow]);
    assert_eq!(b.listen_drops(), 1);
}

#[test]
fn tcp_listen_overflow() {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg(), [2; 32], 0, test_policy).unwrap();
    b.listen(remote, 0).unwrap();
    a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(syns(&mut b, 1), [DropReason::TcpListenOverflow]);
    assert_eq!((b.listen_overflows(), b.listen_drops()), (1, 1));
}

#[test]
fn tcp_connection_limit() {
    let mut config = cfg();
    config.max_connections = 1;
    let mut b = Endpoint::new(config, [2; 32], 0, test_policy).unwrap();
    b.listen(addresses().1, 1).unwrap();
    assert_eq!(syns(&mut b, 2), [DropReason::TcpConnectionLimit]);
}

#[test]
fn memory_refused() {
    let mut config = cfg();
    config.max_buffer_bytes = connection_charge(&config);
    let mut b = Endpoint::new(config, [2; 32], 0, test_policy).unwrap();
    b.listen(addresses().1, 4).unwrap();
    assert_eq!(syns(&mut b, 2), [DropReason::MemoryRefused]);
}

#[test]
fn tcp_close_while_the_terminal_reset_is_owed() {
    let mut p = pair();
    p.b.abort(p.server).unwrap();
    assert_eq!(p.with(|_| {}, b"x"), [DropReason::TcpClose]);
}

#[test]
fn tcp_invalid_ack_sequence_in_syn_sent() {
    let mut a = Endpoint::new(cfg(), [1; 32], 0, test_policy).unwrap();
    let (local, remote) = addresses();
    a.connect(0, local, remote).unwrap();
    let syn = packets(&mut a, 0);
    let syn = wire::parse(syn[0].0, &syn[0].1).unwrap().header;
    let header = wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 1_000,
        acknowledgment: syn.sequence.wrapping_add(1_000),
        flags: wire::SYN | wire::ACK,
        window: 1024,
        urgent_pointer: 0,
    };
    let ba = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let mut bytes = [0; 64];
    let len = wire::encode(ba, header, &[], &[], &mut bytes).unwrap();
    let r = recorded(&mut a, |a| {
        a.input(1, ba, &bytes[..len]).unwrap();
    });
    assert_eq!(r, [DropReason::TcpInvalidAckSequence]);
}

#[test]
fn tcp_rfc7323_paws_and_missing_timestamp() {
    let mut p = pair();
    let old = (p.ts.0.wrapping_sub(10_000), p.ts.1);
    let bytes = segment(p.next, Some(old), b"x");
    assert_eq!(p.to_b(&bytes), [DropReason::TcpRfc7323Paws]);
    let bytes = segment(p.next, None, b"x");
    assert_eq!(p.to_b(&bytes), [DropReason::TcpMissingTimestamp]);
}

#[test]
fn tcp_invalid_syn() {
    let mut p = pair();
    assert_eq!(
        p.with(|h| h.flags = wire::SYN, &[]),
        [DropReason::TcpInvalidSyn]
    );
}

#[test]
fn tcp_old_data_old_sequence_and_invalid_sequence() {
    let mut p = pair();
    let back = |by: u32| move |h: &mut wire::Header| h.sequence = h.sequence.wrapping_sub(by);
    assert_eq!(p.with(back(4), b"data"), [DropReason::TcpOldData]);
    assert_eq!(p.with(back(100), b"data"), [DropReason::TcpOldSequence]);
    assert_eq!(
        p.with(|h| h.sequence = h.sequence.wrapping_add(100_000), b"data"),
        [DropReason::TcpInvalidSequence]
    );
}

#[test]
fn tcp_ofomerge() {
    let mut p = pair();
    let ahead = |h: &mut wire::Header| h.sequence = h.sequence.wrapping_add(8);
    assert_eq!(p.with(ahead, b"late"), []);
    assert_eq!(p.with(ahead, b"late"), [DropReason::TcpOfoMerge]);
}

#[test]
fn tcp_zerowindow() {
    let mut p = pair();
    // Fill the server's receive buffer, unread.
    for _ in 0..64 {
        let _ = p.a.write(p.client, &[7; 256]);
        pump(&mut p.a, &mut p.b, 2_500);
    }
    // Nothing read: RCV.NXT follows the first four octets by what is held.
    let held = p.b.readable_bytes(p.server).unwrap();
    p.next.sequence = p.next.sequence.wrapping_add(held as u32 - 4);
    p.ts = (p.ts.0.wrapping_add(1_000), p.ts.1);
    // The sender stopped at the window the receiver offered, which silly
    // window avoidance closed early: fill the rest of the buffer.
    let mut held = held;
    while held < 1024 {
        assert_eq!(p.with(|_| {}, &[7; 16]), []);
        let now = p.b.readable_bytes(p.server).unwrap();
        assert!(now > held);
        p.next.sequence = p.next.sequence.wrapping_add((now - held) as u32);
        held = now;
    }
    let r = p.with(|_| {}, b"x");
    assert_eq!(r, [DropReason::TcpZeroWindow]);
}

#[test]
fn tcp_overwindow_after_the_fin() {
    let mut p = pair();
    p.a.shutdown(p.client).unwrap();
    pump(&mut p.a, &mut p.b, 2_500);
    assert_eq!(p.b.state(p.server), Ok(State::CloseWait));
    p.ts = (p.ts.0.wrapping_add(1_000), p.ts.1);
    let r = p.with(|h| h.sequence = h.sequence.wrapping_add(1), b"x");
    assert_eq!(r, [DropReason::TcpOverWindow]);
}

#[test]
fn tcp_abort_on_data() {
    let mut p = pair();
    // Unread data would make the close an abort (Linux's tcp_close).
    p.b.read(p.server, &mut [0; 16]).unwrap();
    p.b.close(p.server).unwrap();
    assert_eq!(p.with(|_| {}, b"x"), [DropReason::TcpAbortOnData]);
}

#[test]
fn tcp_too_old_ack_and_ack_unsent_data() {
    let mut p = pair();
    let ack = |by: i32| {
        move |h: &mut wire::Header| h.acknowledgment = h.acknowledgment.wrapping_add_signed(by)
    };
    assert_eq!(p.with(ack(-100_000), &[]), [DropReason::TcpTooOldAck]);
    assert_eq!(p.with(ack(100_000), &[]), [DropReason::TcpAckUnsentData]);
}

#[test]
fn tcp_flags_without_ack_and_an_inexact_reset() {
    let mut p = pair();
    assert_eq!(p.with(|h| h.flags = wire::PSH, &[]), [DropReason::TcpFlags]);
    let r = p.with(
        |h| {
            h.flags = wire::RST;
            h.sequence = h.sequence.wrapping_add(10);
        },
        &[],
    );
    assert_eq!(r, [DropReason::TcpReset]);
    assert_eq!(p.b.state(p.server), Ok(State::Established));
}

#[test]
fn a_time_wait_record_drops_old_timestamps_and_syns() {
    let (mut b, _, server, ip, h, ts) = time_wait_endpoint_with(cfg(), false);
    b.release(server).unwrap();
    assert!(!b.connection_exists(server));
    let (seq, ack) = (h.acknowledgment, h.sequence);
    let old = tw_segment(ip, h, seq, ack, wire::ACK, Some((ts.wrapping_sub(10_000), 0)));
    let r = recorded(&mut b, |b| {
        b.input(4_000, ip, &old).unwrap();
    });
    assert_eq!(r, [DropReason::TcpRfc7323TwPaws]);
    let syn = tw_segment(ip, h, seq, 0, wire::SYN, Some((ts, 0)));
    let r = recorded(&mut b, |b| {
        b.input(4_000, ip, &syn).unwrap();
    });
    assert_eq!(r, [DropReason::TcpInvalidSyn]);
}

// A reserved output of the client's that the embedding then disposes of.
fn reserved(p: &mut Pair) -> (TransmitAttempt, Vec<u8>) {
    p.a.write(p.client, b"tail").unwrap();
    let mut out = [0; 2048];
    let (poll, attempt) = p
        .a
        .poll_reserved_transmit_for(3_000, p.client, &mut out, 16)
        .unwrap();
    let packet = poll.packet.unwrap();
    (attempt.unwrap(), out[..packet.len].to_vec())
}

fn reserving_pair() -> Pair {
    let mut p = pair();
    p.a.enable_output_reservations().unwrap();
    p
}

#[test]
fn socket_close_for_abandoned_output() {
    let mut p = reserving_pair();
    let (attempt, _) = reserved(&mut p);
    let r = recorded(&mut p.a, |a| assert!(a.abandon_transmit(attempt).unwrap()));
    assert_eq!(r, [DropReason::SocketClose]);
}

#[test]
fn neigh_failed_and_neigh_queuefull_for_unsubmitted_output() {
    for reason in [DropReason::NeighFailed, DropReason::NeighQueueFull] {
        let mut p = reserving_pair();
        let (attempt, _) = reserved(&mut p);
        let r = recorded(&mut p.a, |a| {
            assert!(a.discard_unsubmitted(3_000, attempt, None, reason).unwrap());
        });
        assert_eq!(r, [reason]);
    }
}

#[test]
fn stale_egress_for_a_refused_stateless_reply() {
    let mut p = reserving_pair();
    // A segment for no connection draws a reset on the stateless lane.
    let mut header = p.next;
    header.source_port = p.next.destination_port;
    header.destination_port = 9;
    let ba = IpMetadata {
        source: ab().destination,
        destination: ab().source,
    };
    let mut bytes = [0; 64];
    let len = wire::encode(ba, header, &[], &[], &mut bytes).unwrap();
    assert_eq!(
        recorded(&mut p.a, |a| {
            a.input(3_000, ba, &bytes[..len]).unwrap();
        }),
        [DropReason::NoSocket]
    );
    let mut out = [0; 256];
    let (poll, attempt) = p.a.poll_reserved_transmit(3_000, &mut out, 16).unwrap();
    assert_eq!(poll.packet.unwrap().connection, None);
    let r = recorded(&mut p.a, |a| {
        assert!(a.reject_unsubmitted(attempt.unwrap()).unwrap());
    });
    assert_eq!(r, [DropReason::StaleEgress]);
}

#[test]
fn the_feed_reports_each_discard_with_its_tuple() {
    let mut p = pair();
    assert_eq!(p.b.drops().feed_capacity(), 0);
    p.b.drops_mut().set_feed(2).unwrap();
    for _ in 0..3 {
        p.with(|h| h.flags = wire::SYN, &[]);
    }
    let (local, remote) = addresses();
    let event = p.b.drops_mut().take_event().unwrap();
    assert_eq!(event.reason, DropReason::TcpInvalidSyn);
    assert_eq!(event.at, 3_000);
    assert_eq!(event.len, 32);
    assert_eq!(
        event.subject,
        DropSubject::Transport {
            protocol: 6,
            source: local,
            destination: remote,
        }
    );
    assert!(p.b.drops_mut().take_event().is_some());
    assert!(p.b.drops_mut().take_event().is_none());
    assert_eq!(p.b.drops().feed_lost(), 1);
    assert_eq!(p.b.drop_counts()[DropReason::TcpInvalidSyn], 3);
}
