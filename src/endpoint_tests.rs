extern crate std;

use crate::wire;
use crate::*;
use std::{vec, vec::Vec};

fn addresses() -> (core::net::SocketAddr, core::net::SocketAddr) {
    (
        "192.0.2.1:40000".parse().unwrap(),
        "192.0.2.2:8080".parse().unwrap(),
    )
}

fn config() -> EndpointConfig {
    EndpointConfig {
        max_connections: 8,
        max_listeners: 2,
        connection: ConnectionConfig {
            mss: 64,
            send_capacity: 1024,
            receive_capacity: 1024,
            nagle: false,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    }
}

fn endpoints() -> (Endpoint, Endpoint, ListenerId, ConnectionId) {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    (a, b, listener, client)
}

fn packets(endpoint: &mut Endpoint, now: u64) -> Vec<(IpMetadata, Vec<u8>)> {
    let mut result = Vec::new();
    for _ in 0..256 {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            assert!(wire::parse(packet.ip, &bytes[..packet.len]).is_ok());
            result.push((packet.ip, bytes[..packet.len].to_vec()));
        }
        if !output.more_work {
            return result;
        }
    }
    panic!("endpoint failed to quiesce within its bounded flight");
}

fn deliver(endpoint: &mut Endpoint, now: u64, packets: Vec<(IpMetadata, Vec<u8>)>) {
    for (ip, bytes) in packets {
        endpoint.input(now, ip, &bytes).unwrap();
    }
}

fn pump(a: &mut Endpoint, b: &mut Endpoint, now: u64) {
    for _ in 0..128 {
        let ab = packets(a, now);
        let ba = packets(b, now);
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        deliver(b, now, ab);
        deliver(a, now, ba);
    }
    panic!("unexpected infinite packet exchange");
}

fn tick(a: &mut Endpoint, b: &mut Endpoint, now: u64) {
    assert!(!a.on_timeout(now, 64).unwrap());
    assert!(!b.on_timeout(now, 64).unwrap());
    pump(a, b, now);
}

#[test]
fn endpoint_transfer_backpressure_events_half_close_and_time_wait() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Established);
    assert_eq!(b.state(server).unwrap(), State::Established);
    assert!(
        matches!(a.next_event(),Some(Event::Connection(id,events)) if id==client && events.connected)
    );
    let payload: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
    assert_eq!(a.write(client, &payload).unwrap(), 1024);
    assert_eq!(
        a.write(client, b"x"),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    pump(&mut a, &mut b, 0);
    for t in 1..=8 {
        tick(&mut a, &mut b, t * 200_000);
    }
    let mut data = [0; 2048];
    assert_eq!(b.read(server, &mut data).unwrap(), 1024);
    assert_eq!(&data[..1024], &payload[..1024]);
    assert_eq!(a.acknowledged(client).unwrap(), 1024);
    a.shutdown(client).unwrap();
    pump(&mut a, &mut b, 1_600_000);
    assert_eq!(b.read(server, &mut data).unwrap(), 0);
    assert_eq!(b.state(server).unwrap(), State::CloseWait);
    assert_eq!(b.write(server, b"reply").unwrap(), 5);
    b.shutdown(server).unwrap();
    pump(&mut a, &mut b, 1_600_000);
    tick(&mut a, &mut b, 1_800_000);
    assert_eq!(a.read(client, &mut data).unwrap(), 5);
    assert_eq!(&data[..5], b"reply");
    assert_eq!(a.read(client, &mut data).unwrap(), 0);
    assert_eq!(a.state(client).unwrap(), State::TimeWait);
    a.release(client).unwrap();
    assert_eq!(a.state(client), Err(EndpointError::InvalidHandle));
    let (local, remote) = addresses();
    assert_eq!(
        a.connect(1_800_000, local, remote),
        Err(EndpointError::AddressInUse)
    );
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.8
    //= type=test
    //# If the time-wait timeout expires on a connection, delete the TCB,
    //# enter the CLOSED state, and return.

    // Traceability limitation: Asserts tuple reuse after expiry for a released handle,
    // not exact expiry-boundary timing.
    a.on_timeout(300_000_000, 64).unwrap();
    assert!(a.connect(300_000_000, local, remote).is_ok());
}

#[test]
fn loss_reordering_duplication_and_corruption_do_not_corrupt_stream() {
    let (mut a, mut b, listener, client) = endpoints();
    let lost_syn = packets(&mut a, 0);
    assert_eq!(lost_syn.len(), 1);
    tick(&mut a, &mut b, 1_000_000);
    let server = b.accept(listener).unwrap();
    let bytes: Vec<u8> = (0..512).map(|i| (i % 239) as u8).collect();
    a.write(client, &bytes).unwrap();
    let mut flight = packets(&mut a, 1_000_000);
    assert!(!flight.is_empty());
    let lost = flight.remove(0);
    if let Some((ip, packet)) = flight.first() {
        let mut corrupt = packet.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            b.input(1_000_000, *ip, &corrupt).unwrap(),
            InputDisposition::Dropped
        );
    }
    flight.reverse();
    deliver(&mut b, 1_000_000, flight.clone());
    deliver(&mut b, 1_000_000, flight);
    pump(&mut a, &mut b, 1_000_000);
    for t in 2..=12 {
        tick(&mut a, &mut b, t * 1_000_000);
    }
    let mut received = [0; 1024];
    assert_eq!(b.read(server, &mut received).unwrap(), 512);
    assert_eq!(&received[..512], &bytes);
    deliver(&mut b, 12_000_000, vec![lost]);
    assert_eq!(
        b.read(server, &mut received),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(a.acknowledged(client).unwrap(), 512);
}

#[test]
fn output_failure_stale_handles_and_memory_limits_are_explicit() {
    let (mut a, mut b, listener, client) = endpoints();
    let before = a.next_deadline();
    assert!(a.poll_transmit(0, &mut [0; 1], 1).is_err());
    assert_eq!(a.next_deadline(), before);
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    assert_eq!(a.write(client, b"abc").unwrap(), 3);
    let before = a.acknowledged(client).unwrap();
    assert!(a.poll_transmit(0, &mut [0; 20], 1).is_err());
    assert_eq!(a.acknowledged(client).unwrap(), before);
    pump(&mut a, &mut b, 0);
    let mut out = [0; 4];
    assert_eq!(b.read(server, &mut out).unwrap(), 3);
    a.abort(client).unwrap();
    packets(&mut a, 0);
    a.release(client).unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
    //= type=test
    //# Delete the
    //# TCB, enter CLOSED state, and return.

    assert_eq!(a.buffer_bytes(), 0);
    let (local, remote) = addresses();
    let replacement = a.connect(0, local, remote).unwrap();
    assert_ne!(replacement, client);
    assert_eq!(a.write(client, b"bad"), Err(EndpointError::InvalidHandle));
    let mut limited = config();
    limited.max_buffer_bytes = 1;
    let mut endpoint = Endpoint::new(limited, [3; 32], 0).unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
    //= type=test
    //# If there is
    //# no room to create a new connection, return "error: insufficient
    //# resources".
    assert_eq!(
        endpoint.connect(0, local, remote),
        Err(EndpointError::LimitReached)
    );
    assert_eq!(
        a.input(
            0,
            IpMetadata {
                source: remote.ip(),
                destination: local.ip()
            },
            &[0; 19]
        )
        .unwrap(),
        InputDisposition::Dropped
    );
    a.on_timeout(1, 0).unwrap();
    assert_eq!(
        a.poll_transmit(0, &mut [0; 100], 1),
        Err(EndpointError::Connection(Error::TimeWentBackwards))
    );
}

#[test]
fn listener_backlog_and_cleanup_are_bounded() {
    let (mut a, mut b, listener, client) = endpoints();
    let syns = packets(&mut a, 0);
    deliver(&mut b, 0, syns);
    assert!(b.buffer_bytes() > 0);
    b.close_listener(listener).unwrap();
    packets(&mut b, 0);
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(b.accept(listener), Err(EndpointError::InvalidHandle));
    let (_, remote) = addresses();
    assert!(b.listen(remote, 1).is_ok());
    assert_eq!(a.state(client).unwrap(), State::SynSent);
}

#[test]
fn seeded_duplex_network_faults_preserve_every_byte_and_eventually_close() {
    struct Delayed {
        at: u64,
        to_b: bool,
        ip: IpMetadata,
        bytes: Vec<u8>,
    }
    fn random(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed >> 17
    }
    for trial in 1..=8 {
        let (mut a, mut b, listener, client) = endpoints();
        pump(&mut a, &mut b, 0);
        let server = b.accept(listener).unwrap();
        let a_data: Vec<u8> = (0..4096).map(|i| ((i * 7 + trial) % 251) as u8).collect();
        let b_data: Vec<u8> = (0..3072).map(|i| ((i * 13 + trial) % 253) as u8).collect();
        let (mut a_sent, mut b_sent, mut a_read, mut b_read) = (0, 0, Vec::new(), Vec::new());
        let (mut a_closed, mut b_closed, mut a_eof, mut b_eof) = (false, false, false, false);
        let mut seed = trial as u64;
        let mut network: Vec<Delayed> = Vec::new();
        // This checks eventual delivery, not throughput: repeated loss can
        // legitimately drive RFC 6298 backoff to 60 seconds between attempts.
        for step in 1..=100_000 {
            let now = step * 10_000;
            a.on_timeout(now, 32).unwrap();
            b.on_timeout(now, 32).unwrap();
            for (endpoint, id, source, sent, closed) in [
                (&mut a, client, &a_data, &mut a_sent, &mut a_closed),
                (&mut b, server, &b_data, &mut b_sent, &mut b_closed),
            ] {
                if *sent < source.len() {
                    let end = source
                        .len()
                        .min(*sent + 1 + (random(&mut seed) % 197) as usize);
                    match endpoint.write(id, &source[*sent..end]) {
                        Ok(n) => *sent += n,
                        Err(EndpointError::Connection(Error::WouldBlock)) => {}
                        other => panic!("write failed in trial {trial}: {other:?}"),
                    }
                }
                if *sent == source.len() && !*closed {
                    endpoint.shutdown(id).unwrap();
                    *closed = true;
                }
            }
            for (endpoint, to_b) in [(&mut a, true), (&mut b, false)] {
                for (ip, mut bytes) in packets(endpoint, now) {
                    let choice = random(&mut seed);
                    if choice.is_multiple_of(8) || network.len() >= 128 {
                        continue;
                    }
                    if choice.is_multiple_of(17) {
                        let end = bytes.len() - 1;
                        bytes[end] ^= 0x80;
                    }
                    let at = now + (random(&mut seed) % 7) * 10_000;
                    if choice.is_multiple_of(9) {
                        network.push(Delayed {
                            at: at + 20_000,
                            to_b,
                            ip,
                            bytes: bytes.clone(),
                        });
                    }
                    network.push(Delayed {
                        at,
                        to_b,
                        ip,
                        bytes,
                    });
                }
            }
            let mut index = 0;
            while index < network.len() {
                if network[index].at <= now {
                    let packet = network.swap_remove(index);
                    let target = if packet.to_b { &mut b } else { &mut a };
                    target.input(now, packet.ip, &packet.bytes).unwrap();
                } else {
                    index += 1;
                }
            }
            for (endpoint, id, received, eof) in [
                (&mut a, client, &mut a_read, &mut a_eof),
                (&mut b, server, &mut b_read, &mut b_eof),
            ] {
                if random(&mut seed).is_multiple_of(4) {
                    continue;
                }
                let mut out = [0; 113];
                loop {
                    match endpoint.read(id, &mut out) {
                        Ok(0) => {
                            *eof = true;
                            break;
                        }
                        Ok(n) => received.extend_from_slice(&out[..n]),
                        Err(EndpointError::Connection(Error::WouldBlock)) => break,
                        other => panic!("read failed in trial {trial}: {other:?}"),
                    }
                }
            }
            assert!(b_read.len() <= a_data.len());
            assert_eq!(b_read, a_data[..b_read.len()]);
            assert!(a_read.len() <= b_data.len());
            assert_eq!(a_read, b_data[..a_read.len()]);
            if a_eof
                && b_eof
                && a.acknowledged(client).unwrap() == a_data.len() as u64
                && b.acknowledged(server).unwrap() == b_data.len() as u64
            {
                break;
            }
        }
        assert!(
            a_eof && b_eof,
            "trial {trial} did not close: {:?} {:?}; sent={a_sent}/{b_sent} read={}/{} ack={:?}/{:?} deadlines={:?}/{:?}",
            a.state(client),
            b.state(server),
            a_read.len(),
            b_read.len(),
            a.acknowledged(client),
            b.acknowledged(server),
            a.next_deadline(),
            b.next_deadline()
        );
        assert_eq!(a_read, b_data);
        assert_eq!(b_read, a_data);
        assert_eq!(a.acknowledged(client).unwrap(), a_data.len() as u64);
        assert_eq!(b.acknowledged(server).unwrap(), b_data.len() as u64);
    }
}

#[test]
fn closed_status_does_not_keep_owning_the_tuple_or_remove_its_replacement() {
    let (mut a, mut b, listener, old) = endpoints();
    pump(&mut a, &mut b, 0);
    let peer = b.accept(listener).unwrap();
    a.abort(old).unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(b.state(peer).unwrap(), State::Closed);
    let (local, remote) = addresses();
    let replacement = a.connect(1, local, remote).unwrap();
    assert_ne!(old, replacement);
    a.release(old).unwrap();
    pump(&mut a, &mut b, 1);
    let accepted = b.accept(listener).unwrap();
    assert_eq!(a.state(replacement).unwrap(), State::Established);
    b.release(peer).unwrap();
    a.write(replacement, b"new incarnation").unwrap();
    pump(&mut a, &mut b, 1);
    let mut data = [0; 32];
    assert_eq!(b.read(accepted, &mut data).unwrap(), 15);
    assert_eq!(&data[..15], b"new incarnation");
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.3
//= type=test
//# When the number of transmissions of the same segment reaches or
//# exceeds threshold R1, pass negative advice (see Section 3.3.1.4
//# of [19]) to the IP layer, to trigger dead-gateway diagnosis.

// Traceability limitation: Asserts half-open route advice, not passive application
// error reporting or gateway diagnosis.
fn half_open_retransmissions_report_route_advice_without_accepting() {
    let (mut a, mut b, listener, _) = endpoints();
    deliver(&mut b, 0, packets(&mut a, 0));
    packets(&mut b, 0); // Deliberately lose the SYN-ACK and all retransmissions.
    for _ in 0..3 {
        let time = b.next_deadline().unwrap();
        b.on_timeout(time, 8).unwrap();
        packets(&mut b, time);
    }
    let (local, remote) = addresses();
    assert_eq!(
        b.next_event(),
        Some(Event::RouteAdvice(Tuple {
            local: remote,
            remote: local
        }))
    );
    assert_eq!(b.next_event(), None);
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
//= type=test
//# If an application on a multihomed host does not specify the local IP
//# address when actively opening a TCP connection, then the TCP
//# implementation MUST ask the IP layer to select a local IP address
//# before sending the (first) SYN (MUST-44).
fn source_selection_and_keepalive_are_per_connection_controls() {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a
        .connect_with_source(0, None, remote, |destination| {
            assert_eq!(destination, remote);
            Ok(local)
        })
        .unwrap();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    assert_eq!(a.tuple(client).unwrap(), Tuple { local, remote });
    a.set_keepalive(
        client,
        Some(KeepaliveConfig {
            send_garbage: false,
            idle_us: 10_000_000,
            interval_us: 1_000_000,
            probes: 3,
        }),
    )
    .unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# This interval MUST
    //# be configurable (MUST-27)
    assert_eq!(a.next_deadline(), Some(10_000_000));
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.4
    //= type=test
    //# keep-alives are included, the application MUST be able to turn them
    //# on or off for each TCP connection (MUST-24),
    a.set_keepalive(client, None).unwrap();
    assert_eq!(a.next_deadline(), None);
}

#[test]
fn ipv6_metadata_is_rejected_instead_of_silently_misrouting() {
    use core::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
    let mut endpoint = Endpoint::new(config(), [1; 32], 0).unwrap();
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    for (flow, scope) in [(1, 0), (0, 3)] {
        let address = SocketAddr::V6(SocketAddrV6::new(ip, 8080, flow, scope));
        assert_eq!(
            endpoint.listen(address, 1),
            Err(EndpointError::InvalidAddress)
        );
        assert_eq!(
            endpoint.connect(0, address, "[2001:db8::2]:80".parse().unwrap()),
            Err(EndpointError::InvalidAddress)
        );
    }
}

#[test]
fn same_tick_reopen_uses_a_new_initial_sequence() {
    let (mut a, _, _, client) = endpoints();
    let first = packets(&mut a, 0);
    let first = wire::parse(first[0].0, &first[0].1)
        .unwrap()
        .header
        .sequence;
    a.abort(client).unwrap();
    a.release(client).unwrap();
    let (local, remote) = addresses();
    a.connect(0, local, remote).unwrap();
    let second = packets(&mut a, 0);
    let second = wire::parse(second[0].0, &second[0].1)
        .unwrap()
        .header
        .sequence;
    assert_ne!(first, second);
}

#[test]
fn application_work_uses_latest_endpoint_time_and_output_metadata() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    // Other flows/driver operations may advance the endpoint while this flow is idle.
    a.poll_transmit(1_000_000_000, &mut [0; 128], 1).unwrap();
    a.set_user_timeout(client, 1_000_000).unwrap();
    a.set_hop_limit(client, 37).unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //= type=test
    //# It is not required, but the
    //# application SHOULD be able to change the Differentiated Services
    //# field during the connection lifetime (SHLD-21).
    a.set_dscp(client, 46).unwrap();
    a.write(client, b"abc").unwrap();
    a.on_timeout(1_000_000_000, 8).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Established);
    let mut out = [0; 128];
    let packet = a
        .poll_transmit(1_000_000_000, &mut out, 8)
        .unwrap()
        .packet
        .unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //= type=test
    //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
    //# configurable (MUST-49).
    assert_eq!(packet.hop_limit, 37);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //= type=test
    //# The application layer MUST be able to specify the Differentiated
    //# Services field for segments that are sent on a connection (MUST-48).
    assert_eq!(packet.dscp, 46);
    assert_eq!(
        wire::parse(packet.ip, &out[..packet.len]).unwrap().payload,
        b"abc"
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//# TCP implementations MUST act on an ICMP error message passed up from
//# the IP layer, directing it to the connection that created the error
//# (MUST-54).
fn lower_layer_errors_require_a_matching_outstanding_quote() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    while a.next_event().is_some() {}
    a.write(client, b"pending").unwrap();
    let output = packets(&mut a, 0);
    let sequence = wire::parse(output[0].0, &output[0].1)
        .unwrap()
        .header
        .sequence;
    let (local, remote) = addresses();
    let tuple = Tuple { local, remote };
    assert!(
        !a.network_error(
            0,
            tuple,
            sequence.wrapping_sub(1),
            NetworkError::HardUnreachable
        )
        .unwrap()
    );
    assert!(
        a.network_error(0, tuple, sequence, NetworkError::SoftUnreachable)
            .unwrap()
    );
    assert_eq!(a.state(client).unwrap(), State::Established);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= type=test
    //# SHOULD make the information available to the application (SHLD-25).

    // Traceability limitation: This assertion covers an established active connection
    // only, not passive-half-open error visibility.
    assert!(
        matches!(a.next_event(),Some(Event::Connection(_,e)) if e.network_error==Some(NetworkError::SoftUnreachable))
    );
    a.lower_mss(client, 16).unwrap();
    assert!(
        a.network_error(0, tuple, sequence, NetworkError::HardUnreachable)
            .unwrap()
    );
    assert_eq!(
        a.close_reason(client).unwrap(),
        Some(CloseReason::NetworkError)
    );
    assert_eq!(a.state(client).unwrap(), State::Closed);
}

#[test]
fn unknown_connection_reset_has_correct_sequence_and_never_answers_reset() {
    let mut b = Endpoint::new(config(), [4; 32], 0).unwrap();
    let (local, remote) = addresses();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: u32::MAX,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 1024,
        urgent_pointer: 0,
    };
    let mut input = [0; 128];
    let len = wire::encode(ip, header, &[], &[], &mut input).unwrap();
    b.input(0, ip, &input[..len]).unwrap();
    let replies = packets(&mut b, 0);
    assert_eq!(replies.len(), 1);
    let reset = wire::parse(replies[0].0, &replies[0].1).unwrap();
    assert_eq!(reset.header.flags, wire::RST | wire::ACK);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //= type=test
    //# <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

    // Traceability limitation: Checks SYN sequence wrap, acknowledgment and flags; does
    // not assert RST sequence zero or the incoming-ACK branch.
    assert_eq!(reset.header.acknowledgment, 0);
    let len = wire::encode(
        ip,
        wire::Header {
            flags: wire::RST,
            ..header
        },
        &[],
        &[],
        &mut input,
    )
    .unwrap();
    b.input(0, ip, &input[..len]).unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //= type=test
    //# An incoming
    //# segment containing a RST is discarded.
    assert!(packets(&mut b, 0).is_empty());
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
//= type=test
//= reason=Terminal notification cancels stream operations; explicit release reclaims storage after the pending reset is generated.
//# All queued SENDs and RECEIVEs should be given "connection reset"
//# notification; all segments queued for transmission (except for the
//# RST formed above) or retransmission should be flushed. Delete the
//# TCB, enter CLOSED state, and return.
#[test]
fn abort_release_retries_reset_before_reclaiming_storage() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.write(client, b"unsent data must not precede the reset")
        .unwrap();
    a.abort(client).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Closed);
    assert_eq!(a.close_reason(client).unwrap(), Some(CloseReason::Aborted));
    assert_eq!(
        a.write(client, b"late"),
        Err(EndpointError::Connection(Error::InvalidState))
    );
    assert_eq!(
        a.read(client, &mut [0; 1]),
        Err(EndpointError::Connection(Error::InvalidState))
    );
    assert!(core::iter::from_fn(|| a.next_event()).any(|event| {
        matches!(event, Event::Connection(id, events)
            if id == client && events.closed == Some(CloseReason::Aborted))
    }));
    let retained = a.buffer_bytes();
    a.release(client).unwrap();
    assert_eq!(a.state(client), Err(EndpointError::InvalidHandle));
    assert_eq!(a.release(client), Err(EndpointError::InvalidHandle));
    assert_eq!(a.buffer_bytes(), retained);
    assert_eq!(
        a.poll_transmit(0, &mut [0; 1], 1),
        Err(EndpointError::Connection(Error::OutputTooSmall))
    );
    assert_eq!(a.buffer_bytes(), retained);
    assert!(a.has_pending_output());
    let reset = packets(&mut a, 0);
    assert_eq!(reset.len(), 1);
    let segment = wire::parse(reset[0].0, &reset[0].1).unwrap();
    assert_eq!(segment.header.flags, wire::RST);
    assert!(segment.payload.is_empty());
    assert_eq!(a.buffer_bytes(), 0);
    assert!(a.next_deadline().is_none());
    assert!(packets(&mut a, 0).is_empty());
    deliver(&mut b, 0, reset);
    assert_eq!(b.state(server).unwrap(), State::Closed);
    assert_eq!(b.close_reason(server).unwrap(), Some(CloseReason::Reset));
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
//= type=test
//# However, an application program that does not want to receive such
//# ERROR_REPORT calls SHOULD be able to effectively disable these calls
//# (SHLD-20).
#[test]
fn disabling_error_reports_keeps_data_and_terminal_events() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.error_reports = false;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(cfg.clone(), [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    a.connect(0, local, remote).unwrap();
    let (tuple, seq) = passive_quote(&mut a, &mut b);
    for _ in 0..2 * cfg.max_connections {
        assert!(
            b.network_error(0, tuple, seq, NetworkError::SoftUnreachable)
                .unwrap()
        );
    }
    assert!(b.next_event().is_none());
    assert!(
        b.network_error(0, tuple, seq, NetworkError::HardUnreachable)
            .unwrap()
    );
    assert!(b.next_event().is_none());
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );

    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 0);
    let peer = b.accept(listener).unwrap();
    while a.next_event().is_some() {}
    a.write(id, b"x").unwrap();
    let data = packets(&mut a, 0);
    let seq = wire::parse(data[0].0, &data[0].1).unwrap().header.sequence;
    let tuple = Tuple { local, remote };
    assert!(
        a.network_error(0, tuple, seq, NetworkError::SoftUnreachable)
            .unwrap()
    );
    assert!(a.next_event().is_none());
    b.write_urgent(peer, b"!").unwrap();
    deliver(&mut a, 0, packets(&mut b, 0));
    match a.next_event().unwrap() {
        Event::Connection(event_id, events) => {
            assert_eq!(event_id, id);
            assert!(events.readable);
            assert_eq!(events.urgent, None);
            assert_eq!(events.network_error, None);
        }
        event => panic!("unexpected event: {event:?}"),
    }
    assert_eq!(a.read(id, &mut [0; 1]).unwrap(), 1);
    assert!(
        a.network_error(0, tuple, seq, NetworkError::HardUnreachable)
            .unwrap()
    );
    assert!(
        matches!(a.next_event(), Some(Event::Connection(event_id, events))
        if event_id == id && events.closed == Some(CloseReason::NetworkError))
    );
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
//= type=test
//# However, an application program that does not want to receive such
//# ERROR_REPORT calls SHOULD be able to effectively disable these calls
//# (SHLD-20).
#[test]
fn warning_reports_can_be_disabled_without_suppressing_route_advice() {
    let (local, remote) = addresses();
    for enabled in [false, true] {
        let mut cfg = config();
        cfg.error_reports = enabled;
        let mut a = Endpoint::new(cfg, [1; 32], 0).unwrap();
        let id = a.connect(0, local, remote).unwrap();
        packets(&mut a, 0);
        for attempt in 0..3 {
            let time = a.next_deadline().unwrap();
            a.on_timeout(time, 64).unwrap();
            packets(&mut a, time);
            let mut warning = false;
            let mut advice = false;
            while let Some(event) = a.next_event() {
                match event {
                    Event::RouteAdvice(tuple) => {
                        assert_eq!(tuple, Tuple { local, remote });
                        advice = true;
                    }
                    Event::Connection(event_id, events) => {
                        assert_eq!(event_id, id);
                        warning |= events.retransmission_warning;
                    }
                    event => panic!("unexpected event: {event:?}"),
                }
            }
            assert_eq!(advice, attempt == 2);
            assert_eq!(warning, enabled && attempt == 2);
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
//= type=test
//# However, the conditions that are reported asynchronously to the application MUST include:
#[test]
fn asynchronous_reports_include_urgent_icmp_and_retransmission_warning() {
    let (mut a, mut b, listener, id) = endpoints();
    pump(&mut a, &mut b, 0);
    let peer = b.accept(listener).unwrap();
    while a.next_event().is_some() {}
    b.write_urgent(peer, b"!").unwrap();
    deliver(&mut a, 0, packets(&mut b, 0));
    assert!(
        matches!(a.next_event(), Some(Event::Connection(event_id, events))
        if event_id == id && events.readable && events.urgent == Some(1))
    );
    assert_eq!(a.read(id, &mut [0; 1]).unwrap(), 1);
    a.write(id, b"lost").unwrap();
    let data = packets(&mut a, 0);
    let seq = wire::parse(data[0].0, &data[0].1).unwrap().header.sequence;
    let (local, remote) = addresses();
    assert!(
        a.network_error(
            0,
            Tuple { local, remote },
            seq,
            NetworkError::SoftUnreachable
        )
        .unwrap()
    );
    assert!(
        matches!(a.next_event(), Some(Event::Connection(event_id, events))
        if event_id == id && events.network_error == Some(NetworkError::SoftUnreachable))
    );
    for attempt in 0..3 {
        let deadline = a.next_deadline().unwrap();
        a.on_timeout(deadline, 64).unwrap();
        packets(&mut a, deadline);
        let mut warned = false;
        while let Some(event) = a.next_event() {
            if let Event::Connection(event_id, events) = event {
                assert_eq!(event_id, id);
                warned |= events.retransmission_warning;
            }
        }
        assert_eq!(warned, attempt == 2);
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.3
//= type=test
//# Data or controls that were queued for transmission MAY be included.
#[test]
fn queued_application_data_piggybacks_on_the_final_handshake_ack() {
    let (mut a, mut b, listener, client) = endpoints();
    assert_eq!(a.write(client, b"queued before connect completes"), Ok(31));
    deliver(&mut b, 0, packets(&mut a, 0));
    deliver(&mut a, 0, packets(&mut b, 0));
    let reply = packets(&mut a, 0);
    assert_eq!(reply.len(), 1);
    let segment = wire::parse(reply[0].0, &reply[0].1).unwrap();
    assert_eq!(segment.header.flags & (wire::SYN | wire::ACK), wire::ACK);
    assert_eq!(segment.payload, b"queued before connect completes");
    deliver(&mut b, 0, reply);
    let server = b.accept(listener).unwrap();
    let mut received = [0; 64];
    let count = b.read(server, &mut received).unwrap();
    assert_eq!(&received[..count], b"queued before connect completes");
}

fn passive_quote(a: &mut Endpoint, b: &mut Endpoint) -> (Tuple, u32) {
    deliver(b, 0, packets(a, 0));
    let reply = packets(b, 0);
    assert_eq!(reply.len(), 1);
    let syn_ack = wire::parse(reply[0].0, &reply[0].1).unwrap();
    assert_eq!(syn_ack.header.flags, wire::SYN | wire::ACK | wire::ECE);
    let (local, remote) = addresses();
    (
        Tuple {
            local: remote,
            remote: local,
        },
        syn_ack.header.sequence,
    )
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.8
//= type=test
//# There MUST be a mechanism for reporting soft TCP error conditions to
//# the application (MUST-47).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//# SHOULD make the information available to the application (SHLD-25).
fn passive_network_errors_are_visible_before_accept_and_survive_cleanup() {
    let (mut a, mut b, listener, _) = endpoints();
    let (tuple, sequence) = passive_quote(&mut a, &mut b);
    assert!(
        b.network_error(0, tuple, sequence, NetworkError::SoftUnreachable)
            .unwrap()
    );
    assert_eq!(
        b.next_event(),
        Some(Event::PassiveError {
            listener,
            tuple,
            error: NetworkError::SoftUnreachable
        })
    );
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert!(b.buffer_bytes() > 0);
    assert!(
        b.network_error(0, tuple, sequence, NetworkError::HardUnreachable)
            .unwrap()
    );
    assert!(packets(&mut b, 0).is_empty());
    assert_eq!(b.buffer_bytes(), 0);
    b.close_listener(listener).unwrap();
    packets(&mut b, 0);
    assert_ne!(b.listen(tuple.local, 4).unwrap(), listener);
    assert_eq!(
        b.next_event(),
        Some(Event::PassiveError {
            listener,
            tuple,
            error: NetworkError::HardUnreachable
        })
    );
    assert_eq!(b.next_event(), None);
}

#[test]
fn passive_network_error_quotes_and_queue_capacity_are_checked() {
    let (mut a, mut b, listener, _) = endpoints();
    let (tuple, sequence) = passive_quote(&mut a, &mut b);
    let mut unmatched = tuple;
    unmatched.remote.set_port(tuple.remote.port() + 1);
    for (quote_tuple, quote_sequence, error) in [
        (unmatched, sequence, NetworkError::HardUnreachable),
        (
            tuple,
            sequence.wrapping_sub(1),
            NetworkError::HardUnreachable,
        ),
        (
            tuple,
            sequence.wrapping_add(1),
            NetworkError::SoftUnreachable,
        ),
        (tuple, sequence, NetworkError::SourceQuench),
    ] {
        assert!(
            !b.network_error(0, quote_tuple, quote_sequence, error)
                .unwrap()
        );
        assert_eq!(b.next_event(), None);
    }
    for _ in 0..config().max_connections {
        assert!(
            b.network_error(0, tuple, sequence, NetworkError::TimeExceeded)
                .unwrap()
        );
    }
    assert!(
        !b.network_error(0, tuple, sequence, NetworkError::SourceQuench)
            .unwrap()
    );
    assert_eq!(
        b.network_error(0, tuple, sequence, NetworkError::HardUnreachable),
        Err(EndpointError::LimitReached)
    );
    assert_eq!(
        b.next_event(),
        Some(Event::PassiveError {
            listener,
            tuple,
            error: NetworkError::TimeExceeded
        })
    );
    // Retrying the same hard report proves overflow did not close/unmap the child.
    assert!(
        b.network_error(0, tuple, sequence, NetworkError::HardUnreachable)
            .unwrap()
    );
    packets(&mut b, 0);
    assert_eq!(b.buffer_bytes(), 0);
    for _ in 1..config().max_connections {
        assert_eq!(
            b.next_event(),
            Some(Event::PassiveError {
                listener,
                tuple,
                error: NetworkError::TimeExceeded
            })
        );
    }
    assert_eq!(
        b.next_event(),
        Some(Event::PassiveError {
            listener,
            tuple,
            error: NetworkError::HardUnreachable
        })
    );
    assert_eq!(b.next_event(), None);
    assert!(
        !b.network_error(0, tuple, sequence, NetworkError::SoftUnreachable)
            .unwrap()
    );
    assert_eq!(b.next_event(), None);
}

fn opened_isn(endpoint: &mut Endpoint, now: u64, tuple: Tuple) -> u32 {
    let id = endpoint.connect(now, tuple.local, tuple.remote).unwrap();
    let syn = packets(endpoint, now);
    assert_eq!(syn.len(), 1);
    let sequence = wire::parse(syn[0].0, &syn[0].1).unwrap().header.sequence;
    endpoint.abort(id).unwrap();
    packets(endpoint, now);
    endpoint.release(id).unwrap();
    sequence
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
//= type=test
//# A TCP implementation MUST use the above type of "clock" for clock-
//# driven selection of initial sequence numbers (MUST-8),
fn isn_four_microsecond_clock_progresses_and_wraps() {
    let (local, remote) = addresses();
    let tuple = Tuple { local, remote };
    let mut endpoint = Endpoint::new(config(), [7; 32], 0).unwrap();
    let first = opened_isn(&mut endpoint, 0, tuple);
    let second = opened_isn(&mut endpoint, 4, tuple);
    assert_eq!(second, first.wrapping_add(1));
    let third = opened_isn(&mut endpoint, 44, tuple);
    assert_eq!(third, second.wrapping_add(10));
    let start = u64::from(u32::MAX - 1) * 4;
    let mut endpoint = Endpoint::new(config(), [7; 32], start).unwrap();
    let before_wrap = opened_isn(&mut endpoint, start, tuple);
    let after_wrap = opened_isn(&mut endpoint, start + 12, tuple);
    assert_eq!(after_wrap, before_wrap.wrapping_add(3));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.4.1
//= type=test
//# SHOULD
//# generate its initial sequence numbers with the expression:
//#
//# ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
//#
//# where M is the 4 microsecond timer, and F() is a pseudorandom
//# function (PRF) of the connection's identifying parameters ("localip,
//# localport, remoteip, remoteport") and a secret key ("secretkey")
//# (SHLD-1).
fn isn_depends_on_secret_and_each_tuple_component() {
    let (local, remote) = addresses();
    let tuple = Tuple { local, remote };
    let sample =
        |secret, tuple| opened_isn(&mut Endpoint::new(config(), secret, 0).unwrap(), 0, tuple);
    let initial = sample([7; 32], tuple);
    assert_eq!(initial, sample([7; 32], tuple));
    // Key sensitivity is regression evidence, not a proof of MUST-9 secrecy.
    assert_ne!(initial, sample([8; 32], tuple));
    for changed in [
        Tuple {
            local: "192.0.2.3:40000".parse().unwrap(),
            ..tuple
        },
        Tuple {
            local: "192.0.2.1:40001".parse().unwrap(),
            ..tuple
        },
        Tuple {
            remote: "192.0.2.3:8080".parse().unwrap(),
            ..tuple
        },
        Tuple {
            remote: "192.0.2.2:8081".parse().unwrap(),
            ..tuple
        },
    ] {
        assert_ne!(initial, sample([7; 32], changed));
    }
}

fn input_header(endpoint: &mut Endpoint, ip: IpMetadata, header: wire::Header) -> InputDisposition {
    let mut bytes = [0; 128];
    let len = wire::encode(ip, header, &[], &[], &mut bytes).unwrap();
    endpoint.input(0, ip, &bytes[..len]).unwrap()
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5
//= type=test
//# Note that a TCP implementation MUST keep track of whether a
//# connection has reached SYN-RECEIVED state as the result of a passive
//# OPEN or an active OPEN (MUST-11).
fn syn_received_reset_preserves_passive_listener_but_closes_active_open() {
    let (mut a, mut b, listener, client) = endpoints();
    let syns = packets(&mut a, 0);
    let syn = wire::parse(syns[0].0, &syns[0].1).unwrap().header;
    deliver(&mut b, 0, syns.clone());
    let replies = packets(&mut b, 0);
    let syn_ack = wire::parse(replies[0].0, &replies[0].1).unwrap().header;
    input_header(
        &mut b,
        syns[0].0,
        wire::Header {
            sequence: syn.sequence.wrapping_add(1),
            flags: wire::RST,
            ..syn
        },
    );
    assert!(packets(&mut b, 0).is_empty());
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    // The same listener still admits a fresh SYN.
    deliver(&mut b, 0, syns);
    assert_eq!(packets(&mut b, 0).len(), 1);

    // A bare SYN to the active opener creates simultaneous-open SYN-RECEIVED.
    input_header(
        &mut a,
        replies[0].0,
        wire::Header {
            flags: wire::SYN,
            acknowledgment: 0,
            ..syn_ack
        },
    );
    assert_eq!(a.state(client).unwrap(), State::SynReceived);
    packets(&mut a, 0);
    input_header(
        &mut a,
        replies[0].0,
        wire::Header {
            sequence: syn_ack.sequence.wrapping_add(1),
            flags: wire::RST,
            ..syn_ack
        },
    );
    assert_eq!(a.state(client).unwrap(), State::Closed);
    assert_eq!(a.close_reason(client).unwrap(), Some(CloseReason::Reset));
    assert!(a.buffer_bytes() > 0); // Active terminal status belongs to its caller.
}

#[test]
fn duplicate_listen_and_pending_open_port_sharing_preserve_existing_records() {
    let (mut a, mut b, listener, client) = endpoints();
    let (local, remote) = addresses();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //= type=test
    //# Every passive OPEN call either creates a new connection record in
    //# LISTEN state, or it returns an error; it MUST NOT affect any
    //# previously created connection record (MUST-41).
    assert_eq!(b.listen(remote, 1), Err(EndpointError::AddressInUse));
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //= type=test
    //# A TCP implementation that supports multiple concurrent connections
    //# MUST provide an OPEN call that will functionally allow an application
    //# to LISTEN on a port while a connection block with the same local port
    //# is in SYN-SENT or SYN-RECEIVED state (MUST-42).
    let active_listener = a.listen(local, 1).unwrap();
    assert_eq!(a.state(client).unwrap(), State::SynSent);
    let syns = packets(&mut a, 0);
    deliver(&mut b, 0, syns);
    let replies = packets(&mut b, 0);
    let header = wire::parse(replies[0].0, &replies[0].1).unwrap().header;
    input_header(
        &mut a,
        replies[0].0,
        wire::Header {
            flags: wire::SYN,
            acknowledgment: 0,
            ..header
        },
    );
    assert_eq!(a.state(client).unwrap(), State::SynReceived);
    a.close_listener(active_listener).unwrap();
    packets(&mut a, 0); // Complete bounded listener cleanup, not the active open.
    assert!(a.listen(local, 1).is_ok());
    assert_eq!(a.state(client).unwrap(), State::SynReceived);
    deliver(&mut a, 0, replies);
    pump(&mut a, &mut b, 0);
    assert_eq!(a.state(client).unwrap(), State::Established);
    let server = b.accept(listener).unwrap();
    assert_eq!(b.state(server).unwrap(), State::Established);
}

#[test]
fn explicit_source_and_wildcard_listener_bind_and_reuse_actual_local_address() {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0).unwrap();
    let listener = b.listen("0.0.0.0:8080".parse().unwrap(), 4).unwrap();
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //= type=test
    //# The optional "local IP address" parameter MUST be supported to allow
    //# the specification of the local IP address (MUST-43).
    let client = a
        .connect_with_source(0, Some(local), remote, |_| {
            panic!("explicit source must bypass selection")
        })
        .unwrap();
    let syns = packets(&mut a, 0);
    assert_eq!(syns[0].0.source, local.ip());
    deliver(&mut b, 0, syns);
    let replies = packets(&mut b, 0);
    assert_eq!(replies[0].0.source, remote.ip());
    deliver(&mut a, 0, replies);
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    assert_eq!(b.tuple(server).unwrap().local, remote);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
    //= type=test
    //# At all other times, a previous segment has either been sent or
    //# received on this connection, and TCP implementations MUST use the
    //# same local address that was used in those previous segments (MUST-
    //# 45).
    for (endpoint, id, expected) in [(&mut a, client, local.ip()), (&mut b, server, remote.ip())] {
        endpoint.write(id, b"bound").unwrap();
        let flight = packets(endpoint, 0);
        assert!(!flight.is_empty());
        assert!(flight.iter().all(|(ip, _)| ip.source == expected));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# o  In general, the processing of received segments MUST be
//# implemented to aggregate ACK segments whenever possible
//# (MUST-58).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# For example, if the TCP endpoint is processing a
//# series of queued segments, it MUST process them all before
//# sending any ACK segments (MUST-59).
fn queued_input_aggregates_acknowledgments_before_output_poll() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.write(client, &[7; 192]).unwrap();
    let flight = packets(&mut a, 0);
    assert_eq!(flight.len(), 3);
    let last = wire::parse(flight[2].0, &flight[2].1).unwrap();
    let next = last.header.sequence.wrapping_add(last.payload.len() as u32);
    deliver(&mut b, 0, flight); // Driver feeds its entire input batch before polling.
    let replies = packets(&mut b, 0);
    assert_eq!(replies.len(), 1);
    let ack = wire::parse(replies[0].0, &replies[0].1).unwrap();
    assert_eq!(ack.header.flags, wire::ACK);
    assert_eq!(ack.header.acknowledgment, next);
    assert_eq!(b.read(server, &mut [0; 192]).unwrap(), 192);
}

#[test]
fn listener_cleanup_retries_unaccepted_child_reset() {
    let (mut a, mut b, listener, _) = endpoints();
    passive_quote(&mut a, &mut b);
    b.close_listener(listener).unwrap();
    assert_eq!(
        b.poll_transmit(0, &mut [0; 1], 1),
        Err(EndpointError::Connection(Error::OutputTooSmall))
    );
    assert!(b.buffer_bytes() > 0);
    let replies = packets(&mut b, 0);
    assert_eq!(replies.len(), 1);
    assert_ne!(
        wire::parse(replies[0].0, &replies[0].1)
            .unwrap()
            .header
            .flags
            & wire::RST,
        0
    );
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(b.accept(listener), Err(EndpointError::InvalidHandle));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
//= type=test
//= reason=Directed-broadcast validation requires configured subnet knowledge.
//# A TCP implementation MUST reject as an error a local OPEN call for an
//# invalid remote IP address (e.g., a broadcast or multicast address)
//# (MUST-46).
fn configured_directed_broadcasts_are_rejected_before_open_or_input() {
    let (local, remote) = addresses();
    let broadcast = "192.0.2.255:8080".parse().unwrap();
    let host: core::net::SocketAddr = "192.0.2.254:8080".parse().unwrap();
    let mut cfg = config();
    // A host address is accepted as the subnet specification, as with interface addresses.
    cfg.ipv4_subnets.push(("192.0.2.17".parse().unwrap(), 24));
    let mut endpoint = Endpoint::new(cfg, [1; 32], 0).unwrap();
    assert_eq!(
        endpoint.connect(0, local, broadcast),
        Err(EndpointError::InvalidAddress)
    );
    assert_eq!(
        endpoint.connect(0, broadcast, remote),
        Err(EndpointError::InvalidAddress)
    );
    assert_eq!(
        endpoint.listen(broadcast, 1),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    assert_eq!(endpoint.buffer_bytes(), 0);
    endpoint.listen("0.0.0.0:8080".parse().unwrap(), 4).unwrap();
    let syn = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: 123,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 1024,
        urgent_pointer: 0,
    };
    for ip in [
        IpMetadata {
            source: local.ip(),
            destination: broadcast.ip(),
        },
        IpMetadata {
            source: broadcast.ip(),
            destination: remote.ip(),
        },
    ] {
        assert_eq!(
            input_header(&mut endpoint, ip, syn),
            InputDisposition::Dropped
        );
        assert_eq!(endpoint.buffer_bytes(), 0);
        assert!(packets(&mut endpoint, 0).is_empty());
    }
    assert_eq!(
        input_header(
            &mut endpoint,
            IpMetadata {
                source: host.ip(),
                destination: remote.ip()
            },
            syn
        ),
        InputDisposition::Processed
    );
    assert!(endpoint.buffer_bytes() > 0);
    assert_eq!(packets(&mut endpoint, 0).len(), 1);
    assert!(endpoint.connect(0, local, host).is_ok());
    assert!(endpoint.listen(host, 1).is_ok());
}

#[test]
fn subnet_prefix_bounds_point_to_point_and_ipv6_behavior() {
    let (local, _) = addresses();
    let remote = "192.0.2.255:8080".parse().unwrap();
    for prefix in [31, 32] {
        let mut cfg = config();
        cfg.ipv4_subnets
            .push(("192.0.2.254".parse().unwrap(), prefix));
        let mut endpoint = Endpoint::new(cfg, [1; 32], 0).unwrap();
        assert!(endpoint.connect(0, local, remote).is_ok());
        assert!(endpoint.listen(remote, 1).is_ok());
        // The .255 point-to-point/host address is also valid on input.
        let syn = wire::Header {
            source_port: 41000,
            destination_port: 8080,
            sequence: 1,
            acknowledgment: 0,
            flags: wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        };
        assert_eq!(
            input_header(
                &mut endpoint,
                IpMetadata {
                    source: local.ip(),
                    destination: remote.ip()
                },
                syn
            ),
            InputDisposition::Processed
        );
        assert!(
            packets(&mut endpoint, 0)
                .iter()
                .any(|(ip, _)| ip.source == remote.ip())
        );
    }
    for cfg in [
        EndpointConfig {
            ipv4_subnets: vec![("192.0.2.1".parse().unwrap(), 33)],
            ..config()
        },
        EndpointConfig {
            ipv4_subnets: vec![("192.0.2.1".parse().unwrap(), 24); 65],
            ..config()
        },
    ] {
        assert!(matches!(
            Endpoint::new(cfg, [1; 32], 0),
            Err(EndpointError::Connection(Error::InvalidArgument))
        ));
    }
    let mut cfg = config();
    cfg.ipv4_subnets = vec![("0.0.0.0".parse().unwrap(), 0); 64];
    let mut endpoint = Endpoint::new(cfg, [1; 32], 0).unwrap();
    assert!(endpoint.connect(0, local, remote).is_ok()); // /0 has only 255.255.255.255 broadcast.
    assert_eq!(
        endpoint.connect(0, local, "255.255.255.255:8080".parse().unwrap()),
        Err(EndpointError::InvalidAddress)
    );
    let v6_local = "[2001:db8::1]:40000".parse().unwrap();
    let v6_remote = "[2001:db8::2]:8080".parse().unwrap();
    assert!(endpoint.connect(0, v6_local, v6_remote).is_ok());
    assert!(endpoint.listen(v6_remote, 1).is_ok());
    assert_eq!(
        endpoint.connect(0, v6_local, "[ff02::1]:8080".parse().unwrap()),
        Err(EndpointError::InvalidAddress)
    );
    // No prefix knowledge is inferred from addresses when the list is empty.
    let mut endpoint = Endpoint::new(config(), [1; 32], 0).unwrap();
    assert!(endpoint.connect(0, local, remote).is_ok());
}

#[test]
fn passive_report_backpressure_does_not_block_active_connection_errors() {
    let (mut a, mut b, listener, _) = endpoints();
    let (tuple, sequence) = passive_quote(&mut a, &mut b);
    for _ in 0..config().max_connections {
        assert!(
            b.network_error(0, tuple, sequence, NetworkError::SoftUnreachable)
                .unwrap()
        );
    }
    let mut active_tuple = tuple;
    active_tuple.local.set_port(tuple.local.port() + 1);
    let active = b
        .connect(0, active_tuple.local, active_tuple.remote)
        .unwrap();
    let output = packets(&mut b, 0);
    assert_eq!(output.len(), 1);
    let sequence = wire::parse(output[0].0, &output[0].1)
        .unwrap()
        .header
        .sequence;
    assert!(
        b.network_error(0, active_tuple, sequence, NetworkError::HardUnreachable)
            .unwrap()
    );
    assert_eq!(b.state(active).unwrap(), State::Closed);
    for _ in 0..config().max_connections {
        assert_eq!(
            b.next_event(),
            Some(Event::PassiveError {
                listener,
                tuple,
                error: NetworkError::SoftUnreachable
            })
        );
    }
    assert!(
        matches!(b.next_event(), Some(Event::Connection(id, events)) if id == active && events.network_error == Some(NetworkError::HardUnreachable))
    );
    assert_eq!(b.next_event(), None);
}

fn ecn_packet(endpoint: &mut Endpoint, now: u64) -> (Transmit, Vec<u8>) {
    let mut bytes = [0; 2048];
    let packet = endpoint
        .poll_transmit(now, &mut bytes, 64)
        .unwrap()
        .packet
        .unwrap();
    (packet, bytes[..packet.len].to_vec())
}

fn ecn_deliver(endpoint: &mut Endpoint, now: u64, packet: &(Transmit, Vec<u8>), ce: bool) {
    endpoint
        .input_with_traffic_class(
            now,
            packet.0.ip,
            (packet.0.dscp << 2) | if ce { 3 } else { packet.0.ecn },
            &packet.1,
        )
        .unwrap();
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.2
//= type=test
//# A TCP endpoint SHOULD implement ECN as described in RFC 3168 (SHLD-
//# 8).
fn classic_ecn_duplex_feedback_loss_cwr_and_capacity() {
    let (mut a, mut b, listener, client) = endpoints();
    let syn = ecn_packet(&mut a, 0);
    assert_eq!(syn.0.ecn, 0);
    assert_eq!(
        wire::parse(syn.0.ip, &syn.1).unwrap().header.flags,
        wire::SYN | wire::ECE | wire::CWR
    );
    ecn_deliver(&mut b, 0, &syn, false);
    let synack = ecn_packet(&mut b, 0);
    assert_eq!(synack.0.ecn, 0);
    assert_eq!(
        wire::parse(synack.0.ip, &synack.1).unwrap().header.flags,
        wire::SYN | wire::ACK | wire::ECE
    );
    ecn_deliver(&mut a, 0, &synack, false);
    let ack = ecn_packet(&mut a, 0);
    assert_eq!(ack.0.ecn, 0);
    ecn_deliver(&mut b, 0, &ack, false);
    let server = b.accept(listener).unwrap();
    {
        let (sender, receiver, id) = (&mut a, &mut b, client);
        sender.write(id, &[1; 64]).unwrap();
        let data = ecn_packet(sender, 1);
        assert_eq!(data.0.ecn, 2);
        let mut corrupt = data.1.clone();
        corrupt[16] ^= 1;
        assert_eq!(
            receiver
                .input_with_traffic_class(1, data.0.ip, 3, &corrupt)
                .unwrap(),
            InputDisposition::Dropped
        );
        assert!(
            receiver
                .poll_transmit(1, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        ecn_deliver(receiver, 1, &data, true);
        let lost_ece = ecn_packet(receiver, 1);
        assert_eq!(lost_ece.0.ecn, 0);
        assert_ne!(
            wire::parse(lost_ece.0.ip, &lost_ece.1)
                .unwrap()
                .header
                .flags
                & wire::ECE,
            0
        );
        // Duplicate old data does not create a new CE event but repeats existing echo.
        ecn_deliver(receiver, 2, &data, false);
        let ece = ecn_packet(receiver, 2);
        assert_ne!(
            wire::parse(ece.0.ip, &ece.1).unwrap().header.flags & wire::ECE,
            0
        );
        ecn_deliver(sender, 2, &ece, false);
        // ECE alone schedules no retransmission.
        assert!(
            sender
                .poll_transmit(2, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        sender.write(id, &[2; 64]).unwrap();
        assert_eq!(
            sender.poll_transmit(2, &mut [0; 19], 64),
            Err(EndpointError::Connection(Error::OutputTooSmall))
        );
        let cwr = ecn_packet(sender, 2);
        assert_eq!(cwr.0.ecn, 2);
        assert_ne!(
            wire::parse(cwr.0.ip, &cwr.1).unwrap().header.flags & wire::CWR,
            0
        );
        // Lose CWR data; the RTO retransmission must be Not-ECT and have no CWR.
        let deadline = sender.next_deadline().unwrap();
        sender.on_timeout(deadline, 64).unwrap();
        let retransmit = ecn_packet(sender, deadline);
        assert_eq!(retransmit.0.ecn, 0);
        assert_eq!(
            wire::parse(retransmit.0.ip, &retransmit.1)
                .unwrap()
                .header
                .flags
                & wire::CWR,
            0
        );
        ecn_deliver(receiver, deadline, &retransmit, false);
        receiver.on_timeout(deadline + 200_000, 64).unwrap();
        let ack = ecn_packet(receiver, deadline + 200_000);
        assert_ne!(
            wire::parse(ack.0.ip, &ack.1).unwrap().header.flags & wire::ECE,
            0
        );
        ecn_deliver(sender, deadline + 200_000, &ack, false);
        sender.write(id, &[3; 64]).unwrap();
        // ECE at a one-MSS window after RTO delays fresh data for another RTO.
        assert!(
            sender
                .poll_transmit(deadline + 200_000, &mut [0; 2048], 64)
                .unwrap()
                .packet
                .is_none()
        );
        let now = deadline + 10_200_000;
        sender.on_timeout(now, 64).unwrap();
        let cwr = ecn_packet(sender, now);
        assert_ne!(
            wire::parse(cwr.0.ip, &cwr.1).unwrap().header.flags & wire::CWR,
            0
        );
        ecn_deliver(receiver, now, &cwr, false);
        receiver.on_timeout(now + 200_000, 64).unwrap();
        let ack = ecn_packet(receiver, now + 200_000);
        assert_eq!(
            wire::parse(ack.0.ip, &ack.1).unwrap().header.flags & wire::ECE,
            0
        );
        ecn_deliver(sender, now + 200_000, &ack, false);
    }
    b.write(server, &[4; 64]).unwrap();
    let now = 20_000_000;
    let data = ecn_packet(&mut b, now);
    assert_eq!(data.0.ecn, 2);
    ecn_deliver(&mut a, now, &data, true);
    let ack = ecn_packet(&mut a, now);
    assert_ne!(
        wire::parse(ack.0.ip, &ack.1).unwrap().header.flags & wire::ECE,
        0
    );
    ecn_deliver(&mut b, now, &ack, false);
    b.write(server, &[5; 64]).unwrap();
    let cwr = ecn_packet(&mut b, now);
    assert_ne!(
        wire::parse(cwr.0.ip, &cwr.1).unwrap().header.flags & wire::CWR,
        0
    );
}

#[test]
fn classic_ecn_opt_out_and_syn_timeout_fallback() {
    for (enabled, lost_syn) in [(false, false), (true, true)] {
        let (local, remote) = addresses();
        let mut cfg = config();
        cfg.connection.ecn = enabled;
        let mut a = Endpoint::new(config(), [1; 32], 0).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
        let listener = b.listen(remote, 4).unwrap();
        let id = a.connect(0, local, remote).unwrap();
        let first = ecn_packet(&mut a, 0);
        let now = if lost_syn { 1_000_000 } else { 0 };
        let syn = if lost_syn {
            a.on_timeout(now, 64).unwrap();
            assert!(a.poll_transmit(now, &mut [0; 19], 64).is_err());
            let syn = ecn_packet(&mut a, now);
            assert_eq!(
                wire::parse(syn.0.ip, &syn.1).unwrap().header.flags,
                wire::SYN
            );
            syn
        } else {
            first
        };
        ecn_deliver(&mut b, now, &syn, false);
        let synack = ecn_packet(&mut b, now);
        assert_eq!(
            wire::parse(synack.0.ip, &synack.1).unwrap().header.flags,
            wire::SYN | wire::ACK
        );
        ecn_deliver(&mut a, now, &synack, false);
        pump(&mut a, &mut b, now);
        let server = b.accept(listener).unwrap();
        for (endpoint, id) in [(&mut a, id), (&mut b, server)] {
            endpoint.write(id, &[0; 64]).unwrap();
            assert_eq!(ecn_packet(endpoint, now).0.ecn, 0);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
//= type=test
//# TCP implementations MAY pass the most recently received
//# Differentiated Services field up to the application (MAY-9).
fn received_dscp_is_validated_per_connection_and_independent_of_send_dscp() {
    let (mut a, mut b, listener, client) = endpoints();
    assert_eq!(a.received_dscp(client).unwrap(), None);
    a.set_dscp(client, 46).unwrap();
    let syn = ecn_packet(&mut a, 0);
    ecn_deliver(&mut b, 0, &syn, false);
    let synack = ecn_packet(&mut b, 0);
    a.input_with_traffic_class(0, synack.0.ip, 10 << 2 | 3, &synack.1)
        .unwrap();
    assert_eq!(a.received_dscp(client).unwrap(), Some(10));
    let mut corrupt = synack.1.clone();
    corrupt[16] ^= 1;
    assert_eq!(
        a.input_with_traffic_class(0, synack.0.ip, 63 << 2, &corrupt)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert_eq!(a.received_dscp(client).unwrap(), Some(10));
    let unknown = IpMetadata {
        source: "192.0.2.99".parse().unwrap(),
        ..synack.0.ip
    };
    let parsed = wire::parse(synack.0.ip, &synack.1).unwrap();
    let mut bytes = [0; 128];
    let len = wire::encode(unknown, parsed.header, &[], &[], &mut bytes).unwrap();
    a.input_with_traffic_class(0, unknown, 63 << 2, &bytes[..len])
        .unwrap();
    assert_eq!(a.received_dscp(client).unwrap(), Some(10));
    // Drain the unknown tuple's reset, then the handshake ACK.
    let mut ack = ecn_packet(&mut a, 0);
    if wire::parse(ack.0.ip, &ack.1).unwrap().header.flags & wire::RST != 0 {
        ack = ecn_packet(&mut a, 0);
    }
    assert_eq!(ack.0.dscp, 46);
    ecn_deliver(&mut b, 0, &ack, false);
    let server = b.accept(listener).unwrap();
    assert_eq!(b.received_dscp(server).unwrap(), Some(46));
    assert_eq!(synack.0.dscp, 0);
    a.abort(client).unwrap();
    packets(&mut a, 0);
    a.release(client).unwrap();
    assert_eq!(a.received_dscp(client), Err(EndpointError::InvalidHandle));
}

#[test]
fn optional_stream_controls_refresh_endpoint_work_and_charge_marker_storage() {
    let (mut a, mut b, listener, client) = endpoints();
    assert_eq!(a.buffer_bytes(), 3 * 1024 + 2 * 1024 + 64);
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    while a.next_event().is_some() {}
    while b.next_event().is_some() {}
    a.write_with_push(client, b"retain!", false).unwrap();
    assert!(packets(&mut a, 0).is_empty());
    assert_eq!(a.flush(client), Ok(0));
    a.write_with_push(client, b"ab", false).unwrap();
    assert!(packets(&mut a, 0).is_empty());
    a.write_with_push(client, b"cd", true).unwrap();
    pump(&mut a, &mut b, 0);
    assert!(matches!(b.next_event(), Some(Event::Connection(id, events))
        if id == server && events.readable && events.pushed));
    let mut retained = [0; 7];
    assert_eq!(b.read(server, &mut retained), Ok(7));
    assert_eq!(&retained, b"retain!");
    b.close(server).unwrap(); // Unread abcd: schedule RST, not FIN.
    assert_eq!(
        b.read(server, &mut [0]),
        Err(EndpointError::Connection(Error::InvalidState))
    );
    assert!(matches!(b.next_event(), Some(Event::Connection(id, events))
        if id == server && events.closed == Some(CloseReason::Aborted)));
    pump(&mut a, &mut b, 0);
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::Reset)));
    assert_eq!(
        a.flush(client),
        Err(EndpointError::Connection(Error::InvalidState))
    );

    let mut limited = config();
    limited.max_buffer_bytes = 3 * 1024 + 2 * 1024 + 64 - 1;
    let mut endpoint = Endpoint::new(limited, [3; 32], 0).unwrap();
    let (local, remote) = addresses();
    assert_eq!(
        endpoint.connect(0, local, remote),
        Err(EndpointError::LimitReached)
    );
}

#[test]
fn flush_discards_unsent_data_after_peer_advertises_zero_window() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.write(client, &[42; 1024]).unwrap();
    pump(&mut a, &mut b, 0);
    for t in 1..=8 {
        tick(&mut a, &mut b, t * 200_000);
    }
    assert_eq!(a.acknowledged(client), Ok(1024));
    a.write_with_push(client, b"discard", false).unwrap();
    assert!(packets(&mut a, 1_600_000).is_empty());
    assert_eq!(a.flush(client), Ok(7));
    let mut received = [0; 1024];
    assert_eq!(b.read(server, &mut received), Ok(1024));
    assert_eq!(received, [42; 1024]);
    pump(&mut a, &mut b, 1_600_000);
    a.write(client, b"replacement").unwrap();
    pump(&mut a, &mut b, 1_600_000);
    assert_eq!(b.read(server, &mut received), Ok(11));
    assert_eq!(&received[..11], b"replacement");
}

fn completed_route(hops: &[u8]) -> Ipv4Options {
    let mut bytes = [0; 40];
    let len = 3 + hops.len() * 4;
    bytes[..3].copy_from_slice(&[131, len as u8, len as u8 + 1]);
    for (i, &hop) in hops.iter().enumerate() {
        bytes[3 + i * 4..7 + i * 4].copy_from_slice(&[192, 0, 2, hop]);
    }
    Ipv4Options::parse(&bytes[..len], true).unwrap()
}

fn option_packet(endpoint: &mut Endpoint, now: u64) -> (Transmit, Vec<u8>) {
    let mut bytes = [0; 2048];
    for _ in 0..64 {
        if let Some(packet) = endpoint.poll_transmit(now, &mut bytes, 16).unwrap().packet {
            return (packet, bytes[..packet.len].to_vec());
        }
    }
    panic!("no output");
}

// Check a real TCP pseudoheader against the logical destination, not the first hop.
fn assert_route(packet: Transmit, bytes: &[u8], hops: &[u8]) {
    use core::net::{IpAddr, Ipv4Addr};
    let route = packet.ipv4_options.source_route.unwrap();
    let expected: Vec<_> = hops.iter().map(|&n| Ipv4Addr::new(192, 0, 2, n)).collect();
    assert_eq!(route.hops(), expected);
    let (IpAddr::V4(source), IpAddr::V4(remote)) = (packet.ip.source, packet.ip.destination) else {
        panic!()
    };
    let mut options = [0; 40];
    let (first, len) = packet
        .ipv4_options
        .encode(source, remote, 0, &mut options)
        .unwrap();
    assert!(wire::parse(packet.ip, bytes).is_ok());
    if !hops.is_empty() {
        assert!(len <= 40);
        assert_eq!(first, expected[0]);
        assert!(
            wire::parse(
                IpMetadata {
                    source: packet.ip.source,
                    destination: first.into()
                },
                bytes
            )
            .is_err()
        );
        assert_eq!(
            &options[3 + 4 * (hops.len() - 1)..7 + 4 * (hops.len() - 1)],
            &remote.octets()
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.1
//= type=test
//# When a TCP connection is OPENed passively and a packet arrives with a
//# completed IP Source Route Option (containing a return route), TCP
//# implementations MUST save the return route and use it for all
//# segments sent on this connection (MUST-53).  If a different source
//# route arrives in a later segment, the later definition SHOULD
//# override the earlier one (SHLD-24).
#[test]
fn ipv4_passive_owned_return_route_replacement_and_rejected_tcp_metadata() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    a.connect(0, local, remote).unwrap();
    let (syn, bytes) = option_packet(&mut a, 0);
    let route_a = completed_route(&[8, 9]);
    b.input_with_ipv4_options(0, syn.ip, 0, route_a, &bytes)
        .unwrap();
    let (synack, bytes) = option_packet(&mut b, 0);
    assert_route(synack, &bytes, &[9, 8]);
    a.input(0, synack.ip, &bytes).unwrap();
    let (ack, ack_bytes) = option_packet(&mut a, 0);
    b.input_with_ipv4_options(0, ack.ip, 0, route_a, &ack_bytes)
        .unwrap();
    let server = b.accept(listener).unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(route_a));
    let original = wire::parse(ack.ip, &ack_bytes).unwrap().header;
    let route_b = completed_route(&[10, 11]);
    for case in 0..4 {
        let mut header = original;
        match case {
            0 => header.sequence = header.sequence.wrapping_add(1_000_000),
            1 => header.acknowledgment = header.acknowledgment.wrapping_add(1_000_000),
            2 => header.flags = 0,
            _ => {}
        }
        let mut forged = [0; 60];
        let len = wire::encode(ack.ip, header, &[], &[], &mut forged).unwrap();
        if case == 3 {
            forged[16] ^= 1;
        }
        b.input_with_ipv4_options(0, ack.ip, 0, route_b, &forged[..len])
            .unwrap();
        assert_eq!(b.received_ipv4_options(server).unwrap(), Some(route_a));
        b.write(server, b"x").unwrap();
        let (packet, bytes) = option_packet(&mut b, 0);
        assert_route(packet, &bytes, &[9, 8]);
    }
    b.input_with_ipv4_options(0, ack.ip, 0, route_b, &ack_bytes)
        .unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(route_b));
    b.write(server, b"x").unwrap();
    let (packet, bytes) = option_packet(&mut b, 0);
    assert_route(packet, &bytes, &[11, 10]);
    b.input(0, ack.ip, &ack_bytes).unwrap();
    assert_eq!(
        b.received_ipv4_options(server).unwrap(),
        Some(Ipv4Options::default())
    );
    b.write(server, b"x").unwrap();
    let (packet, bytes) = option_packet(&mut b, 0);
    assert_route(packet, &bytes, &[11, 10]);
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.1
//= type=test
//# An application MUST be able to specify a source route when it
//# actively opens a TCP connection (MUST-51), and this MUST take
//# precedence over a source route received in a datagram (MUST-52).
#[test]
fn ipv4_active_route_precedence_and_unoverridden_active_learning() {
    use core::net::Ipv4Addr;
    for explicit in [false, true] {
        let (local, remote) = addresses();
        let mut cfg = config();
        cfg.ipv4_options_enabled = true;
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
        b.listen(remote, 4).unwrap();
        let options = OutgoingIpv4Options {
            source_route: explicit
                .then(|| SourceRoute::new(&[Ipv4Addr::new(192, 0, 2, 7)], true).unwrap()),
            ..Default::default()
        };
        let client = a
            .connect_with_ipv4_options(0, local, remote, options)
            .unwrap();
        let (syn, bytes) = option_packet(&mut a, 0);
        if explicit {
            assert_route(syn, &bytes, &[7]);
        }
        b.input(0, syn.ip, &bytes).unwrap();
        let (synack, bytes) = option_packet(&mut b, 0);
        // SYN-SENT ACK rejection also cannot poison the return route.
        let mut bad_header = wire::parse(synack.ip, &bytes).unwrap().header;
        bad_header.acknowledgment = bad_header.acknowledgment.wrapping_add(500);
        let mut bad = [0; 60];
        let n = wire::encode(synack.ip, bad_header, &[], &[], &mut bad).unwrap();
        a.input_with_ipv4_options(0, synack.ip, 0, completed_route(&[13]), &bad[..n])
            .unwrap();
        assert_eq!(a.received_ipv4_options(client).unwrap(), None);
        let _ = packets(&mut a, 0); // Drain the bad-ACK reset.
        a.input_with_ipv4_options(0, synack.ip, 0, completed_route(&[9]), &bytes)
            .unwrap();
        let (packet, bytes) = option_packet(&mut a, 0);
        assert_route(packet, &bytes, if explicit { &[7] } else { &[9] });
        assert_eq!(packet.ipv4_options.source_route.unwrap().strict, explicit);
        assert_eq!(a.tuple(client).unwrap(), Tuple { local, remote });
    }
}

#[test]
fn ipv4_options_security_profile_validation_and_control_route() {
    use core::net::Ipv4Addr;
    let (local, remote) = addresses();
    let route = SourceRoute::new(&[Ipv4Addr::new(192, 0, 2, 7)], false).unwrap();
    let options = OutgoingIpv4Options {
        source_route: Some(route),
        ..Default::default()
    };
    let mut a = Endpoint::new(config(), [1; 32], 0).unwrap();
    assert!(
        a.connect_with_ipv4_options(0, local, remote, options)
            .is_err()
    );
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    cfg.ipv4_subnets.push((Ipv4Addr::new(192, 0, 2, 0), 24));
    let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
    let mut bad = options;
    bad.source_route = Some(SourceRoute::new(&[Ipv4Addr::new(192, 0, 2, 255)], false).unwrap());
    assert!(b.connect_with_ipv4_options(0, local, remote, bad).is_err());
    assert!(
        b.connect_with_ipv4_options(
            0,
            "[2001:db8::1]:40000".parse().unwrap(),
            "[2001:db8::2]:80".parse().unwrap(),
            options
        )
        .is_err()
    );
    let client = a.connect(0, local, remote).unwrap();
    let (syn, bytes) = option_packet(&mut a, 0);
    assert_eq!(
        a.input_with_ipv4_options(0, syn.ip, 0, completed_route(&[7]), &bytes)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert_eq!(a.received_ipv4_options(client).unwrap(), None);
    assert_eq!(
        b.input_with_ipv4_options(0, syn.ip, 0, completed_route(&[255]), &bytes)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert!(!b.has_pending_output());
    b.input_with_ipv4_options(0, syn.ip, 0, completed_route(&[7, 8]), &bytes)
        .unwrap();
    let (reset, bytes) = option_packet(&mut b, 0);
    assert_route(reset, &bytes, &[8, 7]);
    assert_ne!(
        wire::parse(reset.ip, &bytes).unwrap().header.flags & wire::RST,
        0
    );
    let ipv6 = IpMetadata {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    };
    assert_eq!(
        b.input_with_ipv4_options(0, ipv6, 0, completed_route(&[7]), &bytes)
            .unwrap(),
        InputDisposition::Dropped
    );
}

#[test]
fn ipv4_options_reserve_send_budget_without_lowering_receive_mss() {
    let (local, remote) = addresses();
    for base in [68, 1480, u16::MAX] {
        let mut cfg = config();
        cfg.ipv4_options_enabled = true;
        cfg.connection.mss = 1460;
        cfg.connection.send_capacity = 65536;
        cfg.connection.receive_capacity = 65536;
        cfg.connection.send_ip_payload_limit = base;
        cfg.connection.receive_ip_payload_limit = 1480;
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
        b.listen(remote, 4).unwrap();
        let client = a.connect(0, local, remote).unwrap();
        let (syn, bytes) = option_packet(&mut a, 0);
        assert_eq!(wire::parse(syn.ip, &bytes).unwrap().options.mss, Some(1460));
        b.input(0, syn.ip, &bytes).unwrap();
        pump(&mut a, &mut b, 0);
        a.write(client, &[0; 3000]).unwrap();
        for (_, bytes) in packets(&mut a, 0) {
            assert!(bytes.len() <= usize::from(base.min(65515) - 40));
        }
    }
    for base in [0, 39, 40, 67] {
        let mut cfg = config();
        cfg.ipv4_options_enabled = true;
        cfg.connection.send_ip_payload_limit = base;
        assert!(Endpoint::new(cfg, [1; 32], 0).is_err());
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
//= type=test
//# A TCP implementation MAY support the Timestamp (MAY-10) and Record
//# Route (MAY-11) Options.
#[test]
fn ipv4_outgoing_requests_and_received_owned_snapshot() {
    use core::net::{IpAddr, Ipv4Addr};
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let request = OutgoingIpv4Options {
        source_route: Some(SourceRoute::new(&[], false).unwrap()),
        record_route_slots: Some(2),
        timestamp: Some(TimestampRequest::AddressTimes(2)),
    };
    let mut invalid = request;
    invalid.source_route = None; // No fixed route budget for automatic route replacement.
    assert!(
        a.connect_with_ipv4_options(0, local, remote, invalid)
            .is_err()
    );
    invalid = request;
    invalid.record_route_slots = Some(9);
    assert!(
        a.connect_with_ipv4_options(0, local, remote, invalid)
            .is_err()
    );
    invalid = request;
    invalid.timestamp = Some(TimestampRequest::Prespecified {
        addresses: [Ipv4Addr::BROADCAST; 4],
        len: 1,
    });
    assert!(
        a.connect_with_ipv4_options(0, local, remote, invalid)
            .is_err()
    );
    a.connect_with_ipv4_options(0, local, remote, request)
        .unwrap();
    let (syn, bytes) = option_packet(&mut a, 0);
    assert_eq!(syn.ipv4_options, request);
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (syn.ip.source, syn.ip.destination) else {
        panic!()
    };
    let mut raw = [0; 40];
    let (_, len) = syn
        .ipv4_options
        .encode(source, destination, 0x8000_0001, &mut raw)
        .unwrap();
    let options = Ipv4Options::parse(&raw[..len], true)
        .unwrap()
        .record(destination, 0x8000_0002)
        .unwrap();
    raw.fill(0); // No metadata borrows the input packet.
    b.input_with_ipv4_options(0, syn.ip, 0, options, &bytes)
        .unwrap();
    let (synack, bytes) = option_packet(&mut b, 0);
    a.input(0, synack.ip, &bytes).unwrap();
    let (ack, bytes) = option_packet(&mut a, 0);
    b.input_with_ipv4_options(0, ack.ip, 0, options, &bytes)
        .unwrap();
    let server = b.accept(listener).unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(options));
}
