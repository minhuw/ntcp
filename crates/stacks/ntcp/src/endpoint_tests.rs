extern crate std;

use crate::wire;
use crate::*;
use std::{vec, vec::Vec};

// Synthetic documentation networks only; this is a test policy, not runtime configuration.
fn test_policy(request: AddressValidation) -> bool {
    test_subnet_policy(24)(request)
}

fn test_subnet_policy(prefix: u8) -> impl Fn(AddressValidation) -> bool {
    assert!(prefix <= 32);
    move |request| {
        let valid = |address: core::net::IpAddr| match address {
            core::net::IpAddr::V4(ip) => {
                ip.octets()[..3] == [192, 0, 2]
                    && (prefix > 30
                        || u32::from(ip)
                            != (u32::from_be_bytes([192, 0, 2, 254]) | (u32::MAX >> prefix)))
            }
            core::net::IpAddr::V6(ip) => ip.segments()[..2] == [0x2001, 0xdb8],
        };
        match request {
            AddressValidation::Bind { local } => local.is_unspecified() || valid(local),
            AddressValidation::Open { local, remote } => valid(local) && valid(remote),
            AddressValidation::Incoming {
                source,
                destination,
            } => valid(source) && valid(destination),
            AddressValidation::Route {
                source,
                destination,
                hop,
            } => valid(source) && valid(destination) && valid(hop),
        }
    }
}

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
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
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

    assert!(a.buffer_bytes() > 0);
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 1).unwrap();
    assert_eq!(a.buffer_bytes(), 0);
    let (local, remote) = addresses();
    let replacement = a.connect(expiry, local, remote).unwrap();
    assert_ne!(replacement, client);
    assert_eq!(a.write(client, b"bad"), Err(EndpointError::InvalidHandle));
    let mut limited = config();
    limited.max_buffer_bytes = 1;
    let mut endpoint = Endpoint::new(limited, [3; 32], 0, test_policy).unwrap();
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
            expiry,
            IpMetadata {
                source: remote.ip(),
                destination: local.ip()
            },
            &[0; 19]
        )
        .unwrap(),
        InputDisposition::Dropped
    );
    a.on_timeout(expiry + 1, 0).unwrap();
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
    assert!(b.buffer_bytes() > 0);
    let expiry = b.next_deadline().unwrap();
    b.on_timeout(expiry, 1).unwrap();
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(b.accept(listener), Err(EndpointError::InvalidHandle));
    let (_, remote) = addresses();
    assert!(b.listen(remote, 1).is_ok());
    assert_eq!(a.state(client).unwrap(), State::SynSent);
}

#[test]
fn every_connection_joining_the_accept_queue_raises_acceptable() {
    // As each new child wakes a Linux listener: a caller that took the
    // event but not every pending connection hears of the next one, and
    // joins before the caller looks give one event.
    let acceptable = |b: &mut Endpoint, listener| {
        let mut count = 0;
        while let Some(event) = b.next_event() {
            count += usize::from(event == Event::Acceptable(listener));
        }
        count
    };
    let (mut a, mut b, listener, _) = endpoints();
    let (local, remote) = addresses();
    pump(&mut a, &mut b, 0);
    assert_eq!(acceptable(&mut b, listener), 1);
    let address = |port| core::net::SocketAddr::new(local.ip(), port);
    a.connect(0, address(40001), remote).unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(acceptable(&mut b, listener), 1);
    for port in [40002, 40003] {
        a.connect(0, address(port), remote).unwrap();
    }
    pump(&mut a, &mut b, 0);
    assert_eq!(acceptable(&mut b, listener), 1);
    for _ in 0..4 {
        b.accept(listener).unwrap();
    }
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(acceptable(&mut b, listener), 0);
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
        // Eventual delivery, not an R2 give-up: a run of losses at the
        // 60-second backoff ceiling must not end either side before the
        // simulation's 1000-second horizon.
        a.set_user_timeout(client, 1_000_000_000).unwrap();
        b.set_user_timeout(server, 1_000_000_000).unwrap();
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
    assert_eq!(
        a.connect(1, local, remote),
        Err(EndpointError::AddressInUse)
    );
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 1).unwrap();
    assert_eq!(a.state(old), Ok(State::Closed));
    let replacement = a.connect(expiry, local, remote).unwrap();
    assert_ne!(old, replacement);
    a.release(old).unwrap();
    pump(&mut a, &mut b, expiry);
    let accepted = b.accept(listener).unwrap();
    assert_eq!(a.state(replacement).unwrap(), State::Established);
    b.release(peer).unwrap();
    a.write(replacement, b"new incarnation").unwrap();
    pump(&mut a, &mut b, expiry);
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
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
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
    let mut endpoint = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
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
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
//= type=test
//= reason=Unknown tuple reset suppression and data discarded; control output subject to explicit capacity/rate bounds.
//# all data in the incoming segment is discarded. An incoming segment containing a RST is
//# discarded. An incoming segment not containing a RST causes a RST to be sent in response.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
//= type=test
//= reason=Checks ACK-derived reset sequence and non-ACK sequence-space length including SYN/FIN across wrap.
//# If the ACK bit is off, sequence number zero is used,
//# <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> If the ACK bit is on, <SEQ=SEG.ACK><CTL=RST>
fn unknown_connection_reset_has_correct_sequence_and_never_answers_reset() {
    let mut b = Endpoint::new(config(), [4; 32], 0, test_policy).unwrap();
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
    //# If the ACK bit is off, sequence number zero is used,
    //#
    //# <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    assert_eq!(reset.header.sequence, 0);
    assert_eq!(reset.header.acknowledgment, 0);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.1
    //= type=test
    //# If the ACK bit is on,
    //#
    //# <SEQ=SEG.ACK><CTL=RST>
    input_header(
        &mut b,
        ip,
        wire::Header {
            acknowledgment: 12345,
            flags: wire::ACK,
            ..header
        },
    );
    let replies = packets(&mut b, 0);
    assert_eq!(replies.len(), 1);
    let reset = wire::parse(replies[0].0, &replies[0].1).unwrap();
    assert_eq!(reset.header.sequence, 12345);
    assert_eq!(reset.header.flags, wire::RST);
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
    //# segment containing a RST is discarded.  An incoming segment not
    //# containing a RST causes a RST to be sent in response.
    assert!(packets(&mut b, 0).is_empty());
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.5
//= type=test
//= reason=Terminal notification cancels stream operations immediately; explicit release invalidates the handle while bounded reset quarantine retains storage until expiry.
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
    assert_eq!(a.buffer_bytes(), retained);
    assert_eq!(a.next_deadline(), Some(config().connection.time_wait_us));
    assert!(packets(&mut a, 0).is_empty());
    deliver(&mut b, 0, reset);
    assert_eq!(b.state(server).unwrap(), State::Closed);
    assert_eq!(b.close_reason(server).unwrap(), Some(CloseReason::Reset));
    a.on_timeout(config().connection.time_wait_us, 1).unwrap();
    assert_eq!(a.buffer_bytes(), 0);
    assert!(a.next_deadline().is_none());
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
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg.clone(), [2; 32], 0, test_policy).unwrap();
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

    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
        let mut a = Endpoint::new(cfg, [1; 32], 0, test_policy).unwrap();
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
//= reason=Checks the clock progression, wraparound, and its addition to an independently assembled HMAC input.
//# A TCP implementation MUST use the above type of "clock" for clock-
//# driven selection of initial sequence numbers (MUST-8), and SHOULD
//# generate its initial sequence numbers with the expression:
fn isn_four_microsecond_clock_progresses_and_wraps() {
    let (local, remote) = addresses();
    let tuple = Tuple { local, remote };
    let mut endpoint = Endpoint::new(config(), [7; 32], 0, test_policy).unwrap();
    let first = opened_isn(&mut endpoint, 0, tuple);
    use hmac::{Hmac, Mac};
    let mut prf = Hmac::<sha2::Sha256>::new_from_slice(&[7; 32]).unwrap();
    prf.update(b"ntcp initial sequence");
    // IPv4 family tags, addresses and network-order ports for addresses().
    prf.update(&[4, 192, 0, 2, 1, 0x9c, 0x40, 4, 192, 0, 2, 2, 0x1f, 0x90]);
    let tag = prf.finalize().into_bytes();
    let f = u32::from_be_bytes(tag[..4].try_into().unwrap());
    assert_eq!(first, f.wrapping_add(1)); // First OPEN advances the zero-time clock.
    let second = opened_isn(&mut endpoint, 4, tuple);
    assert_eq!(second, first.wrapping_add(1));
    let third = opened_isn(&mut endpoint, 44, tuple);
    assert_eq!(third, second.wrapping_add(10));
    let start = u64::from(u32::MAX - 1) * 4;
    let mut endpoint = Endpoint::new(config(), [7; 32], start, test_policy).unwrap();
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
    let sample = |secret, tuple| {
        opened_isn(
            &mut Endpoint::new(config(), secret, 0, test_policy).unwrap(),
            0,
            tuple,
        )
    };
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

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
//= type=test
//= reason=LISTEN ACK/SYN-ACK/FIN-ACK reset sequence is checked; bounded reset_for output.
//# Any acknowledgment is bad if it arrives on a connection still in the LISTEN state. An
//# acceptable reset segment should be formed for any arriving ACK-bearing segment. The RST
//# should be formatted as follows: <SEQ=SEG.ACK><CTL=RST>
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
//= type=test
//= reason=Drops no-SYN, no-ACK non-RST input before allocating a child.
//# This should not be reached. Drop the segment and return.
fn listen_ignores_resets_resets_acks_and_drops_segments_without_syn() {
    let (local, remote) = addresses();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: 100,
        acknowledgment: 12345,
        flags: 0,
        window: 1024,
        urgent_pointer: 0,
    };
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= type=test
    //# An incoming RST should be ignored.  Return.
    for flags in [wire::RST, wire::RST | wire::ACK, wire::RST | wire::SYN] {
        assert_eq!(
            input_header(&mut b, ip, wire::Header { flags, ..header }),
            InputDisposition::Dropped
        );
        assert!(packets(&mut b, 0).is_empty());
        assert_eq!(b.buffer_bytes(), 0);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= type=test
    //# Any acknowledgment is bad if it arrives on a connection still
    //# in the LISTEN state.  An acceptable reset segment should be
    //# formed for any arriving ACK-bearing segment.
    for flags in [wire::ACK, wire::ACK | wire::SYN, wire::ACK | wire::FIN] {
        assert_eq!(
            input_header(&mut b, ip, wire::Header { flags, ..header }),
            InputDisposition::Processed
        );
        let replies = packets(&mut b, 0);
        assert_eq!(replies.len(), 1);
        let reset = wire::parse(replies[0].0, &replies[0].1).unwrap();
        assert_eq!(reset.header.flags, wire::RST);
        assert_eq!(reset.header.sequence, header.acknowledgment);
        assert_eq!(b.buffer_bytes(), 0);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.2
    //= type=test
    //# Drop the segment and return.
    for flags in [0, wire::FIN, wire::PSH | wire::URG] {
        assert_eq!(
            input_header(&mut b, ip, wire::Header { flags, ..header }),
            InputDisposition::Dropped
        );
        assert!(packets(&mut b, 0).is_empty());
        assert_eq!(b.buffer_bytes(), 0);
    }
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(
        input_header(
            &mut b,
            ip,
            wire::Header {
                flags: wire::SYN,
                ..header
            }
        ),
        InputDisposition::Processed
    );
    let replies = packets(&mut b, 0);
    assert_eq!(replies.len(), 1);
    assert_eq!(
        wire::parse(replies[0].0, &replies[0].1)
            .unwrap()
            .header
            .flags,
        wire::SYN | wire::ACK
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
//= type=test
//# A passive OPEN call with a specified "local IP address" parameter
//# will await an incoming connection request to that address.  If the
//# parameter is unspecified, a passive OPEN will await an incoming
//# connection request to any local IP address and then bind the local IP
//# address of the connection to the particular address that is used.
fn passive_bind_matches_concrete_or_any_local_address() {
    let (local, remote) = addresses();
    for bind in [remote, "0.0.0.0:8080".parse().unwrap()] {
        for destination in [remote, "192.0.2.3:8080".parse().unwrap()] {
            let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
            let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
            let listener = b.listen(bind, 4).unwrap();
            let client = a.connect(0, local, destination).unwrap();
            pump(&mut a, &mut b, 0);
            if bind.ip().is_unspecified() || bind == destination {
                let server = b.accept(listener).unwrap();
                assert_eq!(b.state(server).unwrap(), State::Established);
                assert_eq!(b.tuple(server).unwrap().local, destination);
                assert_eq!(a.state(client).unwrap(), State::Established);
            } else {
                assert_eq!(
                    b.accept(listener),
                    Err(EndpointError::Connection(Error::WouldBlock))
                );
                assert_eq!(b.buffer_bytes(), 0);
                assert_eq!(a.close_reason(client).unwrap(), Some(CloseReason::Reset));
            }
        }
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
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.3
//= type=test
//# If the receiver was
//# in SYN-RECEIVED state and had previously been in the LISTEN state,
//# then the receiver returns to the LISTEN state; otherwise, the
//# receiver aborts the connection and goes to the CLOSED state.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//= reason=RST in passive child silently releases it while listener survives; active simultaneous opener terminates and reports Reset (refusal equivalent).
//# If this connection was initiated with a passive OPEN (i.e., came from the LISTEN state),
//# then return this connection to LISTEN state and return. The user need not be informed.
//# If this connection was initiated with an active OPEN (i.e., came from SYN-SENT state),
//# then the connection was refused; signal the user "connection refused". In either case,
//# the retransmission queue should be flushed. And in the active OPEN case, enter the
//# CLOSED state and delete the TCB, and return.
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
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.1
//= type=test
//= reason=Duplicate tuple admission fails without replacing the existing record; independent listener remains legal.
//# Return "error: connection already exists".
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
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
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
    assert!(b.buffer_bytes() > 0);
    let expiry = b.next_deadline().unwrap();
    b.on_timeout(expiry, 1).unwrap();
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(b.accept(listener), Err(EndpointError::InvalidHandle));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.1
//= type=test
//= reason=The synthetic policy is bound to a /24 ingress context; directed-broadcast knowledge is supplied explicitly, not inferred.
//# A TCP implementation MUST reject as an error a local OPEN call for an
//# invalid remote IP address (e.g., a broadcast or multicast address)
//# (MUST-46).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
//= type=test
//= reason=Checksummed SYNs exercise source and destination rejection under the required /24 context policy, with a unicast positive control.
//# |  An incoming SYN with an invalid source address MUST be ignored
//# |  either by TCP or by the IP layer [(MUST-63)] (see
//# |  Section 3.2.1.3).
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.3
//= type=test
//= reason=Checksummed directed-broadcast SYNs are silently dropped before allocation or output in this explicit /24 context.
//# |
//# |  A TCP implementation MUST silently discard an incoming SYN segment
//# |  that is addressed to a broadcast or multicast address [(MUST-57)].
fn scoped_directed_broadcasts_are_rejected_before_open_or_input() {
    let (local, remote) = addresses();
    let broadcast = "192.0.2.255:8080".parse().unwrap();
    let host: core::net::SocketAddr = "192.0.2.254:8080".parse().unwrap();
    let mut endpoint = Endpoint::new(config(), [1; 32], 0, test_subnet_policy(24)).unwrap();
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
    assert!(packets(&mut endpoint, 0).is_empty());
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
fn distinct_ingress_contexts_24_broadcast_31_host_and_ipv6_behavior() {
    let local = "192.0.2.254:40000".parse().unwrap();
    let remote = "192.0.2.255:8080".parse().unwrap();
    for prefix in [24, 31, 32] {
        let mut endpoint = Endpoint::new(config(), [1; 32], 0, test_subnet_policy(prefix)).unwrap();
        if prefix == 24 {
            assert_eq!(
                endpoint.connect(0, local, remote),
                Err(EndpointError::InvalidAddress)
            );
            assert!(endpoint.listen(remote, 1).is_err());
            assert_eq!(endpoint.buffer_bytes(), 0);
            assert!(packets(&mut endpoint, 0).is_empty());
            continue;
        }
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
    let mut endpoint = Endpoint::new(config(), [1; 32], 0, test_subnet_policy(0)).unwrap();
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
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Shared fresh-data output predicate excludes setup, pure ACK, reset, FIN-only, keepalive, persist and retransmitted packets. Fresh FIFO bytes (including Limited Transmit, recovery new data, data/FIN and original TLP) advance tracked sequence space and remain subject to loss recovery. Assertions cover special ECT/Not-ECT outputs, original TLP loss RTO and corrupted CE loss congestion response; no router marking claim.
//# To ensure the reliable delivery of the congestion indication
//# of the CE codepoint, an ECT codepoint MUST NOT be set in a packet
//# unless the loss of that packet in the network would be detected by
//# the end nodes and interpreted as an indication of congestion.
// Actor/condition: TCP sender and IP adapter; all ECT outputs.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
//# We believe that this aspect is still
//# the subject of research, so this document specifies that at this
//# time, "pure" ACK packets MUST NOT indicate ECN-Capability.
// Actor/condition: TCP sender; pure ACK output.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5
//= type=test
//= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
//# Protocols and senders that only require a single ECT codepoint SHOULD
//# use ECT(0).
// Actor/condition: TCP sender; single ECT codepoint policy.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
//# * If a host has received an ECN-setup SYN packet, then it MAY send
//# an ECN-setup SYN-ACK packet.
// Actor/condition: TCP setup responder; received ECN-setup SYN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
//# Otherwise, it MUST NOT send an
//# ECN-setup SYN-ACK packet.
// Actor/condition: TCP setup responder; no received ECN-setup SYN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Shared fresh-data-only CWR predicate and transactional commit preserve signaling through failed outputs, pure ACK, persist, keepalive, FIN-only and retransmissions; tests assert first-fresh CWR and clearing after ECN, RTO, Reno/NewReno, SACK, RACK/PRR, TLP repaired loss and idle reduction.
//# * If a host ever sets the ECT codepoint on a data packet, then
//# that host MUST correctly set/clear the CWR TCP bit on all
//# subsequent packets in the connection.
// Actor/condition: TCP sender; ever transmitted ECT within this connection.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
//# * A host MUST NOT set ECT on SYN or SYN-ACK packets.
// Actor/condition: TCP sender; SYN/SYN-ACK output.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
//# When only one ECT codepoint
//# is needed by a sender for all packets sent on a TCP connection,
//# ECT(0) SHOULD be used.
// Actor/condition: TCP sender; one ECT codepoint for fresh data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First committed fresh-data CWR; lost CWR data retransmits without CWR; next fresh data after subsequent reduction carries CWR. Failed encoding cannot consume pending signaling.
//# Thus, the
//# CWR bit in the TCP header SHOULD NOT be set on retransmitted packets.
// Actor/condition: TCP sender; retransmitted data output.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First committed fresh-data CWR; lost CWR data retransmits without CWR; next fresh data after subsequent reduction carries CWR. Failed encoding cannot consume pending signaling.
//# When the TCP data sender is ready to set the CWR bit after reducing
//# the congestion window, it SHOULD set the CWR bit only on the first
//# new data packet that it transmits.
// Actor/condition: TCP sender; first fresh data after reduction.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.4
//= type=test
//= reason=TCP output policy evidence: fresh ECT(0), setup and pure ACK Not-ECT are asserted at endpoint metadata boundary; external adapters must preserve that metadata. No router/AQM behavior is claimed.
//# For the current generation of TCP congestion control algorithms, pure
//# acknowledgement packets (e.g., packets that do not contain any
//# accompanying data) MUST be sent with the not-ECT codepoint.
// Actor/condition: TCP sender; pure ACK output.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
//= type=test
//= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
//# This document specifies ECN-capable TCP implementations MUST NOT set
//# either ECT codepoint (ECT(0) or ECT(1)) in the IP header for
//# retransmitted data packets, and that the TCP data receiver SHOULD
//# ignore the ECN field on arriving data packets that are outside of the
//# receiver's current window.
// Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.5
//= type=test
//= reason=Sender retransmission Not-ECT asserted at endpoint; receiver invalid/out-of-window CE rejection asserted at sequence/ACK boundaries. TCP roles only, no network marking behavior.
//# To prevent such a denial-of-service attack, we
//# specify that a legitimate TCP data sender MUST NOT set an ECT
//# codepoint on retransmitted data packets, and that the TCP data
//# receiver SHOULD ignore the CE codepoint on out-of-window packets.
// Actor/condition: TCP sender and receiver; retransmitted data output and out-of-window received data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1
//= type=test
//= reason=TCP flag layout: existing endpoint parses emitted SYN/SYN-ACK ECE/CWR; wire constants and encoder use the assigned low-byte positions. Erratum 2307 corrects only the RFC793 figure reference.
//# Bit 9 in the Reserved field of the TCP header is designated as the ECN-Echo flag.
// Actor/condition: TCP endpoint; selected mitigation.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1
//= type=test
//= reason=TCP flag layout: existing endpoint asserts emitted CWR in setup SYN and fresh data, absent from SYN-ACK/retransmissions.
//# The CWR flag is assigned to Bit 8 in the Reserved field of the TCP header.
// Actor/condition: TCP endpoint; selected mitigation.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=First-fresh CWR tests cover RTO, Reno/NewReno fast retransmit, SACK and RACK/PRR reductions; TLP repaired-loss trace asserts CWR only after actual reduction. ECN and idle tests plus shared successful fresh-data commit cover other causes and failed encoding.
//# When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
// Actor/condition: TCP endpoint; any reduction cause including timeout, fast retransmit and ECN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Receive CE latch survives to the next ACK; two-packet aggregate tests mark either first or second segment, assert cumulative coverage of both and ECE, and contrast ECN-off. Immediate ACK scheduling on CE is retained.
//# When TCP receives a CE data packet at the destination end-system, the TCP data receiver sets the ECN-Echo flag in the TCP header of the subsequent ACK packet. If there is any ACK withholding implemented, as in current "delayed-ACK" TCP implementations where the TCP receiver can send an ACK for two arriving data packets, then the ECN-Echo flag in the ACK packet will be set to '1' if the CE codepoint is set in any of the data packets being acknowledged. That is, if any of the received data packets are CE packets, then the returning ACK has the ECN-Echo flag set.
// Actor/condition: TCP endpoint; CE data including delayed-ACK aggregation.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.3
//= type=test
//= reason=Dropped feedback/repeated echo, unmarked CWR clearing, subsequent CE and CE-marked CWR assertions establish latch behavior. Erratum 3639 clarifies CWR-before-CE; reordered older CWR is guarded by CE epoch sequence.
//# After a TCP receiver sends an ACK packet with the ECN-Echo bit set, that TCP receiver continues to set the ECN-Echo flag in all the ACK packets it sends (whether they acknowledge CE data packets or non-CE data packets) until it receives a CWR packet (a packet with the CWR flag set). After the receipt of the CWR packet, acknowledgments for subsequent non-CE data packets do not have the ECN-Echo flag set.
// Actor/condition: TCP endpoint; echo persistence until CWR and later CE.
//= https://www.rfc-editor.org/rfc/rfc3168#section-21
//= type=test
//= reason=Output defaults to Not-ECT unless eligible fresh data with bilateral ECN; setup, control ACK, retransmission and opted-out data metadata are asserted.
//# the not-ECT codepoint should be the default.
// Actor/condition: TCP endpoint; default IP/TCP output ECN policy.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Endpoint corrupts the checksum of actual ECT data and submits it with CE; receiver drops without feedback or bytes. Sender timeout reduces cwnd and retransmits that same sequence/payload Not-ECT without CWR.
//# Similarly, if a CE packet is dropped later in the network due to corruption (bit errors), the end nodes should still invoke congestion control, just as TCP would today in response to a dropped data packet.
// Actor/condition: TCP endpoint; loss of corrupted CE data.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.2
//= type=test
//= reason=Bilateral setup gates fresh data ECT(0), with endpoint metadata assertions in both directions; no router marking claim.
//# For a TCP connection using ECN, new data packets are transmitted with an ECT codepoint set in the IP header.
// Actor/condition: TCP endpoint; negotiated fresh data.
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
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1.1
//= type=test
//= reason=Optional timeout fallback selected; asserts plain setup after timeout and ECT suppression, retaining earlier receive commitment. No RST-triggered retry claim.
//# A host that receives no reply to an ECN-setup SYN within the normal
//# SYN retransmission timeout interval MAY resend the SYN and any
//# subsequent SYN retransmissions with CWR and ECE cleared.
// Actor/condition: TCP setup initiator/responder; no setup reply before SYN retransmission timeout.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
//# * If a host has received an ECN-setup SYN packet, then it MAY send
//# an ECN-setup SYN-ACK packet.
// Actor/condition: TCP setup responder; received ECN-setup SYN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Responder ECN setup only after peer setup: endpoint asserts setup SYN yields ECE-only SYN-ACK; opt-out/plain SYN yields plain SYN-ACK. No ECT on handshake output.
//# Otherwise, it MUST NOT send an
//# ECN-setup SYN-ACK packet.
// Actor/condition: TCP setup responder; no received ECN-setup SYN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host MUST NOT set ECT on data packets unless it has sent at
//# least one ECN-setup SYN or ECN-setup SYN-ACK packet, and has
//# received at least one ECN-setup SYN or ECN-setup SYN-ACK packet,
//# and has sent no non-ECN-setup SYN or non-ECN-setup SYN-ACK
//# packet.
// Actor/condition: TCP sender; ECT eligibility after bilateral setup with no local plain setup.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# If a host has received at least one non-ECN-setup SYN
//# or non-ECN-setup SYN-ACK packet, then it SHOULD NOT set ECT on
//# data packets.
// Actor/condition: TCP sender; received any plain setup packet.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# * A host that is not willing to use ECN on a TCP connection SHOULD
//# clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
//# SYN-ACK packets that it sends to indicate this unwillingness.
// Actor/condition: TCP setup sender; unwilling to use ECN.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=Setup/opt-out evidence: exact SYN/SYN-ACK flag interpretation, plain setup forbids ECT, all SYN-ACK ECE/CWR forms are asserted. Earlier receive commitment is separately retained.
//# Receivers MUST correctly handle all forms of the non-ECN-setup
//# SYN and SYN-ACK packets.
// Actor/condition: TCP setup receiver; any non-ECN-setup SYN/SYN-ACK flag combination.
//= https://www.rfc-editor.org/rfc/rfc3168#section-21
//= type=test
//= reason=Output defaults to Not-ECT unless eligible fresh data with bilateral ECN; setup, control ACK, retransmission and opted-out data metadata are asserted.
//# the not-ECT codepoint should be the default.
// Actor/condition: TCP endpoint; default IP/TCP output ECN policy.
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1
//= type=test
//= reason=ECN-off CE/ECT receive tests now prove no implicit enablement or echo; negotiated exact-sequence probes explicitly honor section 6.1.6. Sender Not-ECT outputs are asserted. A receiver cannot recover an overwritten original Not-ECT from CE alone, so universal per-packet ignore applicability is not proven. Rejected errata 3636/3680 do not waive the original text; retain this unresolved interpretation/evidence obligation.
//# If the TCP connection does not wish to use ECN notification for a particular packet, the sending TCP sets the ECN codepoint to not-ECT, and the TCP receiver ignores the CE codepoint in the received packet.
// Actor/condition: TCP endpoint; packet not sent as ECN-capable.
fn classic_ecn_opt_out_and_syn_timeout_fallback() {
    for (enabled, lost_syn) in [(false, false), (true, true)] {
        let (local, remote) = addresses();
        let mut cfg = config();
        cfg.connection.ecn = enabled;
        let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.2
//= type=test
//= reason=Endpoint corrupts the checksum of actual ECT data and submits it with CE; receiver drops without feedback or bytes. Sender timeout reduces cwnd and retransmits that same sequence/payload Not-ECT without CWR.
//# Similarly, if a CE packet is dropped later in the network due to corruption (bit errors), the end nodes should still invoke congestion control, just as TCP would today in response to a dropped data packet.
fn corrupted_ce_data_loss_invokes_sender_congestion() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.write(client, &[1; 64]).unwrap();
    let data = ecn_packet(&mut a, 1);
    assert_eq!(data.0.ecn, 2);
    let mut corrupt = data.1.clone();
    corrupt[16] ^= 1;
    assert_eq!(
        b.input_with_traffic_class(1, data.0.ip, 3, &corrupt)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert_eq!(
        b.read(server, &mut [0; 64]),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert!(
        b.poll_transmit(1, &mut [0; 2048], 64)
            .unwrap()
            .packet
            .is_none()
    );
    let before = a.transport_info(client).unwrap().cwnd;
    let deadline = a.next_deadline().unwrap();
    a.on_timeout(deadline, 64).unwrap();
    assert!(a.transport_info(client).unwrap().cwnd < before);
    let retry = ecn_packet(&mut a, deadline);
    assert_eq!(retry.0.ecn, 0);
    let retry = wire::parse(retry.0.ip, &retry.1).unwrap();
    assert_eq!(
        retry.header.sequence,
        wire::parse(data.0.ip, &data.1).unwrap().header.sequence
    );
    assert_eq!(retry.payload, &[1; 64]);
    assert_eq!(retry.header.flags & wire::CWR, 0);
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
    assert_eq!(a.buffer_bytes(), connection_charge(&config()));
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
    limited.max_buffer_bytes = connection_charge(&config()) - 1;
    let mut endpoint = Endpoint::new(limited, [3; 32], 0, test_policy).unwrap();
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
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
fn ipv4_opaque_metadata_default_admission_and_failed_input_safety() {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    // With IPv4 options disabled, Record Route, Timestamp and unknown options
    // are still retained metadata; only source routes are refused.
    let options = Ipv4Options::parse(
        &[
            30, 2, 7, 7, 8, 192, 0, 2, 9, 68, 8, 9, 0, 0x80, 0, 0, 1, 158, 3, 0,
        ],
        false,
    )
    .unwrap();
    let (syn, bytes) = option_packet(&mut a, 0);
    let buffers = b.buffer_bytes();
    for metadata in [
        completed_route(&[7]),
        Ipv4Options::parse(&[137, 7, 8, 192, 0, 2, 7], true).unwrap(),
        Ipv4Options::parse(
            &[7, 3, 4, 68, 4, 5, 0, 131, 7, 8, 192, 0, 2, 7, 30, 2],
            true,
        )
        .unwrap(),
    ] {
        assert_eq!(
            b.input_with_ipv4_options(0, syn.ip, 0, metadata, &bytes)
                .unwrap(),
            InputDisposition::Dropped
        );
        assert_eq!(b.buffer_bytes(), buffers);
    }
    let v6 = IpMetadata {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    };
    assert_eq!(
        b.input_with_ipv4_options(0, v6, 0, options, &bytes)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert_eq!(b.buffer_bytes(), buffers);
    b.input_with_ipv4_options(0, syn.ip, 0, options, &bytes)
        .unwrap();
    let (synack, bytes) = option_packet(&mut b, 0);
    assert_eq!(synack.ipv4_options, OutgoingIpv4Options::default());
    a.input(0, synack.ip, &bytes).unwrap();
    let (ack, bytes) = option_packet(&mut a, 0);
    b.input_with_ipv4_options(0, ack.ip, 0, options, &bytes)
        .unwrap();
    let server = b.accept(listener).unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(options));
    let mut corrupt = bytes.clone();
    corrupt[16] ^= 1;
    let changed = Ipv4Options::parse(&[158, 2], false).unwrap();
    b.input_with_ipv4_options(0, ack.ip, 0, changed, &corrupt)
        .unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(options));
    a.write(client, b"opaque metadata").unwrap();
    let (data, bytes) = option_packet(&mut a, 0);
    b.input_with_ipv4_options(0, data.ip, 0, changed, &bytes)
        .unwrap();
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(changed));
    let mut out = [0; 32];
    let n = b.read(server, &mut out).unwrap();
    assert_eq!(&out[..n], b"opaque metadata");
    b.enable_output_reservations().unwrap();
    b.write(server, b"reply").unwrap();
    let mut output = [0; 1500];
    let (reserved, token) = b.poll_reserved_transmit(0, &mut output, 32).unwrap();
    assert_eq!(
        reserved.packet.unwrap().ipv4_options,
        OutgoingIpv4Options::default()
    );
    let allocation = b.buffer_bytes();
    assert_eq!(
        b.input_with_ipv4_options(0, data.ip, 0, options, &bytes),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(b.received_ipv4_options(server).unwrap(), Some(changed));
    assert_eq!(b.buffer_bytes(), allocation);
    b.accept_transmit(0, token.unwrap()).unwrap();
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
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    assert!(
        a.connect_with_ipv4_options(0, local, remote, options)
            .is_err()
    );
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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
        assert!(Endpoint::new(cfg, [1; 32], 0, test_policy).is_err());
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
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
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

fn time_wait_endpoint(
    cfg: EndpointConfig,
) -> (
    Endpoint,
    ListenerId,
    ConnectionId,
    IpMetadata,
    wire::Header,
    u32,
) {
    time_wait_endpoint_with(cfg, true)
}

// `b` closed first and is in TIME-WAIT, with `reuse_time_wait` as given.
fn time_wait_endpoint_with(
    mut cfg: EndpointConfig,
    reuse: bool,
) -> (
    Endpoint,
    ListenerId,
    ConnectionId,
    IpMetadata,
    wire::Header,
    u32,
) {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    cfg.reuse_time_wait = reuse;
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 1_000);
    let server = b.accept(listener).unwrap();
    b.shutdown(server).unwrap();
    pump(&mut a, &mut b, 2_000);
    a.shutdown(client).unwrap();
    let fin = packets(&mut a, 3_000);
    let peer_ts = wire::parse(fin[0].0, &fin[0].1)
        .unwrap()
        .options
        .timestamps
        .map_or(0, |ts| ts.0);
    deliver(&mut b, 3_000, fin);
    let final_ack = packets(&mut b, 3_000);
    assert_eq!(final_ack.len(), 1);
    let header = wire::parse(final_ack[0].0, &final_ack[0].1).unwrap().header;
    let incoming_ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    assert_eq!(b.state(server).unwrap(), State::TimeWait);
    (b, listener, server, incoming_ip, header, peer_ts)
}

fn tw_segment(
    ip: IpMetadata,
    old: wire::Header,
    seq: u32,
    ack: u32,
    flags: u8,
    ts: Option<(u32, u32)>,
) -> Vec<u8> {
    tw_segment_with_payload(ip, old, seq, ack, flags, ts, &[])
}

fn tw_segment_with_payload(
    ip: IpMetadata,
    old: wire::Header,
    seq: u32,
    ack: u32,
    flags: u8,
    ts: Option<(u32, u32)>,
    payload: &[u8],
) -> Vec<u8> {
    let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Some((value, echo)) = ts {
        options[4..8].copy_from_slice(&value.to_be_bytes());
        options[8..].copy_from_slice(&echo.to_be_bytes());
    }
    let mut bytes = vec![0; 32 + payload.len()];
    let len = wire::encode(
        ip,
        wire::Header {
            source_port: old.destination_port,
            destination_port: old.source_port,
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 1024,
            urgent_pointer: 0,
        },
        if ts.is_some() { &options } else { &[] },
        payload,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}

// `output` is the one ACK a TIME-WAIT whose last ACK was `old` answers a SYN
// with that may not reopen its tuple: SND.NXT, RCV.NXT, no data. A Linux
// timewait socket sends the same (TCP_TW_ACK_OOW, or the timewait ACK of a
// TCP_TW_SYN that found no listener).
fn assert_time_wait_ack(output: &[(IpMetadata, Vec<u8>)], old: wire::Header) {
    assert_eq!(output.len(), 1);
    let ack = wire::parse(output[0].0, &output[0].1).unwrap();
    assert_eq!(ack.header.flags, wire::ACK);
    assert_eq!(
        (ack.header.sequence, ack.header.acknowledgment),
        (old.sequence, old.acknowledgment)
    );
    assert!(ack.payload.is_empty());
}

// The fixture exchanges real endpoint SYN/data-control/FIN packets, not synthetic
// state changes; reopening packets below isolate the RFC freshness boundaries.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
//= type=test
//# This algorithm for reducing TIME-WAIT is a Best
//# Current Practice that SHOULD be implemented since Timestamp Options
//# are commonly used, and using them to reduce TIME-WAIT provides
//# benefits for busy Internet servers (SHLD-4).
#[test]
fn time_wait_reuse_timestamp_and_sequence_freshness() {
    for old_ts in [false, true] {
        for case in 0..8 {
            let mut cfg = config();
            cfg.connection.timestamps = old_ts;
            let (mut b, listener, old, ip, h, last_ts) = time_wait_endpoint(cfg);
            let newer_seq = h.acknowledgment.wrapping_add(100);
            let older_seq = h.acknowledgment.wrapping_sub(100);
            let (seq, ts, expected) = match case {
                0 => (older_seq, Some(last_ts.wrapping_add(1)), old_ts),
                1 => (newer_seq, Some(last_ts), true),
                2 => (older_seq, Some(last_ts), false),
                3 => (newer_seq, Some(last_ts.wrapping_sub(1)), !old_ts),
                4 => (newer_seq, None, true),
                5 => (older_seq, None, false),
                6 => (newer_seq, Some(last_ts.wrapping_add(1 << 31)), !old_ts),
                _ => (h.acknowledgment.wrapping_add(1 << 31), None, false),
            };
            let syn = tw_segment(ip, h, seq, 0, wire::SYN, ts.map(|v| (v, 0)));
            let disposition = b.input(4_000, ip, &syn).unwrap();
            assert_eq!(
                disposition,
                InputDisposition::Processed,
                "old_ts={old_ts} case={case}"
            );
            // A stale SYN is the TIME-WAIT connection's to answer, not the
            // listener's; a fresh one ends the old incarnation's TIME-WAIT.
            assert_eq!(
                b.state(old),
                Ok(if expected {
                    State::Closed
                } else {
                    State::TimeWait
                })
            );
            assert_eq!((b.listen_overflows(), b.listen_drops()), (0, 0));
            assert_eq!(b.time_wait_connections(), usize::from(!expected));
            assert_eq!(
                b.accept(listener),
                Err(EndpointError::Connection(Error::WouldBlock))
            );
            let output = packets(&mut b, 4_000);
            if !expected {
                assert_time_wait_ack(&output, h);
            } else {
                assert_eq!(output.len(), 1);
                let synack = wire::parse(output[0].0, &output[0].1).unwrap();
                assert_eq!(
                    crate::seq::Seq(synack.header.sequence).serial_cmp(crate::seq::Seq(h.sequence)),
                    Some(core::cmp::Ordering::Greater)
                );
                assert_eq!(
                    synack.header.flags & (wire::SYN | wire::ACK),
                    wire::SYN | wire::ACK
                );
            }
        }
    }
}

// A SYN that reopens a TIME-WAIT tuple ends that TIME-WAIT at once, as
// Linux deletes its timewait socket before its listener takes the SYN
// (tcp_v4_rcv, TCP_TW_SYN). When the SYN was an old duplicate and the new
// connection fails before establishing, nothing returns to TIME-WAIT: the
// tuple is free.
#[test]
fn a_reopened_connection_that_fails_leaves_no_time_wait() {
    for (released, payload) in [
        (false, b"".as_slice()),
        (true, b"".as_slice()),
        (false, b"data".as_slice()),
        (true, b"data".as_slice()),
    ] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
        let charge = b.buffer_bytes();
        if released {
            // Released, its TIME-WAIT keeps no buffers.
            b.release(old).unwrap();
            assert_eq!(b.buffer_bytes(), 0);
        }
        let baseline = b.buffer_bytes();
        let seq = h.acknowledgment.wrapping_add(100);
        let syn = tw_segment_with_payload(ip, h, seq, 0, wire::SYN, Some((ts + 1, 0)), payload);
        b.input(4_000, ip, &syn).unwrap();
        assert_eq!(b.buffer_bytes(), baseline + charge);
        assert_eq!(b.time_wait_connections(), 0);
        if released {
            assert_eq!(b.state(old), Err(EndpointError::InvalidHandle));
        } else {
            // The application still holding it sees it closed.
            assert_eq!(b.state(old), Ok(State::Closed));
        }
        let output = packets(&mut b, 4_000);
        assert_eq!(output.len(), 1);
        let new_iss = wire::parse(output[0].0, &output[0].1)
            .unwrap()
            .header
            .sequence;
        // An old SYN's originator rejects the unexpected SYNACK. RST deliberately
        // has no timestamps: RFC 7323 forbids applying PAWS to it.
        let rst = tw_segment(ip, h, seq + 1, new_iss + 1, wire::RST, None);
        b.input(5_000, ip, &rst).unwrap();
        assert_eq!(
            b.accept(listener),
            Err(EndpointError::Connection(Error::WouldBlock))
        );
        assert!(packets(&mut b, 5_000).is_empty());
        assert_eq!(b.buffer_bytes(), baseline);
        assert_eq!(b.time_wait_connections(), 0);
        let tuple = Tuple {
            local: addresses().1,
            remote: addresses().0,
        };
        assert_eq!(b.connection_id(tuple), None);
        assert!(b.connect(5_000, tuple.local, tuple.remote).is_ok());
    }
}

#[test]
fn short_time_wait_ends_at_its_configured_deadline() {
    let mut cfg = config();
    cfg.connection.time_wait_us = 0;
    assert!(matches!(
        Endpoint::new(cfg.clone(), [1; 32], 0, test_policy),
        Err(EndpointError::Connection(Error::InvalidArgument))
    ));
    let tuple = Tuple {
        local: addresses().1,
        remote: addresses().0,
    };
    for time_wait_us in [1, 1_000] {
        for released in [false, true] {
            cfg.connection.time_wait_us = time_wait_us;
            let (mut b, _, old, _, _, _) = time_wait_endpoint(cfg.clone());
            let expiry = 3_000 + time_wait_us;
            assert_eq!(b.next_deadline(), Some(expiry));
            if released {
                b.release(old).unwrap();
            }
            b.on_timeout(expiry - 1, 64).unwrap();
            // A released connection's TIME-WAIT outlives the connection.
            assert_eq!(b.connection_exists(old), !released);
            assert_eq!(b.time_wait_connections(), 1);
            assert_eq!(
                b.connect(expiry - 1, tuple.local, tuple.remote),
                Err(EndpointError::AddressInUse)
            );
            b.on_timeout(expiry, 64).unwrap();
            assert!(packets(&mut b, expiry).is_empty());
            assert_eq!(b.connection_exists(old), !released);
            assert_eq!(b.time_wait_connections(), 0);
            assert!(b.connect(expiry, tuple.local, tuple.remote).is_ok());
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//= reason=Freshness applies to passive SYN requests with or without payload; the ordinary factory independently enforces early-data authorization and resource admission.
//# * If TCP Timestamps would be enabled for the new incarnation of the
//# connection, and the timestamp contained in the incoming SYN segment is
//# greater than the last timestamp seen on the previous incarnation of the
//# connection (for that direction of the data transfer), honor the
//# connection request (creating a connection in the SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//= reason=New bilateral timestamps admit the request independently of sequence when the old incarnation did not negotiate timestamps.
//# * If TCP Timestamps would be enabled for the new incarnation of the
//# connection, honor the incoming connection request (creating a connection
//# in the SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# In the above explanation, the phrase "TCP Timestamps would be enabled
//# for the new incarnation for the connection" means that the incoming SYN
//# segment contains a TCP Timestamps option (i.e., the client has enabled
//# TCP Timestamps), and that the SYN/ACK segment that would be sent in
//# response to it would also contain a Timestamps option (i.e., the server
//# has enabled TCP Timestamps). In such a scenario, TCP Timestamps would be
//# enabled for the new incarnation of the connection.
//= https://www.rfc-editor.org/rfc/rfc6191#section-4
//= type=test
//= reason=Newer bilateral timestamps admit older ISNs for empty and data-bearing requests; equal timestamps still require a sequence strictly after the peer FIN.
//# An implementation of the mechanism proposed in this document would
//# enable recycling of the TIME-WAIT state even in the presence of ISNs
//# that are not monotonically increasing across connections, except when
//# the timestamp contained in the incoming SYN is equal to the last
//# timestamp seen on the connection in the TIME-WAIT state (for that
//# direction of the data transfer).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//= reason=Only a SYN without ACK or RST to a TIME-WAIT connection reaches reopen_time_wait, whose reuse_syn freshness uses both the incoming sequence number and its Timestamps option when present. Reuse enabled versus disabled leaves results, state, resources, deadlines and emitted bytes identical in CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING across flag, checksum, timestamp and sequence variants.
//# The following paragraphs summarize the processing of SYN segments
//# received for connections in the TIME-WAIT state. The processing of SYN
//# segments received for connections in all other states is unchanged. Both
//# the ISN (Initial Sequence Number) and the Timestamps option (if present)
//# of the incoming SYN segment are included in the heuristics performed for
//# allowing a high connection-establishment rate.
#[cfg(feature = "packet-test-controls")]
#[test]
fn rfc6191_reuse_all_timestamp_sequence_branches() {
    for old_timestamps in [false, true] {
        for server_timestamps in [false, true] {
            for client_timestamps in [false, true] {
                for timestamp_delta in [u32::MAX, 0, 1] {
                    for sequence_delta in [u32::MAX, 0, 1, 100] {
                        let mut cfg = config();
                        cfg.connection.timestamps = old_timestamps;
                        let (mut b, listener, old, ip, h, last_ts) = time_wait_endpoint(cfg);
                        b.packet_test_timestamp_default(server_timestamps);
                        let baseline = b.buffer_bytes();
                        let deadline = b.next_deadline();
                        // The final ACK acknowledges FIN+1, not the FIN itself.
                        let sequence = h.acknowledgment.wrapping_add(sequence_delta);
                        let timestamp = last_ts.wrapping_add(timestamp_delta);
                        let enabled = server_timestamps && client_timestamps;
                        let newer_sequence =
                            sequence_delta == 0 || sequence_delta == 1 || sequence_delta == 100;
                        let expected = if old_timestamps && enabled {
                            timestamp_delta == 1 || timestamp_delta == 0 && newer_sequence
                        } else {
                            enabled || newer_sequence
                        };
                        let syn = tw_segment(
                            ip,
                            h,
                            sequence,
                            0,
                            wire::SYN,
                            client_timestamps.then_some((timestamp, 0)),
                        );
                        assert_eq!(
                            b.input(4_000, ip, &syn).unwrap(),
                            InputDisposition::Processed,
                            "old={old_timestamps} server={server_timestamps} client={client_timestamps} ts_delta={timestamp_delta} seq_delta={sequence_delta}"
                        );
                        // A reopening SYN ends the old TIME-WAIT at once, as
                        // Linux deletes its timewait socket (TCP_TW_SYN); the
                        // application still holding it sees it closed.
                        assert_eq!(
                            b.state(old),
                            Ok(if expected {
                                State::Closed
                            } else {
                                State::TimeWait
                            })
                        );
                        assert_eq!(b.time_wait_connections(), usize::from(!expected));
                        assert_eq!(
                            b.accept(listener),
                            Err(EndpointError::Connection(Error::WouldBlock))
                        );
                        let current = b
                            .connection_id(Tuple {
                                local: addresses().1,
                                remote: addresses().0,
                            })
                            .unwrap();
                        let output = packets(&mut b, 4_000);
                        if expected {
                            assert_eq!(output.len(), 1);
                            assert_ne!(current, old);
                            assert_eq!(b.state(current), Ok(State::SynReceived));
                            let synack = wire::parse(output[0].0, &output[0].1).unwrap();
                            assert_eq!(
                                synack.header.flags & (wire::SYN | wire::ACK),
                                wire::SYN | wire::ACK
                            );
                            assert_eq!(synack.header.acknowledgment, sequence.wrapping_add(1));
                            assert_eq!(synack.options.timestamps.is_some(), enabled);
                            assert!(
                                crate::seq::Seq(synack.header.sequence)
                                    .after(crate::seq::Seq(h.sequence))
                            );
                        } else {
                            // The TIME-WAIT answers a SYN that may not reopen it
                            // with its ACK, as Linux's does (TCP_TW_ACK_OOW).
                            assert_time_wait_ack(&output, h);
                            assert_eq!(current, old);
                            assert_eq!(b.buffer_bytes(), baseline);
                            assert_eq!(b.next_deadline(), deadline);
                            // A later retransmission with a fresh timestamp can reuse
                            // the same old record after the refusal.
                            if old_timestamps && enabled && timestamp_delta == u32::MAX {
                                let retry = tw_segment(
                                    ip,
                                    h,
                                    sequence,
                                    0,
                                    wire::SYN,
                                    Some((last_ts.wrapping_add(1), 0)),
                                );
                                assert_eq!(
                                    b.input(5_000, ip, &retry).unwrap(),
                                    InputDisposition::Processed
                                );
                                let child = b
                                    .connection_id(Tuple {
                                        local: addresses().1,
                                        remote: addresses().0,
                                    })
                                    .unwrap();
                                assert_eq!(b.state(child), Ok(State::SynReceived));
                                assert_eq!(packets(&mut b, 5_000).len(), 1);
                                assert_eq!(b.state(old), Ok(State::Closed));
                                assert_eq!(b.time_wait_connections(), 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

// Payload and auxiliary flags follow the ordinary passive factory after freshness.
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# * If TCP Timestamps would be enabled for the new incarnation of the
//# connection, and the timestamp contained in the incoming SYN segment is
//# greater than the last timestamp seen on the previous incarnation of the
//# connection (for that direction of the data transfer), honor the
//# connection request (creating a connection in the SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# * If TCP Timestamps would be enabled for the new incarnation of the
//# connection, the timestamp contained in the incoming SYN segment is equal
//# to the last timestamp seen on the previous incarnation of the connection
//# (for that direction of the data transfer), and the Sequence Number of
//# the incoming SYN segment is greater than the last sequence number seen
//# on the previous incarnation of the connection (for that direction of the
//# data transfer), honor the connection request (creating a connection in
//# the SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# * If TCP Timestamps would not be enabled for the new incarnation of the
//# connection, but the Sequence Number of the incoming SYN segment is
//# greater than the last sequence number seen on the previous incarnation
//# of the connection (for the same direction of the data transfer), honor
//# the connection request (creating a connection in the SYN-RECEIVED
//# state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# * If TCP Timestamps would be enabled for the new incarnation of the
//# connection, honor the incoming connection request (creating a connection
//# in the SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//# * If TCP Timestamps would not be enabled for the new incarnation of the
//# connection, but the Sequence Number of the incoming SYN segment is
//# greater than the last sequence number seen on the previous incarnation
//# of the connection (for the same direction of the data transfer), honor
//# the incoming connection request (creating a connection in the
//# SYN-RECEIVED state).
//= https://www.rfc-editor.org/rfc/rfc6191#section-4
//= type=test
//# An implementation of the mechanism proposed in this document would
//# enable recycling of the TIME-WAIT state even in the presence of ISNs
//# that are not monotonically increasing across connections, except when
//# the timestamp contained in the incoming SYN is equal to the last
//# timestamp seen on the connection in the TIME-WAIT state (for that
//# direction of the data transfer).
#[cfg(feature = "packet-test-controls")]
#[test]
fn rfc6191_data_bearing_syn_uses_freshness_and_passive_authorization() {
    for old_timestamps in [false, true] {
        for server_timestamps in [false, true] {
            for client_timestamps in [false, true] {
                for timestamp_delta in [u32::MAX, 0, 1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001] {
                    for (sequence_delta, newer_sequence) in [
                        (u32::MAX, false),
                        (0, false),
                        (1, true),
                        (2, true),
                        (0x7fff_ffff, true),
                        (0x8000_0000, false),
                        (0x8000_0001, false),
                    ] {
                        for auxiliary in [
                            0,
                            wire::PSH,
                            wire::URG,
                            wire::FIN,
                            wire::ECE | wire::CWR,
                            wire::PSH | wire::URG | wire::FIN,
                        ] {
                            let mut cfg = config();
                            cfg.connection.timestamps = old_timestamps;
                            let (mut b, listener, old, ip, h, last_ts) = time_wait_endpoint(cfg);
                            b.packet_test_timestamp_default(server_timestamps);
                            let baseline = b.buffer_bytes();
                            let deadline = b.next_deadline();
                            let old_options = b.received_ipv4_options(old).unwrap();
                            let tuple = Tuple {
                                local: addresses().1,
                                remote: addresses().0,
                            };
                            let sequence = h
                                .acknowledgment
                                .wrapping_sub(1)
                                .wrapping_add(sequence_delta);
                            let timestamp = last_ts.wrapping_add(timestamp_delta);
                            let enabled = server_timestamps && client_timestamps;
                            let expected = if old_timestamps && enabled {
                                matches!(timestamp_delta, 1 | 0x7fff_ffff)
                                    || timestamp_delta == 0 && newer_sequence
                            } else {
                                enabled || newer_sequence
                            };
                            let syn = tw_segment_with_payload(
                                ip,
                                h,
                                sequence,
                                0,
                                wire::SYN | auxiliary,
                                client_timestamps.then_some((timestamp, 0)),
                                b"data",
                            );
                            assert_eq!(wire::parse(ip, &syn).unwrap().payload, b"data");
                            assert_eq!(
                                b.input(4_000, ip, &syn).unwrap(),
                                InputDisposition::Processed,
                                "old={old_timestamps} local={server_timestamps} peer={client_timestamps} ts={timestamp_delta} seq={sequence_delta} flags={auxiliary}"
                            );
                            // An accepted SYN ends the old TIME-WAIT at once
                            // (TCP_TW_SYN), leaving its metadata and data as
                            // they were.
                            assert_eq!(
                                b.state(old),
                                Ok(if expected {
                                    State::Closed
                                } else {
                                    State::TimeWait
                                })
                            );
                            assert_eq!(b.time_wait_connections(), usize::from(!expected));
                            assert_eq!(b.received_ipv4_options(old).unwrap(), old_options);
                            assert_eq!(b.readable_bytes(old), Ok(0));
                            let current = b.connection_id(tuple).unwrap();
                            let output = packets(&mut b, 4_000);
                            assert_eq!(output.len(), 1);
                            assert_eq!(
                                b.accept(listener),
                                Err(EndpointError::Connection(Error::WouldBlock))
                            );
                            if expected {
                                assert_ne!(current, old);
                                assert_eq!(b.state(current), Ok(State::SynReceived));
                                assert_eq!(b.readable_bytes(current), Ok(0));
                                let synack = wire::parse(output[0].0, &output[0].1).unwrap();
                                assert_eq!(
                                    synack.header.flags & (wire::SYN | wire::ACK),
                                    wire::SYN | wire::ACK
                                );
                                assert_eq!(synack.header.acknowledgment, sequence.wrapping_add(1));
                                assert_eq!(synack.options.timestamps.is_some(), enabled);
                                if enabled {
                                    assert_eq!(synack.options.timestamps.unwrap().1, timestamp);
                                }
                                assert!(
                                    crate::seq::Seq(synack.header.sequence)
                                        .after(crate::seq::Seq(h.sequence))
                                );
                                let ack = tw_segment(
                                    ip,
                                    h,
                                    sequence.wrapping_add(1),
                                    synack.header.sequence.wrapping_add(1),
                                    wire::ACK,
                                    enabled.then_some((
                                        timestamp,
                                        synack.options.timestamps.unwrap_or_default().0,
                                    )),
                                );
                                b.input(5_000, ip, &ack).unwrap();
                                assert_eq!(b.accept(listener), Ok(current));
                                assert_eq!(
                                    b.state(current),
                                    Ok(if auxiliary & wire::FIN != 0 {
                                        State::CloseWait
                                    } else {
                                        State::Established
                                    })
                                );
                                let mut read = [0; 4];
                                assert_eq!(b.read(current, &mut read), Ok(4));
                                assert_eq!(&read, b"data");
                                assert_eq!(b.readable_bytes(current), Ok(0));
                            } else {
                                // The TIME-WAIT ACKs the refused SYN and takes
                                // none of its data.
                                assert_time_wait_ack(&output, h);
                                assert_eq!(current, old);
                                assert_eq!(b.buffer_bytes(), baseline);
                                assert_eq!(b.next_deadline(), deadline);
                                // Rejected payload never updates the old timestamp baseline.
                                let retry = tw_segment_with_payload(
                                    ip,
                                    h,
                                    h.acknowledgment,
                                    0,
                                    wire::SYN | auxiliary,
                                    client_timestamps.then_some((last_ts.wrapping_add(1), 0)),
                                    b"data",
                                );
                                assert_eq!(
                                    b.input(5_000, ip, &retry),
                                    Ok(InputDisposition::Processed)
                                );
                                assert_ne!(b.connection_id(tuple), Some(old));
                                assert_eq!(packets(&mut b, 5_000).len(), 1);
                                assert_eq!(b.state(old), Ok(State::Closed));
                                assert_eq!(b.time_wait_connections(), 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc6191#section-2
//= type=test
//= reason=Wire-established FIN frontiers at zero and wrap admit FIN+1/FIN+2, reject FIN, and reject the exact serial half-space from FIN for payload and empty SYNs.
//# The "last sequence number seen on the previous incarnation of the
//# connection (for the same direction of the data transfer)" refers to the
//# last sequence number used by the previous incarnation of the connection
//# (for the same direction of the data transfer), and not to the last
//# value seen in the Sequence Number field of the corresponding segments.
//# That is, it refers to the sequence number corresponding to the FIN flag
//# of the previous incarnation of the connection, for that direction of
//# the data transfer.
#[test]
fn rfc6191_sequence_reuse_uses_peer_fin_serial_frontier() {
    for old_timestamps in [false, true] {
        for incoming_timestamps in [false, true] {
            for fin in [0, u32::MAX - 1, u32::MAX] {
                for payload in [b"".as_slice(), b"data".as_slice()] {
                    for (offset, accepted) in [
                        (u32::MAX, false),
                        (0, false),
                        (1, true),
                        (2, true),
                        (0x7fff_ffff, true),
                        (0x8000_0000, false),
                        (0x8000_0001, false),
                    ] {
                        let mut cfg = config();
                        cfg.connection.timestamps = old_timestamps;
                        cfg.reuse_time_wait = true;
                        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
                        let (local, remote) = addresses();
                        let ip = IpMetadata {
                            source: local.ip(),
                            destination: remote.ip(),
                        };
                        let listener = b.listen(remote, 4).unwrap();
                        let mut h = wire::Header {
                            source_port: remote.port(),
                            destination_port: local.port(),
                            sequence: 0,
                            acknowledgment: 0,
                            flags: 0,
                            window: 1024,
                            urgent_pointer: 0,
                        };
                        // Establish and close on the wire with FIN at the selected wrap frontier.
                        let syn = tw_segment(
                            ip,
                            h,
                            fin.wrapping_sub(1),
                            0,
                            wire::SYN,
                            old_timestamps.then_some((1, 0)),
                        );
                        b.input(1_000, ip, &syn).unwrap();
                        let output = packets(&mut b, 1_000);
                        let iss = wire::parse(output[0].0, &output[0].1)
                            .unwrap()
                            .header
                            .sequence;
                        let ack = tw_segment(
                            ip,
                            h,
                            fin,
                            iss.wrapping_add(1),
                            wire::ACK,
                            old_timestamps.then_some((2, 1)),
                        );
                        b.input(2_000, ip, &ack).unwrap();
                        let old = b.accept(listener).unwrap();
                        b.shutdown(old).unwrap();
                        let output = packets(&mut b, 2_000);
                        let local_fin = wire::parse(output[0].0, &output[0].1)
                            .unwrap()
                            .header
                            .sequence;
                        let close = tw_segment(
                            ip,
                            h,
                            fin,
                            local_fin.wrapping_add(1),
                            wire::ACK | wire::FIN,
                            old_timestamps.then_some((3, 2)),
                        );
                        b.input(3_000, ip, &close).unwrap();
                        let output = packets(&mut b, 3_000);
                        h = wire::parse(output[0].0, &output[0].1).unwrap().header;
                        assert_eq!(h.acknowledgment, fin.wrapping_add(1));
                        assert_eq!(b.state(old), Ok(State::TimeWait));
                        let baseline = b.buffer_bytes();
                        let deadline = b.next_deadline();
                        let syn = tw_segment_with_payload(
                            ip,
                            h,
                            fin.wrapping_add(offset),
                            0,
                            wire::SYN,
                            incoming_timestamps.then_some((3, 0)),
                            payload,
                        );
                        assert_eq!(
                            b.input(4_000, ip, &syn).unwrap(),
                            InputDisposition::Processed,
                            "fin={fin} offset={offset} old_ts={old_timestamps} incoming_ts={incoming_timestamps}"
                        );
                        assert_eq!(
                            b.state(old),
                            Ok(if accepted {
                                State::Closed
                            } else {
                                State::TimeWait
                            })
                        );
                        let output = packets(&mut b, 4_000);
                        if accepted {
                            assert_eq!(output.len(), 1);
                            let synack = wire::parse(output[0].0, &output[0].1).unwrap();
                            assert_eq!(
                                synack.header.acknowledgment,
                                fin.wrapping_add(offset).wrapping_add(1)
                            );
                            assert!(
                                crate::seq::Seq(synack.header.sequence)
                                    .after(crate::seq::Seq(h.sequence))
                            );
                            let child = b
                                .connection_id(Tuple {
                                    local: remote,
                                    remote: local,
                                })
                                .unwrap();
                            assert_ne!(child, old);
                            assert_eq!(b.state(child), Ok(State::SynReceived));
                            assert_eq!(b.readable_bytes(child), Ok(0));
                        } else {
                            assert_time_wait_ack(&output, h);
                            assert_eq!(
                                b.connection_id(Tuple {
                                    local: remote,
                                    remote: local
                                }),
                                Some(old)
                            );
                            assert_eq!(b.buffer_bytes(), baseline);
                            assert_eq!(b.next_deadline(), deadline);
                        }
                    }
                }
            }
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc6429#section-1
//= type=test
//# This guidance is not intended to preclude resource management by the
//# operating system or application, which may request that connections be
//# aborted regardless of whether or not they are in the persist condition.
//# The TCP implementation needs to, of course, comply by aborting such
//# connections.
//= https://www.rfc-editor.org/rfc/rfc6429#section-2
//= type=test
//# Clearly, a system needs to be robust to such attacks and allow
//# connections in the persist condition to be aborted in the same way as
//# any other connection.
//= https://www.rfc-editor.org/rfc/rfc6429#section-4
//= type=test
//# Though unstated in RFC 1122, but implicit for system robustness, a TCP
//# implementation needs to allow connections in the ZWP or persist
//# condition to be closed or aborted by their applications or other
//# resource management routines in the operating system.
#[test]
fn rfc6429_explicit_abort_of_responsive_zero_window_connection() {
    for close_first in [false, true] {
        let (mut a, mut b, listener, client) = endpoints();
        pump(&mut a, &mut b, 0);
        let server = b.accept(listener).unwrap();
        // Fill the real receiver; then queue data behind its advertised zero window.
        a.write(client, &[7; 1024]).unwrap();
        tick(&mut a, &mut b, 200_000);
        assert_eq!(b.readable_bytes(server), Ok(1024));
        a.write(client, b"blocked response").unwrap();
        if close_first {
            a.shutdown(client).unwrap();
        }
        // A graceful close queues FIN behind the blocked bytes; the TCP state
        // remains ESTABLISHED until FIN can actually be sent.
        let expected_state = State::Established;
        for _ in 0..3 {
            let when = a.next_deadline().unwrap();
            a.on_timeout(when, 64).unwrap();
            let probes = packets(&mut a, when);
            assert_eq!(probes.len(), 1);
            deliver(&mut b, when, probes);
            let replies = packets(&mut b, when);
            assert_eq!(replies.len(), 1);
            let reply = wire::parse(replies[0].0, &replies[0].1).unwrap();
            assert_eq!(reply.header.window, 0);
            assert_eq!(reply.header.flags & wire::ACK, wire::ACK);
            deliver(&mut a, when, replies);
            assert_eq!(a.state(client), Ok(expected_state));
            assert_eq!(a.close_reason(client), Ok(None));
        }
        let when = a.next_deadline().unwrap();
        a.abort(client).unwrap();
        assert_eq!(a.state(client), Ok(State::Closed));
        assert_eq!(a.close_reason(client), Ok(Some(CloseReason::Aborted)));
        assert!(core::iter::from_fn(|| a.next_event()).any(|event| {
            matches!(event, Event::Connection(id, events)
                if id == client && events.closed == Some(CloseReason::Aborted))
        }));
        assert_eq!(
            a.write(client, b"late"),
            Err(EndpointError::Connection(Error::InvalidState))
        );
        let reset = packets(&mut a, when);
        assert_eq!(reset.len(), 1);
        let segment = wire::parse(reset[0].0, &reset[0].1).unwrap();
        assert_eq!(segment.header.flags & wire::RST, wire::RST);
        assert!(segment.payload.is_empty());
        deliver(&mut b, when, reset);
        assert_eq!(b.state(server), Ok(State::Closed));
        assert_eq!(b.close_reason(server), Ok(Some(CloseReason::Reset)));
        assert!(packets(&mut a, when).is_empty());
    }
}

#[test]
fn time_wait_old_expiry_and_slot_generation_do_not_remove_or_restore_replacement() {
    for (establish, payload) in [
        (false, b"".as_slice()),
        (true, b"".as_slice()),
        (false, b"data".as_slice()),
        (true, b"data".as_slice()),
    ] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        let expiry = 3_000 + cfg.connection.time_wait_us;
        let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
        let baseline = b.buffer_bytes();
        b.release(old).unwrap();
        let seq = h.acknowledgment.wrapping_add(100);
        let syn = tw_segment_with_payload(ip, h, seq, 0, wire::SYN, Some((ts + 1, 0)), payload);
        b.input(expiry - 1_000, ip, &syn).unwrap();
        let output = packets(&mut b, expiry - 1_000);
        let new_iss = wire::parse(output[0].0, &output[0].1)
            .unwrap()
            .header
            .sequence;
        b.on_timeout(expiry, 64).unwrap();
        packets(&mut b, expiry);
        assert_eq!(b.buffer_bytes(), baseline);
        assert_eq!(b.state(old), Err(EndpointError::InvalidHandle));
        // Reuse the expired slot for another tuple before candidate resolution.
        let spare = b
            .connect(expiry, "192.0.2.2:8081".parse().unwrap(), addresses().0)
            .unwrap();
        let resolution = tw_segment(
            ip,
            h,
            seq + 1,
            new_iss.wrapping_add(1),
            if establish { wire::ACK } else { wire::RST },
            Some((ts + 2, 240002)),
        );
        b.input(expiry + 1, ip, &resolution).unwrap();
        packets(&mut b, expiry + 1);
        assert_eq!(b.state(spare), Ok(State::SynSent));
        if establish {
            let child = b.accept(listener).unwrap();
            assert_eq!(b.state(child), Ok(State::Established));
            assert_ne!(child, old);
            assert_eq!(
                b.connect(expiry + 1, addresses().1, addresses().0),
                Err(EndpointError::AddressInUse)
            );
        } else {
            assert_eq!(
                b.accept(listener),
                Err(EndpointError::Connection(Error::WouldBlock))
            );
            assert!(b.connect(expiry + 1, addresses().1, addresses().0).is_ok());
        }
    }
}

#[test]
fn time_wait_reuse_capacity_and_listener_pressure_leave_old_record_unchanged() {
    for (pressure, payload) in [
        (0, b"".as_slice()),
        (1, b"".as_slice()),
        (2, b"".as_slice()),
        (3, b"".as_slice()),
        (0, b"data".as_slice()),
        (1, b"data".as_slice()),
        (2, b"data".as_slice()),
        (3, b"data".as_slice()),
    ] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        if pressure == 0 {
            cfg.max_connections = 4;
        }
        if pressure == 1 {
            cfg.max_buffer_bytes = connection_charge(&cfg);
        }
        let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
        if pressure == 0 {
            for port in 8081..8084 {
                b.connect(
                    3_000,
                    core::net::SocketAddr::new(ip.destination, port),
                    addresses().0,
                )
                .unwrap();
            }
        }
        if pressure == 2 {
            b.close_listener(listener).unwrap();
        }
        if pressure == 3 {
            for port in 40001..40005 {
                let mut header = h;
                header.destination_port = port;
                let syn = tw_segment(ip, header, 99, 0, wire::SYN, Some((4, 0)));
                b.input(3_000, ip, &syn).unwrap();
            }
        }
        packets(&mut b, 3_000);
        let bytes = b.buffer_bytes();
        let syn = tw_segment_with_payload(
            ip,
            h,
            h.acknowledgment + 100,
            0,
            wire::SYN,
            Some((ts + 1, 0)),
            payload,
        );
        // A fresh SYN the listener has no room for is its drop. One that
        // finds no listener is the TIME-WAIT's to answer, as Linux's
        // TCP_TW_SYN falls through to the timewait ACK.
        assert_eq!(
            b.input(4_000, ip, &syn).unwrap(),
            if pressure == 2 {
                InputDisposition::Processed
            } else {
                InputDisposition::Dropped
            }
        );
        assert_eq!(b.buffer_bytes(), bytes);
        assert_eq!(b.state(old), Ok(State::TimeWait));
        let output = packets(&mut b, 4_000);
        if pressure == 2 {
            assert_time_wait_ack(&output, h);
        } else {
            assert!(output.is_empty());
        }
        // At a full backlog the drop is also an overflow; a closed listener
        // took none.
        let counted = match pressure {
            0 | 1 => (0, 1),
            2 => (0, 0),
            _ => (1, 1),
        };
        assert_eq!((b.listen_overflows(), b.listen_drops()), counted);
        assert_eq!(b.time_wait_connections(), 1);
    }
}

// With reuse_time_wait, a SYN that may not reopen its tuple, stale or with
// no listener to take it, is the TIME-WAIT's to answer, as it answers any
// SYN without reuse: a challenge ACK within the challenge-ACK budget,
// carrying the connection's mark (Linux's tw_mark), its timer and the listen
// counters unchanged. A Linux timewait socket ACKs both
// (tcp_timewait_state_process returns TCP_TW_ACK_OOW for the first, and
// tcp_v4_rcv's TCP_TW_SYN falls through to the timewait ACK for the
// second). A record and a held connection answer alike.
#[test]
fn a_time_wait_answers_a_syn_that_may_not_reopen_it_as_without_reuse() {
    for released in [false, true] {
        for no_listener in [false, true] {
            let mut answers = Vec::new();
            for reuse in [false, true] {
                let mut cfg = config();
                cfg.connection.timestamps = true;
                cfg.connection.challenge_ack_limit = 2;
                let (mut b, listener, old, ip, h, ts) = time_wait_endpoint_with(cfg, reuse);
                b.set_mark(old, 0x2a).unwrap();
                if released {
                    b.release(old).unwrap();
                }
                if no_listener {
                    b.close_listener(listener).unwrap();
                }
                packets(&mut b, 3_000);
                let deadline = b.next_deadline();
                // Without a listener even a fresh SYN cannot reopen the tuple.
                let value = if no_listener {
                    ts.wrapping_add(1)
                } else {
                    ts.wrapping_sub(1)
                };
                let syn = tw_segment(
                    ip,
                    h,
                    h.acknowledgment.wrapping_add(100),
                    0,
                    wire::SYN,
                    Some((value, 0)),
                );
                let mut output = Vec::new();
                for now in [4_000, 4_001, 4_002] {
                    assert_eq!(b.input(now, ip, &syn), Ok(InputDisposition::Processed));
                    let mut answer = Vec::new();
                    let mut bytes = [0; 2048];
                    while let Some(packet) = b.poll_transmit(now, &mut bytes, 16).unwrap().packet {
                        assert_eq!(packet.mark, 0x2a);
                        answer.push((packet.ip, bytes[..packet.len].to_vec()));
                    }
                    output.push(answer);
                }
                let case =
                    alloc::format!("released={released} no_listener={no_listener} reuse={reuse}");
                assert_time_wait_ack(&output[0], h);
                assert_time_wait_ack(&output[1], h);
                assert!(output[2].is_empty(), "{case}");
                assert_eq!(b.time_wait_connections(), 1, "{case}");
                assert_eq!(b.connection_exists(old), !released, "{case}");
                assert_eq!((b.listen_overflows(), b.listen_drops()), (0, 0), "{case}");
                assert_eq!(b.next_deadline(), deadline, "{case}");
                answers.push(output);
            }
            assert_eq!(answers[0], answers[1]);
        }
    }
}

// Linux counts a SYN its full accept queue refuses in ListenOverflows and
// ListenDrops, and one refused for memory in ListenDrops alone.
#[test]
fn listen_overflows_and_drops_count_the_syns_a_listener_refuses() {
    // A full backlog, no connection slot, no buffer budget.
    for case in 0..3 {
        let mut cfg = config();
        if case == 1 {
            cfg.max_connections = 2;
        }
        if case == 2 {
            cfg.max_buffer_bytes = connection_charge(&cfg);
        }
        let (local, remote) = addresses();
        let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        let listener = b.listen(remote, [1, 2, 4][case]).unwrap();
        if case == 1 {
            // An accepted connection holds one of the two slots, outside
            // the backlog.
            let earlier = core::net::SocketAddr::new(local.ip(), 40002);
            a.connect(0, earlier, remote).unwrap();
            pump(&mut a, &mut b, 0);
            b.accept(listener).unwrap();
        }
        let first = a.connect(0, local, remote).unwrap();
        let other = core::net::SocketAddr::new(local.ip(), 40001);
        let second = a.connect(0, other, remote).unwrap();
        let mut syns = packets(&mut a, 0);
        assert_eq!(syns.len(), 2);
        let (ip, refused) = syns.pop().unwrap();
        deliver(&mut b, 0, syns);
        assert_eq!((b.listen_overflows(), b.listen_drops()), (0, 0));
        assert_eq!(b.input(0, ip, &refused), Ok(InputDisposition::Dropped));
        let overflows = u64::from(case == 0);
        assert_eq!((b.listen_overflows(), b.listen_drops()), (overflows, 1));
        pump(&mut a, &mut b, 0);
        b.accept(listener).unwrap();
        assert_eq!(a.state(first), Ok(State::Established));
        // The retransmitted SYN finds the accepted connection gone from the
        // backlog, but still holding its slot and budget.
        tick(&mut a, &mut b, 1_000_000);
        if case == 0 {
            assert_eq!(a.state(second), Ok(State::Established));
            assert_eq!((b.listen_overflows(), b.listen_drops()), (1, 1));
        } else {
            assert_eq!(a.state(second), Ok(State::SynSent));
            assert_eq!((b.listen_overflows(), b.listen_drops()), (0, 2));
        }
    }
}

#[test]
fn time_wait_connections_follow_entry_release_expiry_and_abort() {
    let time_wait = |a: &mut Endpoint, b: &mut Endpoint, client| {
        let listener = b.listen(addresses().1, 4).unwrap();
        pump(a, b, 0);
        let server = b.accept(listener).unwrap();
        a.shutdown(client).unwrap();
        pump(a, b, 1_000);
        assert_eq!(a.state(client), Ok(State::FinWait2));
        assert_eq!(a.time_wait_connections(), 0);
        b.shutdown(server).unwrap();
        pump(a, b, 2_000);
        assert_eq!(a.state(client), Ok(State::TimeWait));
        // Only the side that closed first waits.
        assert_eq!(b.state(server), Ok(State::Closed));
        assert_eq!(
            (a.time_wait_connections(), b.time_wait_connections()),
            (1, 0)
        );
    };
    let (local, remote) = addresses();
    let expiry = 2_000 + config().connection.time_wait_us;
    for released in [false, true] {
        let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
        let client = a.connect(0, local, remote).unwrap();
        time_wait(&mut a, &mut b, client);
        if released {
            a.release(client).unwrap();
        }
        a.on_timeout(expiry - 1, 64).unwrap();
        assert_eq!(a.time_wait_connections(), 1);
        a.on_timeout(expiry, 64).unwrap();
        assert!(packets(&mut a, expiry).is_empty());
        assert_eq!(a.time_wait_connections(), 0);
        assert_eq!(a.connection_exists(client), !released);
    }
    // An abort ends TIME-WAIT at once.
    let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    time_wait(&mut a, &mut b, client);
    a.abort(client).unwrap();
    assert_eq!(a.state(client), Ok(State::Closed));
    assert_eq!(a.time_wait_connections(), 0);
    a.release(client).unwrap();
    assert!(packets(&mut a, 2_000).is_empty());
    assert!(!a.connection_exists(client));
    assert_eq!(a.time_wait_connections(), 0);
}

// The incarnation a reopening SYN replaces leaves TIME-WAIT, and the gauge,
// at once, as Linux deletes its timewait socket; neither the new
// connection's fate nor the old deadline brings it back.
#[test]
fn time_wait_connections_drop_when_a_syn_reopens_the_tuple() {
    for (released, establish) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        let expiry = 3_000 + cfg.connection.time_wait_us;
        let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
        if released {
            b.release(old).unwrap();
        }
        assert_eq!(b.time_wait_connections(), 1);
        let seq = h.acknowledgment.wrapping_add(100);
        let syn = tw_segment(ip, h, seq, 0, wire::SYN, Some((ts + 1, 0)));
        assert_eq!(b.input(4_000, ip, &syn), Ok(InputDisposition::Processed));
        assert_eq!(b.time_wait_connections(), 0);
        let output = packets(&mut b, 4_000);
        let synack = wire::parse(output[0].0, &output[0].1).unwrap();
        let echo = synack.options.timestamps.unwrap().0;
        let resolution = if establish {
            tw_segment(
                ip,
                h,
                seq + 1,
                synack.header.sequence.wrapping_add(1),
                wire::ACK,
                Some((ts + 2, echo)),
            )
        } else {
            // The old SYN's originator rejects the unexpected SYN-ACK.
            tw_segment(
                ip,
                h,
                seq + 1,
                synack.header.sequence.wrapping_add(1),
                wire::RST,
                None,
            )
        };
        b.input(5_000, ip, &resolution).unwrap();
        packets(&mut b, 5_000);
        if establish {
            let new = b.accept(listener).unwrap();
            assert_eq!(b.state(new), Ok(State::Established));
        } else {
            assert_eq!(
                b.accept(listener),
                Err(EndpointError::Connection(Error::WouldBlock))
            );
        }
        assert_eq!(b.time_wait_connections(), 0);
        b.on_timeout(expiry, 64).unwrap();
        packets(&mut b, expiry);
        assert_eq!(b.time_wait_connections(), 0);
        assert_eq!(b.connection_exists(old), !released);
        if !released {
            assert_eq!(b.state(old), Ok(State::Closed));
        }
        assert_eq!((b.listen_overflows(), b.listen_drops()), (0, 0));
    }
}

#[test]
fn timestamps_two_endpoints_reopen_and_transfer_after_time_wait() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.reuse_time_wait = true;
    let expiry = 3_000 + cfg.connection.time_wait_us;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let first = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 1_000);
    let old = b.accept(listener).unwrap();
    b.write(old, b"old stream").unwrap();
    b.shutdown(old).unwrap();
    pump(&mut a, &mut b, 2_000);
    a.shutdown(first).unwrap();
    pump(&mut a, &mut b, 3_000);
    assert_eq!(b.state(old), Ok(State::TimeWait));
    a.release(first).unwrap();
    b.release(old).unwrap();
    b.set_listener_application_timeout(listener, Some(1_234_000))
        .unwrap();
    let second = a.connect(10_000, local, remote).unwrap();
    pump(&mut a, &mut b, 11_000);
    b.set_listener_application_timeout(listener, Some(3_456_000))
        .unwrap();
    let new = b.accept(listener).unwrap();
    assert_eq!(b.application_timeout(new), Ok(Some(1_234_000)));
    assert_ne!(old, new);
    assert_eq!(a.state(second), Ok(State::Established));
    a.write(second, b"new stream").unwrap();
    pump(&mut a, &mut b, 12_000);
    let mut bytes = [0; 16];
    assert_eq!(b.read(new, &mut bytes), Ok(10));
    assert_eq!(&bytes[..10], b"new stream");
    b.on_timeout(expiry, 64).unwrap();
    packets(&mut b, expiry);
    assert_eq!(b.state(new), Ok(State::Established));
    assert_eq!(b.state(old), Err(EndpointError::InvalidHandle));
}

// A reopened connection whose handshake times out leaves its tuple free:
// the TIME-WAIT it replaced ended when it took the tuple.
#[test]
fn time_wait_reopened_candidate_timeout_frees_the_tuple() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.connection.user_timeout_us = 180_000_000;
    let (mut b, listener, old, ip, h, ts) = time_wait_endpoint(cfg);
    let baseline = b.buffer_bytes();
    let syn = tw_segment(
        ip,
        h,
        h.acknowledgment.wrapping_add(100),
        0,
        wire::SYN,
        Some((ts + 1, 0)),
    );
    b.input(4_000, ip, &syn).unwrap();
    packets(&mut b, 4_000);
    b.on_timeout(180_004_000, 64).unwrap();
    packets(&mut b, 180_004_000);
    assert_eq!(b.buffer_bytes(), baseline);
    assert_eq!(b.state(old), Ok(State::Closed));
    assert_eq!(b.time_wait_connections(), 0);
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert!(b.connect(180_004_000, addresses().1, addresses().0).is_ok());
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
//# While still under discussion, to enable research into this area it is
//# now RECOMMENDED that when generating an <RST>, if the segment causing
//# the <RST> to be generated contains a Timestamps option, the <RST>
//# should also contain a Timestamps option.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
//# In the <RST> segment,
//# SEG.TSecr SHOULD be set to SEG.TSval from the incoming segment and
//# SEG.TSval SHOULD be set to zero.
fn timestamps_endpoint_config_and_control_reset_budgets() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.connection.send_ip_payload_limit = 39;
    assert!(matches!(
        Endpoint::new(cfg.clone(), [1; 32], 0, test_policy),
        Err(EndpointError::Connection(Error::InvalidArgument))
    ));
    cfg.connection.send_ip_payload_limit = 40;
    let mut b = Endpoint::new(cfg, [1; 32], 0, test_policy).unwrap();
    let (local, remote) = addresses();
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let h = wire::Header {
        source_port: remote.port(),
        destination_port: local.port(),
        sequence: 0,
        acknowledgment: 0,
        flags: 0,
        window: 0,
        urgent_pointer: 0,
    };
    let syn = tw_segment(ip, h, 123, 0, wire::SYN, Some((77, 0)));
    b.input(1_000, ip, &syn).unwrap();
    assert!(b.poll_transmit(1_000, &mut [0; 31], 16).is_err());
    let reset = packets(&mut b, 1_000);
    assert_eq!(reset.len(), 1);
    let reset = wire::parse(reset[0].0, &reset[0].1).unwrap();
    assert_eq!(reset.options.timestamps, Some((0, 77)));
    assert_eq!(reset.header.flags, wire::RST | wire::ACK);
}

#[test]
fn timestamp_ipv4_option_budget_and_paws_gate_route_updates() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.ipv4_options_enabled = true;
    cfg.connection.send_ip_payload_limit = 79;
    assert!(matches!(
        Endpoint::new(cfg.clone(), [1; 32], 0, test_policy),
        Err(EndpointError::Connection(Error::InvalidArgument))
    ));
    cfg.connection.send_ip_payload_limit = 80;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    let route = completed_route(&[8, 9]);
    let (syn, bytes) = option_packet(&mut a, 1_000);
    assert_eq!(syn.len, 40);
    b.input_with_ipv4_options(1_000, syn.ip, 0, route, &bytes)
        .unwrap();
    let (synack, bytes) = option_packet(&mut b, 1_000);
    assert_eq!(synack.len, 40);
    a.input(1_000, synack.ip, &bytes).unwrap();
    let (ack, bytes) = option_packet(&mut a, 1_000);
    b.input_with_ipv4_options(1_000, ack.ip, 0, route, &bytes)
        .unwrap();
    let server = b.accept(listener).unwrap();
    let header = wire::parse(ack.ip, &bytes).unwrap().header;
    let changed = completed_route(&[10, 11]);
    let baseline = wire::parse(ack.ip, &bytes)
        .unwrap()
        .options
        .timestamps
        .unwrap()
        .0;
    for (value, accepted) in [
        (baseline.wrapping_sub(1), false),
        (baseline.wrapping_add(1), true),
    ] {
        let mut options = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 1];
        options[4..8].copy_from_slice(&value.to_be_bytes());
        let mut packet = [0; 32];
        let n = wire::encode(ack.ip, header, &options, &[], &mut packet).unwrap();
        b.input_with_ipv4_options(2_000, ack.ip, 0, changed, &packet[..n])
            .unwrap();
        assert_eq!(
            b.received_ipv4_options(server).unwrap(),
            Some(if accepted { changed } else { route })
        );
    }
    a.write(client, &[42; 64]).unwrap();
    for (ip, bytes) in packets(&mut a, 2_000) {
        assert!(bytes.len() <= 40);
        let segment = wire::parse(ip, &bytes).unwrap();
        assert!(segment.payload.len() <= 8);
        assert!(segment.options.timestamps.is_some());
    }
}

#[test]
fn time_wait_reuse_keeps_new_syn_return_route_and_timestamp_options() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.ipv4_options_enabled = true;
    let (mut b, _, old, ip, h, last_ts) = time_wait_endpoint(cfg);
    let syn = tw_segment(
        ip,
        h,
        h.acknowledgment.wrapping_add(100),
        0,
        wire::SYN,
        Some((last_ts.wrapping_add(1), 0)),
    );
    b.input_with_ipv4_options(4_000, ip, 0, completed_route(&[8, 9]), &syn)
        .unwrap();
    let (synack, bytes) = option_packet(&mut b, 4_000);
    assert_route(synack, &bytes, &[9, 8]);
    assert!(
        wire::parse(synack.ip, &bytes)
            .unwrap()
            .options
            .timestamps
            .is_some()
    );
    assert_eq!(b.state(old).unwrap(), State::Closed);
}

#[test]
fn address_policy_roles_owned_context_and_source_selection() {
    use std::{cell::RefCell, rc::Rc};
    let (local, remote) = addresses();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let observed = calls.clone();
    // Owned state, with passive-only admission and no wildcard binding.
    let locals = [remote.ip()];
    let mut endpoint = Endpoint::new(config(), [1; 32], 0, move |request| {
        observed.borrow_mut().push(request);
        match request {
            AddressValidation::Bind { local } => locals.contains(&local),
            AddressValidation::Incoming {
                source,
                destination,
            } => source == local.ip() && locals.contains(&destination),
            AddressValidation::Open { .. } => false,
            AddressValidation::Route { .. } => false,
        }
    })
    .unwrap();
    assert!(endpoint.listen("0.0.0.0:8080".parse().unwrap(), 1).is_err());
    assert!(endpoint.listen(local, 1).is_err());
    endpoint.listen(remote, 1).unwrap();
    assert_eq!(
        endpoint.connect_with_source(0, None, local, |_| Ok(remote)),
        Err(EndpointError::InvalidAddress)
    );
    assert_eq!(
        calls.borrow().last(),
        Some(&AddressValidation::Open {
            local: remote.ip(),
            remote: local.ip()
        })
    );
    assert_eq!(endpoint.buffer_bytes(), 0);
    assert!(packets(&mut endpoint, 0).is_empty());
    calls.borrow_mut().clear();
    let header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: 1,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 1024,
        urgent_pointer: 0,
    };
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    // Incoming admission succeeds even though this endpoint forbids active OPEN.
    assert_eq!(
        input_header(&mut endpoint, ip, header),
        InputDisposition::Processed
    );
    assert!(endpoint.buffer_bytes() > 0);
    assert_eq!(packets(&mut endpoint, 0).len(), 1);
    assert_eq!(
        *calls.borrow(),
        vec![AddressValidation::Incoming {
            source: ip.source,
            destination: ip.destination
        }]
    );
    calls.borrow_mut().clear();
    // Existing tuples still pass the incoming boundary before lookup.
    assert_eq!(
        input_header(&mut endpoint, ip, header),
        InputDisposition::Processed
    );
    assert_eq!(
        *calls.borrow(),
        vec![AddressValidation::Incoming {
            source: ip.source,
            destination: ip.destination
        }]
    );
}

#[test]
fn route_policy_receives_logical_pair_for_hops_and_prespecified_timestamps() {
    use core::net::Ipv4Addr;
    use std::{cell::RefCell, rc::Rc};
    let (local, remote) = addresses();
    let hop = Ipv4Addr::new(192, 0, 2, 7);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let observed = calls.clone();
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    let mut endpoint = Endpoint::new(cfg, [1; 32], 0, move |request| {
        observed.borrow_mut().push(request);
        test_policy(request) && !matches!(request, AddressValidation::Route { .. })
    })
    .unwrap();
    for options in [
        OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[hop], false).unwrap()),
            ..Default::default()
        },
        OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[], false).unwrap()),
            timestamp: Some(TimestampRequest::Prespecified {
                addresses: [hop; 4],
                len: 1,
            }),
            ..Default::default()
        },
    ] {
        calls.borrow_mut().clear();
        assert_eq!(
            endpoint.connect_with_ipv4_options(0, local, remote, options),
            Err(EndpointError::InvalidAddress)
        );
        assert_eq!(
            *calls.borrow(),
            vec![AddressValidation::Route {
                source: local.ip(),
                destination: remote.ip(),
                hop: hop.into()
            }]
        );
        assert_eq!(endpoint.buffer_bytes(), 0);
        assert!(packets(&mut endpoint, 0).is_empty());
    }
    let mut sender = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    sender.connect(0, local, remote).unwrap();
    let (ip, bytes) = packets(&mut sender, 0).pop().unwrap();
    calls.borrow_mut().clear();
    assert_eq!(
        endpoint
            .input_with_ipv4_options(0, ip, 0, completed_route(&[7]), &bytes)
            .unwrap(),
        InputDisposition::Dropped
    );
    assert_eq!(
        *calls.borrow(),
        vec![
            AddressValidation::Incoming {
                source: local.ip(),
                destination: remote.ip()
            },
            AddressValidation::Route {
                source: remote.ip(),
                destination: local.ip(),
                hop: hop.into()
            },
        ]
    );
    assert_eq!(endpoint.buffer_bytes(), 0);
    assert!(packets(&mut endpoint, 0).is_empty());
}

// A non-TCP reply (the Host Echo service's) authorizes a received return
// route exactly as TCP admission does: base checks, then the Route policy
// for every hop, from the local address toward the remote one. A
// structurally valid route with one denied hop is refused; strict and loose
// routes of allowed hops are authorized. TCP admission is unchanged.
#[test]
fn return_routes_are_authorized_with_tcp_route_policy() {
    use core::net::{IpAddr, Ipv4Addr};
    use std::{cell::RefCell, rc::Rc};
    let (local, remote) = addresses();
    let denied = Ipv4Addr::new(192, 0, 2, 66);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let observed = calls.clone();
    let endpoint = Endpoint::new(config(), [1; 32], 0, move |request| {
        observed.borrow_mut().push(request);
        test_policy(request)
            && !matches!(request, AddressValidation::Route { hop, .. } if hop == IpAddr::V4(denied))
    })
    .unwrap();
    let hops = [Ipv4Addr::new(192, 0, 2, 8), Ipv4Addr::new(192, 0, 2, 9)];
    for strict in [false, true] {
        let route = SourceRoute::new(&hops, strict).unwrap();
        calls.borrow_mut().clear();
        assert!(endpoint.admits_return_route(local.ip(), remote.ip(), &route));
        let expected: Vec<_> = hops
            .iter()
            .map(|&hop| AddressValidation::Route {
                source: local.ip(),
                destination: remote.ip(),
                hop: hop.into(),
            })
            .collect();
        assert_eq!(*calls.borrow(), expected);
        let route = SourceRoute::new(&[hops[0], denied, hops[1]], strict).unwrap();
        assert!(!endpoint.admits_return_route(local.ip(), remote.ip(), &route));
        // Outside the policy's network: refused whatever the hop.
        let outside = SourceRoute::new(&[Ipv4Addr::new(198, 51, 100, 1)], strict).unwrap();
        assert!(!endpoint.admits_return_route(local.ip(), remote.ip(), &outside));
    }
    // Base checks precede the policy.
    calls.borrow_mut().clear();
    let route = SourceRoute::new(&hops, false).unwrap();
    for invalid in ["0.0.0.0", "255.255.255.255", "224.0.0.1"] {
        let invalid: IpAddr = invalid.parse().unwrap();
        assert!(!endpoint.admits_return_route(invalid, remote.ip(), &route));
        assert!(!endpoint.admits_return_route(local.ip(), invalid, &route));
    }
    assert!(calls.borrow().is_empty());
    // No hop: nothing to authorize.
    let direct = SourceRoute::new(&[], false).unwrap();
    assert!(endpoint.admits_return_route(local.ip(), remote.ip(), &direct));
}

#[test]
fn base_invalid_addresses_never_reach_policy() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.ipv4_options_enabled = true;
    let mut endpoint = Endpoint::new(cfg, [1; 32], 0, |_| {
        panic!("base checks must precede policy")
    })
    .unwrap();
    for invalid in [
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "ff02::1",
    ] {
        let address = invalid.parse().unwrap();
        let socket = core::net::SocketAddr::new(address, 8080);
        assert_eq!(
            endpoint.connect(0, local, socket),
            Err(EndpointError::InvalidAddress)
        );
        assert_eq!(
            endpoint.connect(0, socket, remote),
            Err(EndpointError::InvalidAddress)
        );
        if !address.is_unspecified() {
            assert!(endpoint.listen(socket, 1).is_err());
        }
        for ip in [
            IpMetadata {
                source: address,
                destination: remote.ip(),
            },
            IpMetadata {
                source: local.ip(),
                destination: address,
            },
        ] {
            assert_eq!(
                endpoint.input(0, ip, &[]).unwrap(),
                InputDisposition::Dropped
            );
        }
    }
    let options = OutgoingIpv4Options {
        timestamp: Some(TimestampRequest::Prespecified {
            addresses: [core::net::Ipv4Addr::BROADCAST; 4],
            len: 1,
        }),
        ..Default::default()
    };
    assert_eq!(
        endpoint.connect_with_ipv4_options(0, local, remote, options),
        Err(EndpointError::InvalidAddress)
    );
    assert_eq!(endpoint.buffer_bytes(), 0);
    assert!(packets(&mut endpoint, 0).is_empty());
}

#[test]
fn readable_bytes_is_a_pure_payload_getter_and_rejects_stale_handles() {
    let (mut a, mut b, listener, client) = endpoints();
    assert_eq!(a.readable_bytes(client), Ok(0));
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.write_urgent(client, b"abcdef").unwrap();
    a.shutdown(client).unwrap();
    pump(&mut a, &mut b, 1);
    while b.next_event().is_some() {}
    let deadline = b.next_deadline();
    let output_pending = b.has_pending_output();
    assert_eq!(b.readable_bytes(server), Ok(6));
    assert_eq!(b.readable_bytes(server), Ok(6));
    assert_eq!(b.next_deadline(), deadline);
    assert_eq!(b.has_pending_output(), output_pending);
    assert!(b.next_event().is_none());
    let mut out = [0; 8];
    assert_eq!(b.read(server, &mut out[..2]), Ok(2));
    assert_eq!(b.readable_bytes(server), Ok(4));
    assert_eq!(b.read(server, &mut out), Ok(4));
    assert_eq!(b.readable_bytes(server), Ok(0));
    assert_eq!(b.read(server, &mut out), Ok(0));
    b.abort(server).unwrap();
    b.release(server).unwrap();
    assert_eq!(b.readable_bytes(server), Err(EndpointError::InvalidHandle));
}

#[test]
fn application_timeout_listener_snapshot_and_preaccept_stall() {
    let (mut a, mut b, listener, _) = endpoints();
    assert_eq!(
        b.set_listener_application_timeout(listener, Some(0)),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    b.set_listener_application_timeout(listener, Some(1_234_000))
        .unwrap();
    pump(&mut a, &mut b, 0);
    b.set_listener_application_timeout(listener, Some(3_456_000))
        .unwrap();
    let child = b.accept(listener).unwrap();
    assert_eq!(b.application_timeout(child), Ok(Some(1_234_000)));
    let (local, remote) = addresses();
    let baseline = b.buffer_bytes();
    let another = a
        .connect(
            10,
            core::net::SocketAddr::new(local.ip(), local.port() + 1),
            remote,
        )
        .unwrap();
    // Deliver SYN only: the passive child's inherited policy runs before accept.
    deliver(&mut b, 10, packets(&mut a, 10));
    packets(&mut b, 10);
    assert!(!b.on_timeout(10 + 3_456_000 - 1, 64).unwrap());
    packets(&mut b, 10 + 3_456_000 - 1);
    assert!(b.buffer_bytes() > baseline);
    assert!(!b.on_timeout(10 + 3_456_000, 64).unwrap());
    packets(&mut b, 10 + 3_456_000);
    // Unaccepted terminal children are reclaimed, not exposed as handles/events.
    assert_eq!(b.buffer_bytes(), baseline);
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(b.state(child), Ok(State::Established));
    assert_eq!(a.state(another), Ok(State::SynSent));
}

#[test]
fn application_timeout_syn_policy_is_not_r2_and_reset_preserves_r2_floor() {
    let (mut a, _, _, client) = endpoints();
    assert_eq!(a.application_timeout(client), Ok(None));
    assert_eq!(
        a.set_application_timeout(client, Some(0)),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    a.set_user_timeout(client, 1_000).unwrap();
    a.set_application_timeout(client, Some(10_000)).unwrap();
    assert_eq!(a.next_deadline(), Some(10_000));
    a.set_application_timeout(client, None).unwrap();
    packets(&mut a, 0);
    a.on_timeout(10_000, 64).unwrap();
    assert_eq!(a.state(client), Ok(State::SynSent));
    a.on_timeout(179_999_999, 64).unwrap();
    assert_eq!(a.state(client), Ok(State::SynSent));
    a.on_timeout(180_000_000, 64).unwrap();
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::TimedOut)));

    let (mut a, _, _, client) = endpoints();
    a.set_application_timeout(client, Some(10_000)).unwrap();
    packets(&mut a, 0);
    a.on_timeout(10_000, 64).unwrap();
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::TimedOut)));
    assert!(
        matches!(a.next_event(), Some(Event::Connection(id, events)) if id == client && events.closed == Some(CloseReason::TimedOut))
    );
}

#[test]
fn application_timeout_does_not_close_healthy_fin_wait2_receive_half() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.set_application_timeout(client, Some(1_000)).unwrap();
    a.shutdown(client).unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(a.state(client), Ok(State::FinWait2));
    a.on_timeout(2_000, 64).unwrap();
    assert_eq!(a.state(client), Ok(State::FinWait2));
    b.write(server, b"reply").unwrap();
    pump(&mut a, &mut b, 2_000);
    let mut bytes = [0; 8];
    assert_eq!(a.read(client, &mut bytes), Ok(5));
    assert_eq!(&bytes[..5], b"reply");
    // The original FIN-WAIT-2 R2 cleanup remains active.
    a.on_timeout(2_000 + config().connection.user_timeout_us, 64)
        .unwrap();
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::TimedOut)));
}

fn connection_charge(cfg: &EndpointConfig) -> usize {
    3 * cfg.connection.receive_capacity
        + 2 * cfg.connection.send_capacity
        + crate::sack::Scoreboard::allocation_bytes(cfg.connection.send_capacity).unwrap()
        + usize::from(cfg.connection.mss)
        + crate::rack::Rack::storage_bytes(cfg.connection.send_capacity).unwrap()
}

#[test]
fn receive_preallocation_validates_limits_and_overflow_before_allocating() {
    assert_eq!(EndpointConfig::default().preallocate_connections, 0);
    let mut cfg = config();
    cfg.preallocate_connections = cfg.max_connections + 1;
    assert!(matches!(
        Endpoint::new(cfg.clone(), [1; 32], 0, test_policy),
        Err(EndpointError::LimitReached)
    ));
    cfg.preallocate_connections = 2;
    cfg.max_buffer_bytes = 2 * connection_charge(&cfg) - 1;
    assert!(matches!(
        Endpoint::new(cfg.clone(), [1; 32], 0, test_policy),
        Err(EndpointError::LimitReached)
    ));
    cfg.max_buffer_bytes += 1;
    let endpoint = Endpoint::new(cfg, [1; 32], 0, test_policy).unwrap();
    assert_eq!(endpoint.buffer_bytes(), 2 * connection_charge(&config()));
    let mut cfg = config();
    cfg.max_connections = usize::MAX / 2;
    cfg.preallocate_connections = cfg.max_connections;
    cfg.max_buffer_bytes = usize::MAX;
    assert!(matches!(
        Endpoint::new(cfg, [1; 32], 0, test_policy),
        Err(EndpointError::LimitReached)
    ));
    let mut cfg = config();
    cfg.connection.receive_capacity = usize::MAX;
    cfg.preallocate_connections = 1;
    assert!(matches!(
        Endpoint::new(cfg, [1; 32], 0, test_policy),
        Err(EndpointError::LimitReached)
    ));
}

#[test]
fn receive_preallocation_failed_constructors_preserve_reserved_budget() {
    let (local, remote) = addresses();
    for preallocate in [0, 1] {
        let mut cfg = config();
        cfg.preallocate_connections = preallocate;
        cfg.connection.mss = 0;
        let charge = connection_charge(&cfg);
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        b.listen(remote, 1).unwrap();
        let mut peer = Endpoint::new(config(), [3; 32], 0, test_policy).unwrap();
        peer.connect(0, local, remote).unwrap();
        let syn = packets(&mut peer, 0).pop().unwrap();
        for _ in 0..3 {
            assert_eq!(
                a.connect(0, local, remote),
                Err(EndpointError::Connection(Error::InvalidArgument))
            );
            assert_eq!(
                b.input(0, syn.0, &syn.1),
                Err(EndpointError::Connection(Error::InvalidArgument))
            );
            assert_eq!(a.buffer_bytes(), preallocate * charge);
            assert_eq!(b.buffer_bytes(), preallocate * charge);
            assert!(packets(&mut a, 0).is_empty());
            assert!(packets(&mut b, 0).is_empty());
        }
    }
}

#[test]
fn receive_preallocation_active_passive_recycle_and_budget_accounting() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.preallocate_connections = 1;
    let charge = connection_charge(&cfg);
    cfg.max_buffer_bytes = 2 * charge;
    let time_wait = cfg.connection.time_wait_us;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    assert_eq!((a.buffer_bytes(), b.buffer_bytes()), (charge, charge));
    let first = a.connect(0, local, remote).unwrap();
    assert_eq!(a.buffer_bytes(), charge);
    assert_eq!(
        a.connect(0, local, remote),
        Err(EndpointError::AddressInUse)
    );
    let mut other_local = local;
    other_local.set_port(local.port() + 1);
    let second = a.connect(0, other_local, remote).unwrap();
    assert_eq!(a.buffer_bytes(), 2 * charge);
    let mut third_local = local;
    third_local.set_port(local.port() + 2);
    assert_eq!(
        a.connect(0, third_local, remote),
        Err(EndpointError::LimitReached)
    );
    pump(&mut a, &mut b, 0);
    let servers = [b.accept(listener).unwrap(), b.accept(listener).unwrap()];
    assert_eq!(b.buffer_bytes(), 2 * charge);
    // Reclaim two allocations into a one-entry pool: only one charge survives.
    for id in [first, second] {
        a.abort(id).unwrap();
        a.release(id).unwrap();
        assert!(a.connection_exists(id));
        assert!(a.poll_transmit(0, &mut [0; 1], 1).is_err());
        packets(&mut a, 0);
        assert!(a.connection_exists(id));
    }
    assert_eq!(a.buffer_bytes(), 2 * charge);
    a.on_timeout(time_wait, 2).unwrap();
    assert!(!a.connection_exists(first));
    assert!(!a.connection_exists(second));
    assert_eq!(a.buffer_bytes(), charge);
    for id in servers {
        b.abort(id).unwrap();
        b.release(id).unwrap();
        packets(&mut b, 0);
    }
    assert_eq!(b.buffer_bytes(), 2 * charge);
    b.on_timeout(time_wait, 2).unwrap();
    assert_eq!(b.buffer_bytes(), charge);
    // At the reserved budget, active and passive opens must still be admitted.
    let fresh = a.connect(time_wait, local, remote).unwrap();
    pump(&mut a, &mut b, time_wait);
    let server = b.accept(listener).unwrap();
    assert_ne!(fresh, first);
    assert_eq!((a.buffer_bytes(), b.buffer_bytes()), (charge, charge));
    a.write(fresh, b"old bytes").unwrap();
    a.shutdown(fresh).unwrap();
    pump(&mut a, &mut b, time_wait);
    assert_eq!(b.state(server), Ok(State::CloseWait));
    // Keep old unread payload and EOF in the receive buffer through abort/reclaim.
    b.abort(server).unwrap();
    b.release(server).unwrap();
    pump(&mut a, &mut b, time_wait);
    a.release(fresh).unwrap();
    packets(&mut a, time_wait);
    b.on_timeout(2 * time_wait, 1).unwrap();
    assert_eq!((a.buffer_bytes(), b.buffer_bytes()), (charge, charge));
    let replacement = a.connect(2 * time_wait + 1, local, remote).unwrap();
    pump(&mut a, &mut b, 2 * time_wait + 1);
    let server = b.accept(listener).unwrap();
    assert_eq!(b.readable_bytes(server), Ok(0));
    assert_eq!(
        b.read(server, &mut [0; 16]),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    while let Some(event) = b.next_event() {
        if let Event::Connection(id, events) = event {
            assert_eq!(id, server);
            assert!(!events.pushed && !events.half_closed && !events.readable);
        }
    }
    a.write(replacement, b"new").unwrap();
    pump(&mut a, &mut b, 2 * time_wait + 1);
    let mut out = [0xaa; 16];
    assert_eq!(b.read(server, &mut out), Ok(3));
    assert_eq!(&out[..3], b"new");
    assert_eq!(&out[3..], &[0xaa; 13]);
    assert_eq!((a.buffer_bytes(), b.buffer_bytes()), (charge, charge));
}

#[test]
fn receive_preallocation_time_wait_reopen_keeps_charges() {
    let mut cfg = config();
    cfg.preallocate_connections = 2;
    let charge = connection_charge(&cfg);
    cfg.max_buffer_bytes = 2 * charge;
    let (mut b, _, old, ip, h, _) = time_wait_endpoint(cfg);
    let tuple = Tuple {
        local: addresses().1,
        remote: addresses().0,
    };
    // Released, the connection is reclaimed into its TIME-WAIT record and
    // its receive storage returns to the pool.
    b.release(old).unwrap();
    assert!(!b.connection_exists(old));
    assert_eq!(b.buffer_bytes(), 2 * charge);
    let seq = h.acknowledgment.wrapping_add(100);
    let syn = tw_segment(ip, h, seq, 0, wire::SYN, None);
    assert_eq!(b.input(4_000, ip, &syn), Ok(InputDisposition::Processed));
    let child = b.connection_id(tuple).unwrap();
    assert_ne!(child, old);
    assert_eq!(b.time_wait_connections(), 0);
    assert_eq!(b.buffer_bytes(), 2 * charge);
    packets(&mut b, 4_000);
    let rst = tw_segment(ip, h, seq + 1, 0, wire::RST, None);
    b.input(5_000, ip, &rst).unwrap();
    packets(&mut b, 5_000);
    // Nothing returns to TIME-WAIT: the tuple is free.
    assert_eq!(b.connection_id(tuple), None);
    assert_eq!(b.time_wait_connections(), 0);
    assert!(!b.connection_exists(child));
    assert_eq!(b.buffer_bytes(), 2 * charge);
    assert!(b.connect(5_000, tuple.local, tuple.remote).is_ok());
    assert_eq!(b.buffer_bytes(), 2 * charge);
}

// Exact BASE-044 recommendation, reconciled with application-visible ABORT CLOSED.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.5.2
//= type=test
//= reason=IPv4/IPv6 terminal resets reserve bounded tuple ownership before output and for exactly the configured TIME-WAIT duration after successful generation; released and retained handles expire safely.
//# The side of a connection issuing a reset should enter the TIME-WAIT state, as
//# this generally helps to reduce the load on busy servers for reasons described
//# in [70].
#[test]
fn reset_quarantine_output_commit_exact_boundary_and_replacement_ownership() {
    for ipv6 in [false, true] {
        for released in [false, true] {
            let (local, remote) = if ipv6 {
                (
                    "[2001:db8::1]:40000".parse().unwrap(),
                    "[2001:db8::2]:8080".parse().unwrap(),
                )
            } else {
                addresses()
            };
            let mut cfg = config();
            cfg.connection.time_wait_us = 1_000_123;
            let duration = cfg.connection.time_wait_us;
            let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
            let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
            let listener = b.listen(remote, 1).unwrap();
            let id = a.connect(0, local, remote).unwrap();
            pump(&mut a, &mut b, 0);
            b.accept(listener).unwrap();
            a.listen(local, 1).unwrap(); // Stale SYN must not reach even a matching listener.
            let tuple = Tuple { local, remote };
            let charge = a.buffer_bytes();
            a.abort(id).unwrap();
            assert_eq!(a.state(id), Ok(State::Closed));
            assert_eq!(a.next_deadline(), None);
            if released {
                a.release(id).unwrap();
            }
            let incoming = IpMetadata {
                source: remote.ip(),
                destination: local.ip(),
            };
            let header = wire::Header {
                source_port: remote.port(),
                destination_port: local.port(),
                sequence: 123,
                acknowledgment: 456,
                flags: 0,
                window: 1024,
                urgent_pointer: 0,
            };
            // Neither failed generation nor stale traffic starts/extends the timer.
            for now in [1, 500] {
                assert_eq!(
                    a.poll_transmit(now, &mut [0; 1], 1),
                    Err(EndpointError::Connection(Error::OutputTooSmall))
                );
                for flags in [wire::SYN, wire::ACK, wire::RST] {
                    let mut bytes = [0; 64];
                    let len = wire::encode(
                        incoming,
                        wire::Header { flags, ..header },
                        &[],
                        b"stale",
                        &mut bytes,
                    )
                    .unwrap();
                    assert_eq!(
                        a.input(now, incoming, &bytes[..len]),
                        Ok(InputDisposition::Dropped)
                    );
                }
                assert_eq!(a.next_deadline(), None);
                assert_eq!(
                    a.connect(now, local, remote),
                    Err(EndpointError::AddressInUse)
                );
                assert_eq!(a.buffer_bytes(), charge);
            }
            assert!(
                a.poll_transmit(1_000, &mut [0; 64], 0)
                    .unwrap()
                    .packet
                    .is_none()
            );
            let (tx, bytes) = ecn_packet(&mut a, 1_000);
            assert_eq!(tx.connection, Some(id));
            assert_ne!(
                wire::parse(tx.ip, &bytes).unwrap().header.flags & wire::RST,
                0
            );
            let expiry = 1_000 + duration;
            assert_eq!(a.next_deadline(), Some(expiry));
            assert!(!a.has_pending_output());
            for flags in [wire::SYN, wire::ACK, wire::RST] {
                let mut bytes = [0; 64];
                let len = wire::encode(
                    incoming,
                    wire::Header { flags, ..header },
                    &[],
                    b"old",
                    &mut bytes,
                )
                .unwrap();
                assert_eq!(
                    a.input(expiry - 1, incoming, &bytes[..len]),
                    Ok(InputDisposition::Dropped)
                );
            }
            assert!(packets(&mut a, expiry - 1).is_empty());
            assert_eq!(a.next_deadline(), Some(expiry));
            assert!(!a.on_timeout(expiry - 1, 1).unwrap());
            assert!(a.on_timeout(expiry, 0).unwrap());
            assert_eq!(
                a.connect(expiry, local, remote),
                Err(EndpointError::AddressInUse)
            );
            assert!(!a.on_timeout(expiry, 1).unwrap());
            assert_eq!(a.connection_id(tuple), None);
            assert_eq!(a.connection_exists(id), !released);
            assert_eq!(a.buffer_bytes(), if released { 0 } else { charge });
            let replacement = a.connect(expiry, local, remote).unwrap();
            assert_ne!(id, replacement);
            if !released {
                assert_eq!(a.state(id), Ok(State::Closed));
                a.release(id).unwrap();
            }
            assert_eq!(a.state(id), Err(EndpointError::InvalidHandle));
            assert_eq!(a.connection_id(tuple), Some(replacement));
            assert!(a.connection_exists(replacement));
        }
    }
}

#[test]
fn reset_quarantine_connection_and_byte_capacity_and_timeout_budgets() {
    for slots in [1, 2] {
        for byte_slots in [0, 1, 2] {
            let mut cfg = config();
            cfg.max_connections = slots;
            let charge = connection_charge(&cfg);
            cfg.max_buffer_bytes = byte_slots * charge;
            let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
            let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
            let (local, remote) = addresses();
            let listener = b.listen(remote, 2).unwrap();
            if byte_slots == 0 {
                assert_eq!(
                    a.connect(0, local, remote),
                    Err(EndpointError::LimitReached)
                );
                continue;
            }
            let id = a.connect(0, local, remote).unwrap();
            pump(&mut a, &mut b, 0);
            b.accept(listener).unwrap();
            a.abort(id).unwrap();
            a.release(id).unwrap();
            packets(&mut a, 0);
            assert_eq!(a.buffer_bytes(), charge);
            let mut other = local;
            other.set_port(local.port() + 1);
            if slots == 2 && byte_slots == 2 {
                let second = a.connect(0, other, remote).unwrap();
                pump(&mut a, &mut b, 0);
                b.accept(listener).unwrap();
                a.abort(second).unwrap();
                a.release(second).unwrap();
                packets(&mut a, 0);
                assert_eq!(a.buffer_bytes(), 2 * charge);
                assert!(a.on_timeout(cfg.connection.time_wait_us, 0).unwrap());
                assert!(a.on_timeout(cfg.connection.time_wait_us, 1).unwrap());
                assert_eq!(a.buffer_bytes(), charge);
            } else {
                assert_eq!(
                    a.connect(0, other, remote),
                    Err(EndpointError::LimitReached)
                );
            }
            assert!(!a.on_timeout(cfg.connection.time_wait_us, 1).unwrap());
            assert_eq!(a.buffer_bytes(), 0);
            assert!(!a.connection_exists(id));
            assert!(
                a.connect(cfg.connection.time_wait_us, local, remote)
                    .is_ok()
            );
        }
    }
    let mut cfg = config();
    cfg.max_connections = 0;
    assert!(matches!(
        Endpoint::new(cfg, [1; 32], 0, test_policy),
        Err(EndpointError::Connection(Error::InvalidArgument))
    ));
}

#[test]
fn reset_quarantine_excludes_received_stateless_nonterminal_and_no_reset_abort() {
    // An inbound reset closes and frees the tuple without a reset-origin timer.
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    b.abort(server).unwrap();
    deliver(&mut a, 0, packets(&mut b, 0));
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::Reset)));
    assert_eq!(a.next_deadline(), None);
    a.release(client).unwrap();
    packets(&mut a, 0);
    let (local, remote) = addresses();
    assert!(a.connect(0, local, remote).is_ok());

    // Bad handshake ACK resets are nonterminal and must not reserve the tuple.
    let (mut a, mut b, _, id) = endpoints();
    let syn = packets(&mut a, 0);
    let h = wire::parse(syn[0].0, &syn[0].1).unwrap().header;
    let ip = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let bad_ack = tw_segment(ip, h, 123, h.sequence, wire::ACK, None);
    a.input(0, ip, &bad_ack).unwrap();
    let rst = packets(&mut a, 0);
    assert_ne!(
        wire::parse(rst[0].0, &rst[0].1).unwrap().header.flags & wire::RST,
        0
    );
    assert_eq!(a.state(id), Ok(State::SynSent));
    a.abort(id).unwrap(); // SYN-SENT owes no reset.
    a.release(id).unwrap();
    assert!(packets(&mut a, 0).is_empty());
    assert_eq!(a.next_deadline(), None);
    assert_eq!(a.buffer_bytes(), 0);
    assert!(a.connect(0, local, remote).is_ok());

    // Stateless reset output consumes no connection slot or reservation.
    let unknown = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let mut bytes = [0; 64];
    let len = wire::encode(
        unknown,
        wire::Header {
            flags: wire::ACK,
            ..h
        },
        &[],
        &[],
        &mut bytes,
    )
    .unwrap();
    b.input(0, unknown, &bytes[..len]).unwrap();
    let (tx, _) = ecn_packet(&mut b, 0);
    assert_eq!(tx.connection, None);
    assert_eq!(b.buffer_bytes(), 0);
    assert_eq!(b.next_deadline(), None);
    assert!(b.connect(0, remote, local).is_ok());

    // ABORT from ordinary TIME-WAIT emits no reset and adds no quarantine.
    let (mut b, _, old, _, _, _) = time_wait_endpoint(config());
    b.abort(old).unwrap();
    b.release(old).unwrap();
    assert!(packets(&mut b, 3_000).is_empty());
    assert_eq!(b.next_deadline(), None);
    assert!(b.connect(3_000, remote, local).is_ok());
}

#[test]
fn reset_failed_child_unlinks_backlog_before_output_and_quarantine_expiry() {
    let (mut a, _, _, _) = endpoints();
    // Use a one-entry backlog, leaving the independent slot bound larger.
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(addresses().1, 1).unwrap();
    let (tuple, _) = passive_quote(&mut a, &mut b);
    let failed = b.connection_id(tuple).unwrap();
    b.abort(failed).unwrap();
    assert_eq!(b.state(failed), Err(EndpointError::InvalidHandle));
    let mut local = addresses().0;
    local.set_port(local.port() + 1);
    a.connect(0, local, addresses().1).unwrap();
    deliver(&mut b, 0, packets(&mut a, 0));
    assert!(
        b.connection_id(Tuple {
            local: addresses().1,
            remote: local
        })
        .is_some()
    );
    assert_eq!(b.buffer_bytes(), 2 * connection_charge(&config()));
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert!(b.poll_transmit(0, &mut [0; 1], 1).is_err());
    b.close_listener(listener).unwrap();
    packets(&mut b, 0); // Must quiesce rather than repeatedly visit quarantined children.
    assert_eq!(b.buffer_bytes(), 2 * connection_charge(&config()));
    b.on_timeout(config().connection.time_wait_us, 2).unwrap();
    assert_eq!(b.buffer_bytes(), 0);
}

#[test]
fn time_wait_reuse_local_reset_keeps_candidate_quarantine() {
    let time_wait = config().connection.time_wait_us;
    for (release_old, payload) in [
        (false, b"".as_slice()),
        (true, b"".as_slice()),
        (false, b"data".as_slice()),
        (true, b"data".as_slice()),
    ] {
        let (mut b, listener, old, ip, h, _) = time_wait_endpoint(config());
        if release_old {
            b.release(old).unwrap();
        }
        let tuple = Tuple {
            local: addresses().1,
            remote: addresses().0,
        };
        let syn =
            tw_segment_with_payload(ip, h, h.acknowledgment + 100, 0, wire::SYN, None, payload);
        b.input(4_000, ip, &syn).unwrap();
        let candidate = b.connection_id(tuple).unwrap();
        b.abort(candidate).unwrap();
        assert_eq!(b.connection_id(tuple), Some(candidate));
        assert_eq!(b.connection_exists(old), !release_old);
        assert_eq!(b.time_wait_connections(), 0);
        assert_eq!(
            b.accept(listener),
            Err(EndpointError::Connection(Error::WouldBlock))
        );
        assert!(b.poll_transmit(5_000, &mut [0; 1], 1).is_err());
        assert_eq!(b.connection_id(tuple), Some(candidate));
        packets(&mut b, 6_000);
        b.on_timeout(3_000 + time_wait, 1).unwrap(); // The old TIME-WAIT would have ended.
        packets(&mut b, 3_000 + time_wait);
        assert_eq!(b.connection_exists(old), !release_old);
        assert_eq!(b.connection_id(tuple), Some(candidate));
        b.on_timeout(6_000 + time_wait, 1).unwrap();
        assert!(!b.connection_exists(candidate));
        assert_eq!(b.connection_id(tuple), None);
        let replacement = b
            .connect(6_000 + time_wait, tuple.local, tuple.remote)
            .unwrap();
        if !release_old {
            b.release(old).unwrap();
        }
        assert_eq!(b.connection_id(tuple), Some(replacement));
    }
}

#[test]
fn early_fin_passive_accept_waits_for_handshake_ack_and_reuse_failure_frees_the_tuple() {
    let (mut a, mut b, listener, _) = endpoints();
    let (tuple, _) = passive_quote(&mut a, &mut b);
    let child = b.connection_id(tuple).unwrap();
    while b.next_event().is_some() {}
    b.shutdown(child).unwrap();
    let fin = packets(&mut b, 0);
    assert_eq!(b.state(child), Ok(State::FinWait1));
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(b.next_event(), None);
    let h = wire::parse(fin[0].0, &fin[0].1).unwrap().header;
    let ip = IpMetadata {
        source: tuple.remote.ip(),
        destination: tuple.local.ip(),
    };
    let ack = tw_segment(ip, h, h.acknowledgment, h.sequence + 1, wire::ACK, None);
    b.input(1, ip, &ack).unwrap();
    assert_eq!(b.next_event(), Some(Event::Acceptable(listener)));
    assert_eq!(b.accept(listener), Ok(child));

    let (mut b, listener, old, ip, h, _) = time_wait_endpoint(config());
    let seq = h.acknowledgment + 100;
    b.input(4_000, ip, &tw_segment(ip, h, seq, 0, wire::SYN, None))
        .unwrap();
    let candidate = b.connection_id(tuple).unwrap();
    packets(&mut b, 4_000);
    b.shutdown(candidate).unwrap();
    packets(&mut b, 4_000);
    assert_eq!(b.state(candidate), Ok(State::FinWait1));
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    b.input(5_000, ip, &tw_segment(ip, h, seq + 1, 0, wire::RST, None))
        .unwrap();
    packets(&mut b, 5_000);
    assert_eq!(b.connection_id(tuple), None);
    assert_eq!(b.state(old), Ok(State::Closed));
    assert_eq!(b.time_wait_connections(), 0);
    assert!(!b.connection_exists(candidate));
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc2883#section-4
//= type=test
//= reason=Checksum-invalid endpoint input never reaches the checked-arrival supersession boundary; failed output and corrupt arrival preserve the valid duplicate report for retry.
//# (1) A D-SACK block is only used to report a duplicate contiguous
//# sequence of data received by the receiver in the most recent packet.
fn dsack_checksum_invalid_arrival_preserves_failed_output_report() {
    let mut cfg = config();
    cfg.connection.sack = true;
    cfg.connection.delayed_ack_us = 0;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    a.write(client, b"duplicate").unwrap();
    let data = packets(&mut a, 40);
    assert_eq!(data.len(), 1);
    let (ip, bytes) = &data[0];
    let segment = wire::parse(*ip, bytes).unwrap();
    let duplicate = (
        segment.header.sequence,
        segment
            .header
            .sequence
            .wrapping_add(segment.payload.len() as u32),
    );
    b.input(40, *ip, bytes).unwrap();
    packets(&mut b, 40);
    b.input(41, *ip, bytes).unwrap();
    assert_eq!(
        b.poll_transmit(41, &mut [0; 19], 16),
        Err(EndpointError::Connection(Error::OutputTooSmall))
    );
    let mut corrupt = bytes.clone();
    corrupt[16] ^= 1;
    assert_eq!(
        b.input(42, *ip, &corrupt).unwrap(),
        InputDisposition::Dropped
    );
    let reports = packets(&mut b, 42);
    assert_eq!(reports.len(), 1);
    assert_eq!(
        wire::parse(reports[0].0, &reports[0].1)
            .unwrap()
            .options
            .sack_blocks[0],
        Some(duplicate)
    );
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=End-to-end restarted SYN-SENT peer receives challenge, emits ACK-derived exact RST, and reestablishes via timed SYN retransmission; retained listener accepts a new connection and data transfers.
//# A legitimate peer, after restart, would not have a TCB in the synchronized state. Thus, when the ACK arrives, the peer should send a RST segment back with the sequence number derived from the ACK field that caused the RST.
//= https://www.rfc-editor.org/rfc/rfc5961#section-4.2
//= type=test
//= reason=End-to-end restarted SYN-SENT peer receives challenge, emits ACK-derived exact RST, and reestablishes via timed SYN retransmission; retained listener accepts a new connection and data transfers.
//# The local TCP endpoint should then rely on SYN retransmission from the remote end to re-establish the connection.
fn rfc5961_restart_challenge_valid_reset_then_syn_retransmission() {
    let (mut a, mut b, listener, _) = endpoints();
    pump(&mut a, &mut b, 0);
    let old = b.accept(listener).unwrap();
    let (local, remote) = addresses();
    // Restart discards all of the client's old TCBs, preserving the server.
    a = Endpoint::new(config(), [99; 32], 10, test_policy).unwrap();
    let restarted = a.connect(10, local, remote).unwrap();
    let syn = packets(&mut a, 10);
    assert_eq!(syn.len(), 1);
    let initial = wire::parse(syn[0].0, &syn[0].1).unwrap();
    assert_eq!(initial.header.flags & wire::SYN, wire::SYN);
    let initial_seq = initial.header.sequence;
    deliver(&mut b, 10, syn);
    assert_eq!(b.state(old), Ok(State::Established));
    let challenge = packets(&mut b, 10);
    assert_eq!(challenge.len(), 1);
    let p = wire::parse(challenge[0].0, &challenge[0].1).unwrap();
    assert_eq!(p.header.flags, wire::ACK);
    assert!(p.payload.is_empty());
    let valid_reset_seq = p.header.acknowledgment;
    deliver(&mut a, 10, challenge);
    assert_eq!(a.state(restarted), Ok(State::SynSent));
    let reset = packets(&mut a, 10);
    assert_eq!(reset.len(), 1);
    let p = wire::parse(reset[0].0, &reset[0].1).unwrap();
    assert_eq!(p.header.flags, wire::RST);
    assert_eq!(p.header.sequence, valid_reset_seq);
    assert!(p.payload.is_empty());
    deliver(&mut b, 10, reset);
    assert_eq!(b.state(old), Ok(State::Closed));
    b.release(old).unwrap();
    let deadline = a.next_deadline().unwrap();
    assert!(!a.on_timeout(deadline, 16).unwrap());
    let retry = packets(&mut a, deadline);
    assert_eq!(retry.len(), 1);
    let p = wire::parse(retry[0].0, &retry[0].1).unwrap();
    assert_eq!(p.header.flags & wire::SYN, wire::SYN);
    assert_eq!(p.header.sequence, initial_seq);
    deliver(&mut b, deadline, retry);
    pump(&mut a, &mut b, deadline);
    let replacement = b.accept(listener).unwrap();
    assert_ne!(replacement, old);
    assert_eq!(a.state(restarted), Ok(State::Established));
    assert_eq!(b.state(replacement), Ok(State::Established));
    a.write(restarted, b"new incarnation").unwrap();
    pump(&mut a, &mut b, deadline);
    let mut data = [0; 32];
    assert_eq!(b.read(replacement, &mut data), Ok(15));
    assert_eq!(&data[..15], b"new incarnation");
}

#[test]
fn endpoint_rejects_zero_challenge_budget_configuration() {
    for interval in [false, true] {
        let mut cfg = config();
        if interval {
            cfg.connection.challenge_ack_interval_us = 0;
        } else {
            cfg.connection.challenge_ack_limit = 0;
        }
        assert!(matches!(
            Endpoint::new(cfg, [1; 32], 0, test_policy),
            Err(EndpointError::Connection(Error::InvalidArgument))
        ));
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
//# While still under discussion, to enable research into this area it is
//# now RECOMMENDED that when generating an <RST>, if the segment causing
//# the <RST> to be generated contains a Timestamps option, the <RST>
//# should also contain a Timestamps option.
//= https://www.rfc-editor.org/rfc/rfc7323#section-5.2
//= type=test
//= reason=Reactive RST uses (0,incoming TSval) independently of local TS configuration/negotiation when the IP payload budget permits 32 TCP bytes. At budgets 28..31 the optional TS is omitted rather than exceeding the path bound; this bounded SHOULD departure is tested for ACK/no-ACK resets. SYN-SENT and synchronized handshake rejection preserve the same echo policy.
//# In the <RST> segment,
//# SEG.TSecr SHOULD be set to SEG.TSval from the incoming segment and
//# SEG.TSval SHOULD be set to zero.
//= https://www.rfc-editor.org/rfc/rfc7323#section-7.1
//= type=test
//= reason=Endpoint derives offset using HMAC-SHA256 secret, tuple and ISS nonce in the separate ntcp timestamp offset domain before first output; ISS is an input, never the offset. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset so peer PAWS sees no random jump; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, echo/RTT/wrap and reuse rollback tests cover the policy.
//# It is therefore RECOMMENDED to generate a random, per-
//# connection offset to be used with the clock source when generating
//# the Timestamps option value (see Section 5.4).
//= https://www.rfc-editor.org/rfc/rfc7323#section-7
//= type=test
//= reason=Endpoint derives offset using HMAC-SHA256 secret, tuple and ISS nonce in the separate ntcp timestamp offset domain before first output; ISS is an input, never the offset. Modular addition/subtraction covers wire TS and ordinary/RACK RTT validation. TIME-WAIT reuse inherits the old local offset so peer PAWS sees no random jump; failed output/candidate rollback retain the old clock. Unrelated tuple/secret, echo/RTT/wrap and reuse rollback tests cover the policy.
//# It is therefore
//# RECOMMENDED to generate a random, per-connection offset to be used
//# with the clock source when generating the Timestamps option value
//# (see Section 5.4).
fn timestamp_privacy_echo_rtt_and_reactive_reset_without_local_enable() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.connection.delayed_ack_us = 0;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    let syn = packets(&mut a, 1_000).pop().unwrap();
    let first = wire::parse(syn.0, &syn.1)
        .unwrap()
        .options
        .timestamps
        .unwrap()
        .0;
    assert_ne!(first, 1);
    b.input(1_000, syn.0, &syn.1).unwrap();
    let synack = packets(&mut b, 2_000).pop().unwrap();
    let reply = wire::parse(synack.0, &synack.1)
        .unwrap()
        .options
        .timestamps
        .unwrap();
    assert_eq!(reply.1, first);
    assert_ne!(reply.0.wrapping_sub(2), first.wrapping_sub(1));
    a.input(2_000, synack.0, &synack.1).unwrap();
    let ack = packets(&mut a, 2_000).pop().unwrap();
    assert_eq!(
        wire::parse(ack.0, &ack.1)
            .unwrap()
            .options
            .timestamps
            .unwrap(),
        (first.wrapping_add(1), reply.0)
    );
    b.input(2_000, ack.0, &ack.1).unwrap();
    b.accept(listener).unwrap();
    let mut other = local;
    other.set_port(local.port() + 1);
    a.connect(2_000, other, remote).unwrap();
    let second = packets(&mut a, 2_000).pop().unwrap();
    assert_ne!(
        wire::parse(second.0, &second.1)
            .unwrap()
            .options
            .timestamps
            .unwrap()
            .0
            .wrapping_sub(2),
        first.wrapping_sub(1)
    );
    a.write(client, b"hello").unwrap();
    let data = packets(&mut a, 3_000).pop().unwrap();
    b.input(3_500, data.0, &data.1).unwrap();
    let ack = packets(&mut b, 3_500).pop().unwrap();
    assert_eq!(
        wire::parse(ack.0, &ack.1)
            .unwrap()
            .options
            .timestamps
            .unwrap()
            .1,
        first.wrapping_add(2)
    );
    a.input(4_000, ack.0, &ack.1).unwrap();
    assert_eq!(a.transport_info(client).unwrap().rtt_us, Some(1_000));

    for budget in [28, 31, 32] {
        for flags in [wire::SYN, wire::ACK] {
            let mut cfg = config();
            cfg.connection.send_ip_payload_limit = budget;
            let mut endpoint = Endpoint::new(cfg, [3; 32], 0, test_policy).unwrap();
            let h = wire::parse(syn.0, &syn.1).unwrap().header;
            let input = tw_segment(syn.0, h, 123, 456, flags, Some((77, 0)));
            endpoint.input(1_000, syn.0, &input).unwrap();
            let reset = packets(&mut endpoint, 1_000).pop().unwrap();
            let reset = wire::parse(reset.0, &reset.1).unwrap();
            assert_eq!(reset.options.timestamps, (budget >= 32).then_some((0, 77)));
            assert_eq!(
                reset.header.flags,
                if flags == wire::ACK {
                    wire::RST
                } else {
                    wire::RST | wire::ACK
                }
            );
        }
    }
}

#[test]
fn timestamp_offset_time_wait_reuse_keeps_virtual_clock() {
    for (granularity, payload) in [
        (crate::TimestampGranularity::Milliseconds, b"".as_slice()),
        (crate::TimestampGranularity::Microseconds, b"".as_slice()),
        (
            crate::TimestampGranularity::Milliseconds,
            b"data".as_slice(),
        ),
        (
            crate::TimestampGranularity::Microseconds,
            b"data".as_slice(),
        ),
    ] {
        let mut cfg = config();
        cfg.connection.timestamps = true;
        cfg.connection.timestamp_granularity = granularity;
        let (mut b, _, old, ip, h, ts) = time_wait_endpoint(cfg);
        let duplicate_fin = tw_segment(
            ip,
            h,
            h.acknowledgment.wrapping_sub(1),
            h.sequence,
            wire::FIN | wire::ACK,
            Some((ts, 0)),
        );
        b.input(4_000, ip, &duplicate_fin).unwrap();
        let output = packets(&mut b, 4_000).pop().unwrap();
        let old_value = wire::parse(output.0, &output.1)
            .unwrap()
            .options
            .timestamps
            .unwrap()
            .0;
        let seq = h.acknowledgment.wrapping_add(100);
        let syn = tw_segment_with_payload(
            ip,
            h,
            seq,
            0,
            wire::SYN,
            Some((ts.wrapping_add(1), 0)),
            payload,
        );
        b.input(5_000, ip, &syn).unwrap();
        assert_eq!(
            b.poll_transmit(5_000, &mut [0; 19], 16),
            Err(EndpointError::Connection(Error::OutputTooSmall))
        );
        let output = packets(&mut b, 5_000).pop().unwrap();
        let synack = wire::parse(output.0, &output.1).unwrap();
        assert_eq!(
            synack.options.timestamps.unwrap().0,
            old_value.wrapping_add((1_000 / granularity.tick_us()) as u32)
        );
        assert_eq!(b.state(old), Ok(State::Closed));
    }
}

#[test]
fn pacing_endpoint_budget_and_halfclose() {
    pacing_endpoint_budget_case(None);
}

#[test]
fn general_pacing_endpoint_budget_and_halfclose() {
    pacing_endpoint_budget_case(Some(crate::PacingConfig {
        initial_window_burst: false,
        max_burst_segments: 1,
        ..crate::PacingConfig::default()
    }));
}

#[test]
fn general_pacing_saturated_deadline_does_not_rearm_endpoint() {
    let start = u64::MAX - 1000;
    let mut cfg = config();
    cfg.connection.timestamps = false;
    cfg.connection.delayed_ack_us = 0;
    cfg.connection.pacing = Some(PacingConfig {
        max_bytes_per_second: Some(1),
        ..PacingConfig::default()
    });
    assert!(cfg.connection.keepalive.is_none());
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], start, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], start, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(start, local, remote).unwrap();
    pump(&mut a, &mut b, start);
    let server = b.accept(listener).unwrap();

    a.write(client, &[0x55; 128]).unwrap();
    let sent = packets(&mut a, start + 1);
    assert_eq!(sent.len(), 2);
    for (ip, bytes) in &sent {
        assert_eq!(wire::parse(*ip, bytes).unwrap().payload.len(), 64);
    }
    assert_eq!(a.next_deadline(), Some(u64::MAX));
    deliver(&mut b, u64::MAX, sent);
    deliver(&mut a, u64::MAX, packets(&mut b, u64::MAX));
    let info = a.transport_info(client).unwrap();
    assert_eq!(
        (info.unacked, info.notsent_bytes, info.send_used),
        (0, 0, 0)
    );

    // Residual pacing debt cannot drain at MAX, but there is no serviceable
    // future wakeup. Budget exhaustion must not perpetually rearm due MAX.
    assert!(!a.on_timeout(u64::MAX, 4).unwrap());
    assert_eq!(a.next_deadline(), None);
    assert!(!a.on_timeout(u64::MAX, 1).unwrap());
    assert!(packets(&mut a, u64::MAX).is_empty());

    // Suppressing the wakeup must not forgive debt or block control output.
    a.write(client, b"new data").unwrap();
    assert!(packets(&mut a, u64::MAX).is_empty());
    b.write(server, b"x").unwrap();
    deliver(&mut a, u64::MAX, packets(&mut b, u64::MAX));
    let control = packets(&mut a, u64::MAX);
    assert_eq!(control.len(), 1);
    let ack = wire::parse(control[0].0, &control[0].1).unwrap();
    assert_eq!(ack.header.flags, wire::ACK);
    assert!(ack.payload.is_empty());
    assert_eq!(a.transport_info(client).unwrap().notsent_bytes, 8);
    assert!(packets(&mut a, u64::MAX).is_empty());
}

fn pacing_endpoint_budget_case(pacing: Option<crate::PacingConfig>) {
    for scale in [1, 1000] {
        let mut cfg = config();
        cfg.connection.prr = pacing.is_none();
        cfg.connection.pacing = pacing;
        cfg.connection.timebase.units_per_second = 1_000_000 * scale;
        assert!(cfg.connection.prr_pacing);
        let (local, remote) = addresses();
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        let listener = b.listen(remote, 4).unwrap();
        let client = a.connect(0, local, remote).unwrap();
        pump(&mut a, &mut b, 0);
        let server = b.accept(listener).unwrap();
        a.write(client, &[0x55; 150]).unwrap();
        a.shutdown(client).unwrap();
        let mut out = [0; 2048];
        let first = a
            .poll_transmit(100 * scale, &mut out, 1)
            .unwrap()
            .packet
            .unwrap();
        let segment = wire::parse(first.ip, &out[..first.len]).unwrap();
        assert_eq!(segment.payload.len(), 64);
        assert_eq!(segment.header.flags & wire::FIN, 0);
        b.input(100 * scale, first.ip, &out[..first.len]).unwrap();
        assert!(
            a.poll_transmit(100 * scale, &mut out, 1)
                .unwrap()
                .packet
                .is_none()
        );
        assert!(!a.has_pending_output()); // Ok(None) removed the queue entry
        let deadline = a.next_deadline().unwrap();
        assert!(deadline > 100 * scale);
        assert!(!a.on_timeout(deadline - 1, 1).unwrap());
        assert!(
            a.poll_transmit(deadline - 1, &mut out, 1)
                .unwrap()
                .packet
                .is_none()
        );
        assert!(a.on_timeout(deadline, 0).unwrap());
        assert!(!a.has_pending_output());
        assert!(
            !a.on_timeout(deadline, 1).unwrap(),
            "deadline={deadline} next={:?}",
            a.next_deadline()
        );
        assert!(a.has_pending_output());
        assert!(a.poll_transmit(deadline, &mut [0; 19], 1).is_err());
        assert!(a.has_pending_output());
        let second = a
            .poll_transmit(deadline, &mut out, 1)
            .unwrap()
            .packet
            .unwrap();
        assert_eq!(
            wire::parse(second.ip, &out[..second.len])
                .unwrap()
                .payload
                .len(),
            64
        );
        b.input(deadline, second.ip, &out[..second.len]).unwrap();
        assert!(
            a.poll_transmit(deadline, &mut out, 1)
                .unwrap()
                .packet
                .is_none()
        );
        let next = a.next_deadline().unwrap();
        assert!(next > deadline);
        a.on_timeout(next, 1).unwrap();
        let last = a.poll_transmit(next, &mut out, 1).unwrap().packet.unwrap();
        let segment = wire::parse(last.ip, &out[..last.len]).unwrap();
        assert_eq!(segment.payload.len(), 22);
        assert_ne!(segment.header.flags & wire::FIN, 0);
        b.input(next, last.ip, &out[..last.len]).unwrap();
        pump(&mut a, &mut b, next);
        assert_eq!(a.state(client).unwrap(), State::FinWait2);
        assert_eq!(b.state(server).unwrap(), State::CloseWait);
        let mut received = [0; 150];
        assert_eq!(b.read(server, &mut received).unwrap(), 150);
        assert_eq!(received, [0x55; 150]);
        // Opposite-direction half-close remains writable. FIN-only bypasses
        // pacing, and cleanup must not retain a pacing timer in TIME-WAIT.
        b.write(server, b"x").unwrap();
        pump(&mut a, &mut b, next);
        b.shutdown(server).unwrap();
        pump(&mut a, &mut b, next);
        assert_eq!(a.state(client).unwrap(), State::TimeWait);
        assert_eq!(b.state(server).unwrap(), State::Closed);
    }
}

#[test]
fn buffer_quotas_live_resize_retention_failure_and_reclamation() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    let original_charge = a.buffer_bytes();
    let payload = vec![42; 512];
    assert_eq!(a.write(client, &payload), Ok(512));
    a.set_buffer_capacities(client, 128, 128).unwrap();
    assert_eq!(a.buffer_capacities(client), Ok((128, 128)));
    assert_eq!(a.buffer_bytes(), original_charge);
    assert_eq!(a.write(client, b"!"), Err(Error::WouldBlock.into()));
    a.set_buffer_capacities(client, 2048, 2048).unwrap();
    let grown_charge = a.buffer_bytes();
    assert!(grown_charge > original_charge);
    assert!(
        matches!(a.next_event(), Some(Event::Connection(id, events)) if id == client && events.writable)
    );
    a.set_buffer_capacities(client, 128, 128).unwrap();
    assert_eq!(a.buffer_bytes(), grown_charge);
    for allocation in 0..4 {
        assert_eq!(
            crate::allocation_tests::fail_after(allocation, || a
                .set_buffer_capacities(client, 4096, 4096)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(a.buffer_capacities(client), Ok((128, 128)));
        assert_eq!(a.buffer_bytes(), grown_charge);
        assert_eq!(a.transport_info(client).unwrap().send_used, 512);
    }
    assert_eq!(
        a.set_buffer_capacities(client, 1 << 30, 1),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(
        a.set_buffer_capacities(client, 1 << 29, 1 << 29),
        Err(EndpointError::LimitReached)
    );
    assert_eq!(a.buffer_capacities(client), Ok((128, 128)));
    assert_eq!(a.buffer_bytes(), grown_charge);
    pump(&mut a, &mut b, 0);
    let mut bytes = [0; 512];
    assert_eq!(b.read(server, &mut bytes), Ok(512));
    assert_eq!(&bytes, payload.as_slice());
    // Quarantine continues charging retained allocations until reset expiry.
    a.abort(client).unwrap();
    a.release(client).unwrap();
    packets(&mut a, 0);
    assert_eq!(a.buffer_bytes(), grown_charge);
    a.on_timeout(config().connection.time_wait_us, 64).unwrap();
    assert!(!a.connection_exists(client));
    assert_eq!(a.buffer_bytes(), 0);
}

#[test]
fn buffer_capacities_prehandshake_inheritance_and_pool_mismatch() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.preallocate_connections = 1;
    let reserved = connection_charge(&cfg);
    cfg.max_buffer_bytes = reserved;
    let mut limited = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    for allocation in 0..4 {
        assert_eq!(
            crate::allocation_tests::fail_after(allocation, || limited.connect(0, local, remote)),
            Err(Error::NoMemory.into())
        );
        assert_eq!(limited.buffer_bytes(), reserved);
        assert_eq!(limited.connection_id(Tuple { local, remote }), None);
    }
    // Incompatible pooled storage is neither reused nor silently enlarged.
    assert_eq!(
        limited.connect_with_buffer_capacities(0, local, remote, 32, 32),
        Err(EndpointError::LimitReached)
    );
    assert_eq!(limited.buffer_bytes(), reserved);
    let id = limited
        .connect_with_buffer_capacities(0, local, remote, 32, 1024)
        .unwrap();
    assert_eq!(limited.buffer_capacities(id), Ok((32, 1024)));
    assert!(limited.buffer_bytes() < reserved);

    cfg.max_buffer_bytes = 16 * reserved;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 2).unwrap();
    b.set_listener_buffer_capacities(listener, 4096, 131072)
        .unwrap();
    assert_eq!(b.listener_buffer_capacities(listener), Ok((4096, 131072)));
    let client = a
        .connect_with_buffer_capacities(0, local, remote, 2048, 262144)
        .unwrap();
    let syn = packets(&mut a, 0);
    let parsed = wire::parse(syn[0].0, &syn[0].1).unwrap();
    assert_eq!(parsed.options.window_scale, Some(3));
    deliver(&mut b, 0, syn);
    let child = b
        .connection_id(Tuple {
            local: remote,
            remote: local,
        })
        .unwrap();
    assert_eq!(b.buffer_capacities(child), Ok((4096, 131072)));
    // A later listener edit affects only subsequently constructed children.
    b.set_listener_buffer_capacities(listener, 8192, 4096)
        .unwrap();
    let synack = packets(&mut b, 0);
    let parsed = wire::parse(synack[0].0, &synack[0].1).unwrap();
    assert_eq!(parsed.options.window_scale, Some(2));
    deliver(&mut a, 0, synack);
    pump(&mut a, &mut b, 0);
    assert_eq!(b.accept(listener), Ok(child));
    assert_eq!(b.buffer_capacities(child), Ok((4096, 131072)));
    assert_eq!(a.buffer_capacities(client), Ok((2048, 262144)));
    // A mismatched pool remains charged alongside the new child.
    assert!(b.buffer_bytes() > reserved);
}

#[test]
fn endpoint_cork_more_eor_deadline_flush_and_failed_output() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    a.set_cork(client, true).unwrap();
    a.write_with_options(client, b"abc", true, true).unwrap();
    assert!(packets(&mut a, 0).is_empty());
    assert_eq!(a.next_deadline(), Some(200_000));
    let charge = a.buffer_bytes();
    a.write_with_options(client, b"de", true, true).unwrap();
    let first = packets(&mut a, 0);
    assert_eq!(first.len(), 1);
    assert_eq!(
        wire::parse(first[0].0, &first[0].1).unwrap().payload,
        b"abc"
    );
    deliver(&mut b, 0, first);
    assert_eq!(a.buffer_bytes(), charge); // No per-record allocations.
    a.set_nagle(client, false).unwrap();
    assert_eq!(
        a.poll_transmit(0, &mut [0; 21], 16),
        Err(EndpointError::Connection(Error::OutputTooSmall))
    );
    let flushed = packets(&mut a, 0);
    assert_eq!(flushed.len(), 1);
    assert_eq!(
        wire::parse(flushed[0].0, &flushed[0].1).unwrap().payload,
        b"de"
    );
    deliver(&mut b, 0, flushed);
    a.write(client, b"fg").unwrap(); // Explicit NODELAY did not clear socket CORK.
    assert!(packets(&mut a, 0).is_empty());
    assert_eq!(a.next_deadline(), Some(200_000));
    assert!(!a.on_timeout(199_999, 16).unwrap());
    assert!(packets(&mut a, 199_999).is_empty());
    assert!(!a.on_timeout(200_000, 16).unwrap());
    let expired = packets(&mut a, 200_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(
        wire::parse(expired[0].0, &expired[0].1).unwrap().payload,
        b"fg"
    );
    deliver(&mut b, 200_000, expired);
    let mut data = [0; 7];
    assert_eq!(b.read(server, &mut data), Ok(7));
    assert_eq!(&data, b"abcdefg"); // Receive remains a byte stream, not records.
    a.write_with_options(client, b"hi", true, false).unwrap();
    assert!(packets(&mut a, 200_000).is_empty());
    a.set_cork(client, false).unwrap();
    let uncorked = packets(&mut a, 200_000);
    assert_eq!(uncorked.len(), 1);
    assert_eq!(
        wire::parse(uncorked[0].0, &uncorked[0].1).unwrap().payload,
        b"hi"
    );
}

#[test]
fn endpoint_lowat_partial_eor_and_unlimited_admission_preserve_heap_quota() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    a.set_buffer_capacities(client, 32, 32).unwrap();
    a.set_cork(client, true).unwrap();
    let charge = a.buffer_bytes();
    assert_eq!(a.send_admission_room(client, Some(24)), Ok(24));
    assert_eq!(
        a.write_with_options_and_notsent_lowat(client, &[1; 40], true, true, Some(24)),
        Ok(24)
    );
    assert_eq!(a.send_admission_room(client, Some(24)), Ok(0));
    assert_eq!(
        a.write_with_options_and_notsent_lowat(client, b"x", true, false, Some(24)),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(a.buffer_bytes(), charge);
    a.set_buffer_capacities(client, 64, 32).unwrap();
    // Growing capacity does not change the exhausted unsent-byte budget.
    assert_eq!(a.send_admission_room(client, Some(24)), Ok(0));
    let charge = a.buffer_bytes();
    assert_eq!(
        a.write_with_options_and_notsent_lowat(client, &[2; 16], true, false, None),
        Ok(16)
    );
    assert_eq!(
        a.write_with_options_and_notsent_lowat(client, &[3; 32], true, false, Some(u32::MAX)),
        Ok(24)
    );
    assert_eq!(a.buffer_bytes(), charge);
}

#[test]
fn tx_timestamp_backend_backpressure_coalesced_callbacks_and_late_hardware() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let _server = b.accept(listener).unwrap();
    let request = |cookie| TxTimestampRequest {
        cookie,
        scheduled: true,
        software_transmit: true,
        hardware_transmit: true,
        acknowledged: true,
    };
    assert_eq!(
        a.write_with_timestamp(client, b"ab", true, false, None, request(1)),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    a.set_tx_timestamp_capacity(client, 8).unwrap();
    assert_eq!(
        a.prepare_write_admission(client, 4, None, request(1)),
        Ok(4)
    );
    for (cookie, bytes, more) in [(1, &b"ab"[..], true), (2, &b"cd"[..], false)] {
        crate::allocation_tests::fail_after(0, || {
            assert_eq!(
                a.write_with_timestamp(client, bytes, more, false, None, request(cookie)),
                Ok(2)
            );
        });
    }
    let mut out = [0; 2048];
    let tx = a.poll_transmit(100, &mut out, 16).unwrap().packet.unwrap();
    let token = tx.tx_timestamp.unwrap();
    assert_eq!(token.connection(), client);
    assert_eq!(token.stream_range(), TxStreamRange { start: 0, end: 4 });
    for cookie in [1, 2] {
        let event = a.next_tx_timestamp(client).unwrap().unwrap();
        assert_eq!(
            (event.cookie, event.target, event.stage),
            (cookie, cookie * 2 - 1, TxTimestampStage::Scheduled)
        );
        assert_eq!(
            event.outcome,
            TxTimestampOutcome::Recorded {
                value: 100,
                clock: TxTimestampClock::CallerTicks(CallerTimebase::default()),
            }
        );
    }
    // A backend WouldBlock retains bytes/token externally and makes no report.
    // Core output-ready alone must not invent backend success.
    assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
    assert!(
        a.poll_transmit(101, &mut [0; 2048], 16)
            .unwrap()
            .packet
            .is_none()
    );
    assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
    b.input(102, tx.ip, &out[..tx.len]).unwrap();
    tick(&mut a, &mut b, 300_000);
    assert_eq!(a.acknowledged(client).unwrap(), 4);
    for cookie in [1, 2] {
        let event = a.next_tx_timestamp(client).unwrap().unwrap();
        assert_eq!(
            (event.cookie, event.stage),
            (cookie, TxTimestampStage::Acknowledged)
        );
        assert_eq!(
            event.outcome,
            TxTimestampOutcome::Recorded {
                value: 300_000,
                clock: TxTimestampClock::CallerTicks(CallerTimebase::default()),
            }
        );
    }
    assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
    let deadline = a.next_deadline();
    let info = a.transport_info(client).unwrap();
    assert_eq!(
        a.report_tx_timestamp(
            token,
            TxTimestampSource::Hardware,
            1,
            TxTimestampClock::DeviceTicks {
                identity: 42,
                units_per_second: Some(0)
            }
        ),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    assert_eq!(
        a.report_tx_timestamp(
            token,
            TxTimestampSource::Software,
            1,
            TxTimestampClock::CallerTicks(CallerTimebase::default())
        ),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    for (source, clock, value) in [
        (
            TxTimestampSource::Software,
            TxTimestampClock::RealtimeNanoseconds,
            7,
        ),
        (
            TxTimestampSource::Hardware,
            TxTimestampClock::DeviceTicks {
                identity: 42,
                units_per_second: None,
            },
            u64::MAX,
        ),
    ] {
        crate::allocation_tests::fail_after(0, || {
            a.report_tx_timestamp(token, source, value, clock)
        })
        .unwrap();
        // Duplicate before and after drain must not produce additional events.
        a.report_tx_timestamp(token, source, value - 1, clock)
            .unwrap();
        for cookie in [1, 2] {
            let event = a.next_tx_timestamp(client).unwrap().unwrap();
            assert_eq!(
                (event.cookie, event.stage, event.source),
                (cookie, TxTimestampStage::Transmit, source)
            );
            assert_eq!(event.outcome, TxTimestampOutcome::Recorded { value, clock });
        }
        a.report_tx_timestamp(token, source, value, clock).unwrap();
        assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
    }
    assert_eq!(a.next_deadline(), deadline);
    assert_eq!(a.transport_info(client).unwrap(), info); // No observation clock drives TCP.
    a.set_tx_timestamp_capacity(client, 0).unwrap();
}

#[test]
fn tx_timestamp_terminal_cancellation_release_and_reused_generation() {
    for drain in [false, true] {
        let (mut a, mut b, listener, client) = endpoints();
        pump(&mut a, &mut b, 0);
        b.accept(listener).unwrap();
        let base_charge = a.buffer_bytes();
        a.set_tx_timestamp_capacity(client, 3).unwrap();
        let request = TxTimestampRequest {
            cookie: 99,
            software_transmit: true,
            hardware_transmit: true,
            acknowledged: true,
            ..Default::default()
        };
        a.write_with_timestamp(client, b"abc", false, false, None, request)
            .unwrap();
        let token = a
            .poll_transmit(1, &mut [0; 2048], 16)
            .unwrap()
            .packet
            .unwrap()
            .tx_timestamp
            .unwrap();
        a.abort(client).unwrap();
        if drain {
            for _ in 0..3 {
                let event = a.next_tx_timestamp(client).unwrap().unwrap();
                assert_eq!(event.cookie, 99);
                assert_eq!(event.outcome, TxTimestampOutcome::Cancelled);
            }
        }
        a.release(client).unwrap();
        assert_eq!(a.buffer_bytes(), base_charge); // Release frees even undrained records.
        assert_eq!(
            a.next_tx_timestamp(client),
            Err(EndpointError::InvalidHandle)
        );
        assert_eq!(
            a.report_tx_timestamp(
                token,
                TxTimestampSource::Hardware,
                99,
                TxTimestampClock::RealtimeNanoseconds
            ),
            Err(EndpointError::InvalidHandle)
        );
        let tx = a
            .poll_transmit(2, &mut [0; 2048], 16)
            .unwrap()
            .packet
            .unwrap();
        assert_eq!(tx.tx_timestamp, None); // Final RST carries no payload range.
        let expiry = 2 + config().connection.time_wait_us;
        a.on_timeout(expiry, 16).unwrap();
        a.poll_transmit(expiry, &mut [0; 2048], 16).unwrap();
        let (local, remote) = addresses();
        let replacement = a.connect(expiry, local, remote).unwrap();
        assert_ne!(replacement, client);
        a.set_tx_timestamp_capacity(replacement, 1).unwrap();
        a.write_with_timestamp(
            replacement,
            b"abc",
            false,
            false,
            None,
            TxTimestampRequest {
                cookie: 100,
                hardware_transmit: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            a.report_tx_timestamp(
                token,
                TxTimestampSource::Hardware,
                100,
                TxTimestampClock::RealtimeNanoseconds
            ),
            Err(EndpointError::InvalidHandle)
        );
        assert_eq!(a.next_tx_timestamp(replacement).unwrap(), None);
        a.cancel_tx_timestamps(replacement).unwrap();
        assert_eq!(
            a.next_tx_timestamp(replacement).unwrap().unwrap().cookie,
            100
        );
        assert_eq!(a.next_tx_timestamp(replacement).unwrap(), None);
    }
}

#[test]
fn tx_timestamp_retransmit_stable_range_preserves_first_observation_and_timewait_cancels() {
    for units_per_second in [1_000_000, 1_000_000_000] {
        let scale = units_per_second / 1_000_000;
        let mut cfg = config();
        cfg.connection.timebase.units_per_second = units_per_second;
        let (local, remote) = addresses();
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg.clone(), [2; 32], 0, test_policy).unwrap();
        let listener = b.listen(remote, 4).unwrap();
        let client = a.connect(0, local, remote).unwrap();
        pump(&mut a, &mut b, 0);
        let server = b.accept(listener).unwrap();
        a.set_tx_timestamp_capacity(client, 3).unwrap();
        a.write_with_timestamp(
            client,
            b"abcd",
            false,
            false,
            None,
            TxTimestampRequest {
                cookie: 1,
                scheduled: true,
                hardware_transmit: true,
                acknowledged: true,
                ..Default::default()
            },
        )
        .unwrap();
        let first = a
            .poll_transmit(100 * scale, &mut [0; 2048], 16)
            .unwrap()
            .packet
            .unwrap();
        let first_token = first.tx_timestamp.unwrap();
        // Drop first packet, then allow the RTO's retransmission to reach peer.
        let retry_at = a.next_deadline().unwrap();
        a.on_timeout(retry_at, 16).unwrap();
        let mut bytes = [0; 2048];
        let retry = a
            .poll_transmit(retry_at, &mut bytes, 16)
            .unwrap()
            .packet
            .unwrap();
        let retry_token = retry.tx_timestamp.unwrap();
        assert_eq!(first_token, retry_token);
        assert_eq!(
            retry_token.stream_range(),
            TxStreamRange { start: 0, end: 4 }
        );
        let event = a.next_tx_timestamp(client).unwrap().unwrap();
        assert_eq!(
            event.outcome,
            TxTimestampOutcome::Recorded {
                value: 100 * scale,
                clock: TxTimestampClock::CallerTicks(cfg.connection.timebase),
            }
        );
        assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
        b.input(retry_at, retry.ip, &bytes[..retry.len]).unwrap();
        let ack_at = retry_at + 300_000 * scale;
        tick(&mut a, &mut b, ack_at);
        assert_eq!(
            a.next_tx_timestamp(client).unwrap().unwrap().stage,
            TxTimestampStage::Acknowledged
        );
        a.shutdown(client).unwrap();
        pump(&mut a, &mut b, ack_at);
        assert_eq!(a.state(client).unwrap(), State::FinWait2);
        assert_eq!(a.next_tx_timestamp(client).unwrap(), None); // Half-close keeps HW pending.
        let mut read = [0; 4];
        assert_eq!(b.read(server, &mut read), Ok(4));
        b.shutdown(server).unwrap();
        pump(&mut a, &mut b, ack_at);
        assert_eq!(a.state(client).unwrap(), State::TimeWait);
        let event = a.next_tx_timestamp(client).unwrap().unwrap();
        assert_eq!(
            (event.stage, event.source, event.outcome),
            (
                TxTimestampStage::Transmit,
                TxTimestampSource::Hardware,
                TxTimestampOutcome::Cancelled
            )
        );
        a.report_tx_timestamp(
            retry_token,
            TxTimestampSource::Hardware,
            10,
            TxTimestampClock::DeviceTicks {
                identity: 7,
                units_per_second: Some(100),
            },
        )
        .unwrap();
        assert_eq!(a.next_tx_timestamp(client).unwrap(), None);
        a.set_tx_timestamp_capacity(client, 0).unwrap();
    }
}

#[test]
fn rx_timestamp_endpoint_validation_peek_copyout_retry_and_sources() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    let server = b.accept(listener).unwrap();
    b.set_rx_timestamp_capacity(server, 4).unwrap();
    a.write(client, b"abcdef").unwrap();
    let mut out = [0; 2048];
    let tx = a.poll_transmit(1, &mut out, 16).unwrap().packet.unwrap();
    let bytes = &out[..tx.len];
    let stamp = RxTimestamp {
        value: u64::MAX,
        clock: TimestampClock::DeviceTicks {
            identity: 7,
            units_per_second: None,
        },
    };
    let timestamps = RxPacketTimestamps {
        software: None,
        hardware: Some(stamp),
    };
    let before = b.rx_timestamp_status(server).unwrap();
    // Invalid caller metadata is rejected before changing endpoint time.
    for invalid in [
        RxPacketTimestamps {
            hardware: Some(RxTimestamp {
                clock: TimestampClock::CallerTicks(CallerTimebase::default()),
                ..stamp
            }),
            ..Default::default()
        },
        RxPacketTimestamps {
            software: Some(RxTimestamp {
                clock: TimestampClock::CallerTicks(CallerTimebase {
                    units_per_second: 1_000_000_000,
                    ..Default::default()
                }),
                ..stamp
            }),
            ..Default::default()
        },
        RxPacketTimestamps {
            hardware: Some(RxTimestamp {
                clock: TimestampClock::DeviceTicks {
                    identity: 7,
                    units_per_second: Some(0),
                },
                ..stamp
            }),
            ..Default::default()
        },
    ] {
        assert_eq!(
            b.input_with_timestamps(100, tx.ip, 0, Ipv4Options::default(), bytes, invalid),
            Err(EndpointError::Connection(Error::InvalidArgument))
        );
    }
    let mut corrupt = bytes.to_vec();
    corrupt[16] ^= 1;
    assert_eq!(
        b.input_with_timestamps(2, tx.ip, 0, Ipv4Options::default(), &corrupt, timestamps),
        Ok(InputDisposition::Dropped)
    );
    assert_eq!(
        b.input_with_timestamps(
            3,
            tx.ip,
            0,
            Ipv4Options::default(),
            &bytes[..19],
            timestamps
        ),
        Ok(InputDisposition::Dropped)
    );
    let segment = wire::parse(tx.ip, bytes).unwrap();
    let mut header = segment.header;
    header.destination_port += 1;
    let mut wrong_tuple = [0; 128];
    let len = wire::encode(tx.ip, header, &[], segment.payload, &mut wrong_tuple).unwrap();
    b.input_with_timestamps(
        4,
        tx.ip,
        0,
        Ipv4Options::default(),
        &wrong_tuple[..len],
        timestamps,
    )
    .unwrap();
    assert_eq!(b.rx_timestamp_status(server).unwrap(), before);
    assert_eq!(
        b.peek_rx_timestamps(server, 1),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    crate::allocation_tests::fail_after(0, || {
        b.input_with_timestamps(5, tx.ip, 0, Ipv4Options::default(), bytes, timestamps)
    })
    .unwrap();
    let info = b.peek_rx_timestamps(server, 6).unwrap().unwrap();
    assert_eq!((info.start, info.end, info.timestamps), (0, 6, timestamps));
    assert_eq!(
        b.peek_rx_timestamps(server, 7),
        Err(EndpointError::Connection(Error::InvalidArgument))
    );
    let deadline = b.next_deadline();
    let mut peek = [0; 4];
    for _ in 0..2 {
        assert_eq!(b.peek(server, &mut peek), Ok(4));
        assert_eq!(&peek, b"abcd");
        assert_eq!(
            b.peek_rx_timestamps(server, 4).unwrap().unwrap().timestamps,
            timestamps
        );
    }
    assert_eq!(b.next_deadline(), deadline);
    assert_eq!(b.read(server, &mut peek), Ok(4));
    assert_eq!(b.peek_rx_timestamps(server, 2).unwrap().unwrap().start, 4);
    assert_eq!(b.read(server, &mut peek), Ok(2));
    assert_eq!(b.rx_timestamp_status(server).unwrap().retained_ranges, 0);
    // Matching caller ticks are a software observation, not protocol time input.
    a.write(client, b"gh").unwrap();
    let tx = a.poll_transmit(6, &mut out, 16).unwrap().packet.unwrap();
    let software = RxPacketTimestamps {
        software: Some(RxTimestamp {
            value: 999,
            clock: TimestampClock::CallerTicks(CallerTimebase::default()),
        }),
        hardware: None,
    };
    b.input_with_timestamps(
        6,
        tx.ip,
        0,
        Ipv4Options::default(),
        &out[..tx.len],
        software,
    )
    .unwrap();
    assert_eq!(
        b.peek_rx_timestamps(server, 2).unwrap().unwrap().timestamps,
        software
    );
    b.abort(server).unwrap();
    let charge = b.buffer_bytes();
    b.release(server).unwrap();
    assert!(b.buffer_bytes() < charge);
    assert_eq!(
        b.rx_timestamp_status(server),
        Err(EndpointError::InvalidHandle)
    );
    assert_eq!(
        b.peek_rx_timestamps(server, 1),
        Err(EndpointError::InvalidHandle)
    );
    assert_eq!(b.send_progress(server), Err(EndpointError::InvalidHandle));
    assert_eq!(
        a.send_progress(client).unwrap().acknowledged,
        a.acknowledged(client).unwrap()
    );
}

#[test]
fn listener_rx_timestamp_snapshot_syn_third_ack_parent_change_and_reuse() {
    let (local, remote) = addresses();
    let mut b = Endpoint::new(config(), [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    assert_eq!(b.listener_rx_timestamp_capacity(listener), Ok(0));
    let charge = b.buffer_bytes();
    crate::allocation_tests::fail_after(0, || b.set_listener_rx_timestamp_capacity(listener, 4))
        .unwrap();
    assert_eq!(b.buffer_bytes(), charge); // Policy only: no storage allocated here.
    let ip = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let tuple = Tuple {
        local: remote,
        remote: local,
    };
    let syn_header = wire::Header {
        source_port: local.port(),
        destination_port: remote.port(),
        sequence: u32::MAX - 2,
        acknowledgment: 0,
        flags: wire::SYN,
        window: 64,
        urgent_pointer: 0,
    };
    let mut syn = [0; 128];
    let syn_len = wire::encode(ip, syn_header, &[], b"abc", &mut syn).unwrap();
    let stamps = |value| RxPacketTimestamps {
        software: Some(RxTimestamp {
            value,
            clock: TimestampClock::RealtimeNanoseconds,
        }),
        hardware: Some(RxTimestamp {
            value: value + 10,
            clock: TimestampClock::DeviceTicks {
                identity: 3,
                units_per_second: None,
            },
        }),
    };
    b.input_with_timestamps(1, ip, 0, Ipv4Options::default(), &syn[..syn_len], stamps(1))
        .unwrap();
    let child = b.connection_id(tuple).unwrap();
    assert_eq!(b.state(child), Ok(State::SynReceived));
    assert_eq!(b.rx_timestamp_status(child).unwrap().capacity, 4);
    assert_eq!(b.rx_timestamp_status(child).unwrap().retained_ranges, 1);
    assert_eq!(
        b.peek_rx_timestamps(child, 3),
        Err(EndpointError::Connection(Error::InvalidArgument))
    ); // Hidden until handshake.
    b.set_listener_rx_timestamp_capacity(listener, 1).unwrap();
    let mut out = [0; 128];
    let reply = b.poll_transmit(2, &mut out, 16).unwrap().packet.unwrap();
    let synack = wire::parse(reply.ip, &out[..reply.len]).unwrap().header;
    assert_eq!(synack.acknowledgment, u32::MAX - 1); // Only SYN is acknowledged.
    b.input_with_timestamps(3, ip, 0, Ipv4Options::default(), &syn[..syn_len], stamps(9))
        .unwrap();
    assert_eq!(b.connection_id(tuple), Some(child));
    assert_eq!(b.rx_timestamp_status(child).unwrap().capacity, 4);
    let mut third = [0; 128];
    let third_len = wire::encode(
        ip,
        wire::Header {
            sequence: synack.acknowledgment,
            acknowledgment: synack.sequence.wrapping_add(1),
            flags: wire::ACK,
            ..syn_header
        },
        &[],
        b"XXXde",
        &mut third,
    )
    .unwrap();
    b.input_with_timestamps(
        4,
        ip,
        0,
        Ipv4Options::default(),
        &third[..third_len],
        stamps(2),
    )
    .unwrap();
    assert_eq!(b.state(child), Ok(State::Established));
    assert_eq!(b.rx_timestamp_status(child).unwrap().retained_ranges, 2);
    assert_eq!(
        b.peek_rx_timestamps(child, 3).unwrap().unwrap().timestamps,
        stamps(1)
    );
    assert_eq!(
        b.peek_rx_timestamps(child, 5).unwrap().unwrap().timestamps,
        stamps(2)
    );
    let mut retained = [0; 5];
    assert_eq!(b.peek(child, &mut retained), Ok(5));
    assert_eq!(&retained, b"abcde"); // Completing ACK cannot overwrite original SYN text.
    assert_eq!(b.accept(listener).unwrap(), child);
    // Future children snapshot new policy, even before the adapter can see them.
    let next_header = wire::Header {
        source_port: local.port() + 1,
        sequence: 10,
        ..syn_header
    };
    let n = wire::encode(ip, next_header, &[], b"x", &mut syn).unwrap();
    b.input_with_timestamps(5, ip, 0, Ipv4Options::default(), &syn[..n], stamps(3))
        .unwrap();
    let mut other = local;
    other.set_port(local.port() + 1);
    let next = b
        .connection_id(Tuple {
            local: remote,
            remote: other,
        })
        .unwrap();
    assert_eq!(b.rx_timestamp_status(next).unwrap().capacity, 1);
    b.close_listener(listener).unwrap();
    packets(&mut b, 6); // Existing cleanup handles the unaccepted second child.
    assert_eq!(b.state(child), Ok(State::Established));
    assert_eq!(
        b.peek_rx_timestamps(child, 3).unwrap().unwrap().timestamps,
        stamps(1)
    );
    assert_eq!(
        b.set_listener_rx_timestamp_capacity(listener, 8),
        Err(EndpointError::InvalidHandle)
    );
    let replacement = b.listen(remote, 4).unwrap();
    assert_ne!(replacement, listener);
    assert_eq!(b.listener_rx_timestamp_capacity(replacement), Ok(0));
    let n = wire::encode(
        ip,
        wire::Header {
            source_port: local.port() + 2,
            ..next_header
        },
        &[],
        b"z",
        &mut syn,
    )
    .unwrap();
    b.input_with_timestamps(7, ip, 0, Ipv4Options::default(), &syn[..n], stamps(4))
        .unwrap();
    other.set_port(local.port() + 2);
    let fresh = b
        .connection_id(Tuple {
            local: remote,
            remote: other,
        })
        .unwrap();
    assert_eq!(b.rx_timestamp_status(fresh).unwrap().capacity, 0);
    assert_eq!(b.rx_timestamp_status(fresh).unwrap().retained_ranges, 0);
    let mut read = [0; 5];
    assert_eq!(b.read(child, &mut read), Ok(5));
    assert_eq!(&read, b"abcde");
}

#[test]
fn listener_rx_timestamp_time_wait_replacement_inherits_current_limit() {
    let (mut b, listener, old, ip, header, _) = time_wait_endpoint(config());
    b.set_listener_rx_timestamp_capacity(listener, 3).unwrap();
    let syn = tw_segment(
        ip,
        header,
        header.acknowledgment.wrapping_add(100),
        0,
        wire::SYN,
        None,
    );
    assert_eq!(b.input(4_000, ip, &syn), Ok(InputDisposition::Processed));
    let child = b
        .connection_id(Tuple {
            local: addresses().1,
            remote: addresses().0,
        })
        .unwrap();
    assert_ne!(child, old);
    assert_eq!(b.rx_timestamp_status(old).unwrap().capacity, 0);
    assert_eq!(b.rx_timestamp_status(child).unwrap().capacity, 3);
    b.set_listener_rx_timestamp_capacity(listener, 0).unwrap();
    assert_eq!(b.rx_timestamp_status(child).unwrap().capacity, 3);
}

#[test]
fn listener_rx_timestamp_does_not_override_simultaneous_active_open() {
    let (local, remote) = addresses();
    let (mut a, mut b, listener_b, client_a) = endpoints();
    let listener_a = a.listen(local, 4).unwrap();
    a.set_listener_rx_timestamp_capacity(listener_a, 4).unwrap();
    b.set_listener_rx_timestamp_capacity(listener_b, 3).unwrap();
    let client_b = b.connect(0, remote, local).unwrap();
    a.set_rx_timestamp_capacity(client_a, 1).unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(a.state(client_a), Ok(State::Established));
    assert_eq!(b.state(client_b), Ok(State::Established));
    assert_eq!(a.rx_timestamp_status(client_a).unwrap().capacity, 1);
    assert_eq!(b.rx_timestamp_status(client_b).unwrap().capacity, 0);
}

#[test]
fn checked_external_write_admission_covers_bytes_phases_and_shutdown() {
    let (mut a, mut b, listener, client) = endpoints();
    pump(&mut a, &mut b, 0);
    b.accept(listener).unwrap();
    let request = TxTimestampRequest {
        cookie: 1,
        scheduled: true,
        software_transmit: true,
        hardware_transmit: false,
        acknowledged: true,
    };
    assert_eq!(
        a.check_write_admission(client, None, request),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    a.set_tx_timestamp_capacity(client, 3).unwrap();
    a.set_buffer_capacities(client, 32, 32).unwrap();
    let charged = a.buffer_bytes();
    assert_eq!(a.prepare_write_admission(client, 32, None, request), Ok(32));
    crate::allocation_tests::fail_after(0, || {
        assert_eq!(a.check_write_admission(client, None, request), Ok(32));
        assert_eq!(
            a.write_with_timestamp(client, &[1; 32], false, false, None, request),
            Ok(32)
        );
    });
    assert_eq!(a.buffer_bytes(), charged);
    assert_eq!(
        a.check_write_admission(client, None, request),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    a.shutdown(client).unwrap();
    assert_eq!(
        a.check_write_admission(client, None, request),
        Err(EndpointError::Connection(Error::InvalidState))
    );
}

#[test]
fn pmtud_endpoint_opt_in_tuple_dispatch_path_query_and_link_update() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.connection.mss = 1460;
    cfg.connection.send_capacity = 32_768;
    cfg.connection.receive_capacity = 32_768;
    cfg.connection.pmtud = Some(PmtudConfig::new(1500));
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    b.listen(remote, 4).unwrap();
    let id = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 1);
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 1500);
    a.write(id, &[1; 1460]).unwrap();
    let output = packets(&mut a, 2);
    let (ip, bytes) = &output[0];
    let seq = wire::parse(*ip, bytes).unwrap().header.sequence;
    let tuple = Tuple { local, remote };
    assert!(
        !a.pmtu_feedback(
            3,
            Tuple {
                local: remote,
                remote: local
            },
            seq,
            bytes.len() as u32 + 20,
            20,
            508
        )
        .unwrap()
    );
    assert!(
        a.pmtu_feedback(3, tuple, seq, bytes.len() as u32 + 20, 20, 508)
            .unwrap()
    );
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 508);
    a.set_first_hop_mtu(4, id, 9000).unwrap();
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 508);
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().first_hop_mtu, 9000);
    assert!(a.set_first_hop_mtu(4, id, 67).is_err());
    assert!(
        packets(&mut a, 5)
            .iter()
            .all(|(_, bytes)| bytes.len() + 20 <= 508)
    );
    let (a, _, _, id) = endpoints();
    assert_eq!(a.path_mtu_info(id).unwrap(), None);
}

#[path = "endpoint_time_wait_tests.rs"]
mod time_wait;

#[path = "endpoint_time_wait_record_tests.rs"]
mod time_wait_record;

#[path = "endpoint_handshake_limit_tests.rs"]
mod handshake_limit;

#[path = "endpoint_accept_reset_tests.rs"]
mod accept_reset;

#[path = "shared_payload_tests.rs"]
mod shared_payload;
