//! The lifecycle admission gate with simulated time: the logic of the
//! deadline, not evidence about any physical clock or deployment fact.
extern crate std;

use super::*;
use crate::{CallerTimebase, Lifecycle, SourceContinuity};
use core::net::SocketAddr;
use std::vec;
use std::vec::Vec;

const SECOND: u64 = 1_000_000;
const QUIET: u64 = 240 * SECOND;

fn config() -> EndpointConfig {
    let mut config = EndpointConfig {
        max_connections: 8,
        max_listeners: 2,
        ..EndpointConfig::default()
    };
    config.connection.nagle = false;
    config
}

fn addresses() -> (SocketAddr, SocketAddr) {
    (
        "192.0.2.1:40000".parse().unwrap(),
        "192.0.2.2:8080".parse().unwrap(),
    )
}

fn ip() -> IpMetadata {
    IpMetadata {
        source: addresses().1.ip(),
        destination: addresses().0.ip(),
    }
}

// Started at zero on a host just booted, nothing asserted: the full interval.
fn quiet() -> Endpoint {
    Endpoint::new(config(), [1; 32], 0, Lifecycle::default(), |_| true).unwrap()
}

fn segment(flags: u8, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20 + payload.len()];
    let len = wire::encode(
        ip(),
        wire::Header {
            source_port: 1000,
            destination_port,
            sequence: 7,
            acknowledgment: 9,
            flags,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        payload,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}

// Everything a refused attempt could have touched, and the output it leaves.
fn untouched(endpoint: &mut Endpoint, now: u64, free: usize, bytes: usize, isn: (u32, Instant)) {
    assert_eq!(endpoint.free.len(), free);
    assert_eq!(endpoint.buffer_bytes(), bytes);
    assert_eq!((endpoint.isn_clock, endpoint.last_isn_time), isn);
    assert!(endpoint.control.is_empty());
    let mut out = [0; 2048];
    assert_eq!(endpoint.poll_transmit(now, &mut out, 16).unwrap().packet, None);
}

fn snapshot(endpoint: &Endpoint) -> (usize, usize, (u32, Instant)) {
    (
        endpoint.free.len(),
        endpoint.buffer_bytes(),
        (endpoint.isn_clock, endpoint.last_isn_time),
    )
}

type Open = fn(&mut Endpoint, Instant) -> Result<ConnectionId, EndpointError>;

fn opens() -> Vec<Open> {
    vec![
        |e, now| e.connect(now, addresses().0, addresses().1),
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            e.connect_with_options(now, local, remote, options)
        },
        |e, now| {
            let (local, remote) = addresses();
            e.connect_with_source(now, None, remote, |_| Ok(local))
        },
        |e, now| {
            let (local, remote) = addresses();
            e.connect_with_ipv4_options(now, local, remote, OutgoingIpv4Options::default())
        },
        |e, now| {
            let (local, remote) = addresses();
            e.connect_fast_open(now, local, remote, b"early").map(|(id, _)| id)
        },
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            e.connect_fast_open_with_policy(
                now,
                local,
                remote,
                b"early",
                options,
                crate::FastOpenClientPolicy::ApplicationProtected,
            )
            .map(|(id, _)| id)
        },
    ]
}

//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn each_active_factory_is_refused_before_the_deadline_and_admitted_at_it() {
    for open in opens() {
        let mut endpoint = quiet();
        endpoint.enable_fast_open().unwrap();
        let (free, bytes, isn) = snapshot(&endpoint);
        for now in [0, QUIET - 1] {
            assert_eq!(open(&mut endpoint, now), Err(EndpointError::QuietUntil(QUIET)));
            untouched(&mut endpoint, now, free, bytes, isn);
        }
        let id = open(&mut endpoint, QUIET).unwrap();
        assert_eq!(endpoint.state(id).unwrap(), State::SynSent);
        let mut out = [0; 2048];
        let tx = endpoint.poll_transmit(QUIET, &mut out, 16).unwrap();
        let syn = tx.packet.unwrap();
        assert_ne!(wire::parse(syn.ip, &out[..syn.len]).unwrap().header.flags & SYN, 0);
    }
}

#[test]
fn a_refused_attempt_keeps_its_ordinary_error_precedence() {
    let mut endpoint = quiet();
    let (local, _) = addresses();
    // An attempt that could never start reports that, not the deadline.
    assert_eq!(
        endpoint.connect(0, local, "192.0.2.2:0".parse().unwrap()),
        Err(EndpointError::InvalidAddress)
    );
}

//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn a_listener_admits_nothing_and_answers_nothing_until_the_deadline() {
    let mut endpoint = quiet();
    let local = addresses().0;
    let listener = endpoint.listen(local, 4).unwrap();
    endpoint.enable_fast_open().unwrap();
    endpoint.set_listener_fast_open(listener, 1).unwrap();
    let (free, bytes, isn) = snapshot(&endpoint);
    let port = local.port();
    for (syn, now) in [
        (segment(SYN, port, &[]), 0),
        (segment(SYN, port, b"data"), QUIET - 1),
    ] {
        assert_eq!(
            endpoint.input(now, ip(), &syn).unwrap(),
            InputDisposition::Dropped
        );
        untouched(&mut endpoint, now, free, bytes, isn);
    }
    assert_eq!(endpoint.listener_queue_info(listener).unwrap().0, 0);
    // An ACK to a listener would draw a stateless reset.
    endpoint.input(QUIET - 1, ip(), &segment(ACK, port, &[])).unwrap();
    untouched(&mut endpoint, QUIET - 1, free, bytes, isn);

    assert_eq!(
        endpoint.input(QUIET, ip(), &segment(SYN, port, &[])).unwrap(),
        InputDisposition::Processed
    );
    let mut out = [0; 2048];
    let tx = endpoint.poll_transmit(QUIET, &mut out, 16).unwrap().packet.unwrap();
    let flags = wire::parse(tx.ip, &out[..tx.len]).unwrap().header.flags;
    assert_eq!(flags & (SYN | ACK), SYN | ACK);
}

#[test]
fn a_closed_port_draws_a_reset_only_from_the_deadline() {
    let mut endpoint = quiet();
    let (free, bytes, isn) = snapshot(&endpoint);
    for flags in [SYN, ACK, wire::FIN | ACK] {
        endpoint.input(QUIET - 1, ip(), &segment(flags, 4000, &[])).unwrap();
        untouched(&mut endpoint, QUIET - 1, free, bytes, isn);
    }
    assert_eq!(endpoint.control_count, 0);
    endpoint.input(QUIET, ip(), &segment(SYN, 4000, &[])).unwrap();
    let mut out = [0; 2048];
    let tx = endpoint.poll_transmit(QUIET, &mut out, 16).unwrap().packet.unwrap();
    let flags = wire::parse(tx.ip, &out[..tx.len]).unwrap().header.flags;
    assert_ne!(flags & RST, 0);
}

// No TIME-WAIT record can exist before the deadline of its own lifecycle, so
// this raises the deadline over one to reach the factory's own check.
//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn time_wait_reuse_is_refused_before_the_deadline_and_admitted_at_it() {
    let (local, remote) = addresses();
    let mut cfg = config();
    cfg.connection.timestamps = true;
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, crate::SETTLED, |_| true).unwrap();
    cfg.reuse_time_wait = true;
    let mut b = Endpoint::new(cfg, [2; 32], 0, crate::SETTLED, |_| true).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    let exchange = |from: &mut Endpoint, to: &mut Endpoint, now| {
        let mut out = [0; 2048];
        while let Some(tx) = from.poll_transmit(now, &mut out, 16).unwrap().packet {
            to.input(now, tx.ip, &out[..tx.len]).unwrap();
        }
    };
    exchange(&mut a, &mut b, 1_000);
    exchange(&mut b, &mut a, 1_000);
    exchange(&mut a, &mut b, 1_000);
    let server = b.accept(listener).unwrap();
    b.shutdown(server).unwrap();
    exchange(&mut b, &mut a, 2_000);
    exchange(&mut a, &mut b, 2_000);
    a.shutdown(client).unwrap();
    let mut out = [0; 2048];
    let fin = a.poll_transmit(3_000, &mut out, 16).unwrap().packet.unwrap();
    let (last_ts, _) = wire::parse(fin.ip, &out[..fin.len]).unwrap().options.timestamps.unwrap();
    b.input(3_000, fin.ip, &out[..fin.len]).unwrap();
    assert_eq!(b.state(server).unwrap(), State::TimeWait);
    while b.poll_transmit(3_000, &mut out, 16).unwrap().packet.is_some() {}

    let mut options = vec![1, 1, 8, 10];
    options.extend_from_slice(&last_ts.wrapping_add(1).to_be_bytes());
    options.extend_from_slice(&0u32.to_be_bytes());
    let incoming = IpMetadata {
        source: local.ip(),
        destination: remote.ip(),
    };
    let mut syn = vec![0; 20 + options.len()];
    let len = wire::encode(
        incoming,
        wire::Header {
            source_port: local.port(),
            destination_port: remote.port(),
            sequence: 0x7000_0000,
            acknowledgment: 0,
            flags: SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &options,
        &[],
        &mut syn,
    )
    .unwrap();
    syn.truncate(len);

    let now = 4_000;
    b.quiet_until = now + 1;
    let isn = (b.isn_clock, b.last_isn_time);
    assert_eq!(b.input(now, incoming, &syn).unwrap(), InputDisposition::Dropped);
    assert_eq!(b.state(server).unwrap(), State::TimeWait);
    assert_eq!((b.isn_clock, b.last_isn_time), isn);
    assert_eq!(b.poll_transmit(now, &mut out, 16).unwrap().packet, None);

    assert_eq!(b.input(now + 1, incoming, &syn).unwrap(), InputDisposition::Processed);
    let tx = b.poll_transmit(now + 1, &mut out, 16).unwrap().packet.unwrap();
    let flags = wire::parse(tx.ip, &out[..tx.len]).unwrap().header.flags;
    assert_eq!(flags & (SYN | ACK), SYN | ACK);
}

#[test]
fn bind_listen_and_clock_queries_work_throughout() {
    let mut endpoint = quiet();
    let listener = endpoint.listen(addresses().0, 4).unwrap();
    assert_eq!(
        endpoint.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    endpoint.on_timeout(SECOND, 8).unwrap();
    assert_eq!(endpoint.next_deadline(), None);
    assert_eq!(endpoint.quiet_until(SECOND), Some(QUIET));
    assert_eq!(endpoint.quiet_until(QUIET), None);
    endpoint.close_listener(listener).unwrap();
}

//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn deadline_over_boot_age_continuity_and_msl() {
    const START: u64 = 1_000 * SECOND;
    for msl in [120 * SECOND, 255 * SECOND] {
        let interval = 2 * msl;
        let timebase = CallerTimebase {
            max_segment_lifetime_us: msl,
            ..CallerTimebase::default()
        };
        let young = 10 * SECOND;
        let remaining = interval - young;
        let ceased = 30;
        let after_ceased = interval - ceased * SECOND;
        let table = [
            // Unknown boot age counts as a boot at the start.
            (None, SourceContinuity::Unknown, interval),
            (None, SourceContinuity::CeasedFor(ceased), interval),
            (None, SourceContinuity::Never, interval),
            // The boot floor is what is left of 2*MSL since boot.
            (Some(young), SourceContinuity::Unknown, interval),
            (Some(young), SourceContinuity::CeasedFor(ceased), after_ceased.max(remaining)),
            (Some(young), SourceContinuity::Never, remaining),
            // Uptime alone never removes the restart floor.
            (Some(interval), SourceContinuity::Unknown, interval),
            (Some(interval), SourceContinuity::CeasedFor(ceased), after_ceased),
            (Some(interval), SourceContinuity::CeasedFor(interval), 0),
            (Some(interval), SourceContinuity::Never, 0),
        ];
        for (boot_age, continuity, wait) in table {
            let lifecycle = Lifecycle { boot_age, continuity };
            assert_eq!(
                lifecycle.deadline(START, timebase),
                START + wait,
                "{lifecycle:?} msl {msl}"
            );
        }
    }
}

#[test]
fn deadline_counts_in_the_callers_units() {
    let timebase = CallerTimebase {
        units_per_second: 1_000_000_000,
        ..CallerTimebase::default()
    };
    let lifecycle = Lifecycle {
        boot_age: Some(u64::MAX),
        continuity: SourceContinuity::CeasedFor(40),
    };
    assert_eq!(lifecycle.deadline(5, timebase), 5 + 200_000_000_000);
}

#[test]
fn the_latest_fact_over_addresses_is_the_longest_wait() {
    use SourceContinuity::{CeasedFor, Never, Unknown};
    for (a, b, latest) in [
        (Unknown, Never, Unknown),
        (Unknown, CeasedFor(9), Unknown),
        (Never, CeasedFor(9), CeasedFor(9)),
        (CeasedFor(3), CeasedFor(9), CeasedFor(3)),
        (Never, Never, Never),
    ] {
        assert_eq!(a.latest(b), latest);
        assert_eq!(b.latest(a), latest);
    }
}

#[test]
fn a_new_endpoint_is_a_new_lifecycle() {
    let mut first = quiet();
    first.connect(QUIET, addresses().0, addresses().1).unwrap();
    // Losing the connection and TIME-WAIT state starts over from the facts
    // of the new start, whatever the old Endpoint had reached.
    let start = QUIET + SECOND;
    let mut second = Endpoint::new(config(), [2; 32], start, Lifecycle::default(), |_| true).unwrap();
    assert_eq!(
        second.connect(start, addresses().0, addresses().1),
        Err(EndpointError::QuietUntil(start + QUIET))
    );
    second
        .connect(start + QUIET, addresses().0, addresses().1)
        .unwrap();
}

// The public active factories `opens` leaves out, each through its own entry
// point: refused at the deadline's last tick with nothing touched, admitted at
// the deadline and after it.
#[test]
fn every_other_active_factory_is_refused_before_the_deadline_and_admitted_from_it() {
    let others: Vec<Open> = vec![
        |e, now| {
            let (local, remote) = addresses();
            e.connect_with_buffer_capacities(now, local, remote, 4096, 4096)
        },
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            e.connect_with_receive_authority(now, local, remote, options, None)
        },
        |e, now| {
            let (local, remote) = addresses();
            e.connect_fast_open_with_buffer_capacities(now, local, remote, b"early", 4096, 4096)
                .map(|(id, _)| id)
        },
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            e.connect_fast_open_with_options(now, local, remote, b"early", options)
                .map(|(id, _)| id)
        },
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            let cookie = wire::FastOpenCookie::new(&[7; 8]).unwrap();
            e.connect_fast_open_with_server_cookie(now, local, remote, b"early", options, Some(cookie))
                .map(|(id, _)| id)
        },
        |e, now| {
            let (local, remote) = addresses();
            let options = ActiveOpenOptions::from(&config().connection);
            e.connect_fast_open_with_receive_authority(
                now,
                local,
                remote,
                b"early",
                options,
                None,
                crate::FastOpenClientPolicy::RequireCookie,
                None,
            )
            .map(|(id, _)| id)
        },
    ];
    for (index, open) in others.into_iter().enumerate() {
        for admitted_at in [QUIET, QUIET + 1] {
            let mut endpoint = quiet();
            endpoint.enable_fast_open().unwrap();
            let (free, bytes, isn) = snapshot(&endpoint);
            assert_eq!(
                open(&mut endpoint, QUIET - 1),
                Err(EndpointError::QuietUntil(QUIET)),
                "factory {index}"
            );
            untouched(&mut endpoint, QUIET - 1, free, bytes, isn);
            let id = open(&mut endpoint, admitted_at).unwrap();
            assert_eq!(endpoint.state(id).unwrap(), State::SynSent, "factory {index}");
            let mut out = [0; 2048];
            let syn = endpoint.poll_transmit(admitted_at, &mut out, 16).unwrap().packet.unwrap();
            let flags = wire::parse(syn.ip, &out[..syn.len]).unwrap().header.flags;
            assert_eq!(flags & (SYN | ACK), SYN, "factory {index}");
        }
    }
}

// A Fast Open cookie request to a listener is a connection request too: no
// cookie is computed or sent before the deadline, and one is from it.
#[test]
fn a_cookie_request_draws_no_cookie_until_the_deadline() {
    let mut endpoint = quiet();
    let local = addresses().0;
    let listener = endpoint.listen(local, 4).unwrap();
    endpoint.enable_fast_open().unwrap();
    endpoint.set_listener_fast_open(listener, 1).unwrap();
    let (free, bytes, isn) = snapshot(&endpoint);
    let request = || {
        let mut bytes = vec![0; 24];
        let len = wire::encode(
            ip(),
            wire::Header {
                source_port: 1000,
                destination_port: local.port(),
                sequence: 7,
                acknowledgment: 0,
                flags: SYN,
                window: 1024,
                urgent_pointer: 0,
            },
            &[34, 2, 1, 1],
            &[],
            &mut bytes,
        )
        .unwrap();
        bytes.truncate(len);
        bytes
    };
    for now in [0, QUIET - 1] {
        assert_eq!(endpoint.input(now, ip(), &request()).unwrap(), InputDisposition::Dropped);
        untouched(&mut endpoint, now, free, bytes, isn);
    }
    assert_eq!(endpoint.input(QUIET, ip(), &request()).unwrap(), InputDisposition::Processed);
    let mut out = [0; 2048];
    let tx = endpoint.poll_transmit(QUIET, &mut out, 16).unwrap().packet.unwrap();
    let reply = wire::parse(tx.ip, &out[..tx.len]).unwrap();
    assert_eq!(reply.header.flags & (SYN | ACK), SYN | ACK);
    assert!(reply.options.fast_open.is_some_and(|cookie| !cookie.as_bytes().is_empty()));
}

// Quiet time is real elapsed time: a substantiated suspend counts towards it
// like awake time, and moves the deadline neither earlier nor later.
#[test]
fn a_suspend_counts_towards_the_quiet_time() {
    let (local, remote) = addresses();
    let mut short = quiet();
    short.resume(QUIET - 1, QUIET - 1).unwrap();
    assert_eq!(short.connect(QUIET - 1, local, remote), Err(EndpointError::QuietUntil(QUIET)));
    let mut long = quiet();
    long.resume(QUIET, QUIET).unwrap();
    assert_eq!(long.quiet_until(QUIET), None);
    long.connect(QUIET, local, remote).unwrap();
}
