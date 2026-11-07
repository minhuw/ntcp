//! Endpoint::resume with simulated samples: the logic of a substantiated
//! suspend, not evidence about any physical clock.
extern crate std;

use super::*;
use crate::{CloseReason, TimestampGranularity};
use std::vec::Vec;

const MS_TICK: u64 = 1_000;
const DAY: u64 = 86_400_000_000;
const WRITE: &[u8] = b"after the suspend";

fn config(granularity: TimestampGranularity) -> EndpointConfig {
    let mut config = EndpointConfig {
        max_connections: 8,
        max_listeners: 2,
        ..EndpointConfig::default()
    };
    config.connection.timestamps = true;
    config.connection.timestamp_granularity = granularity;
    config.connection.nagle = false;
    config
}

fn addresses() -> (core::net::SocketAddr, core::net::SocketAddr) {
    (
        "192.0.2.1:40000".parse().unwrap(),
        "192.0.2.2:8080".parse().unwrap(),
    )
}

fn packets(endpoint: &mut Endpoint, now: u64) -> Vec<(IpMetadata, Vec<u8>)> {
    let mut result = Vec::new();
    for _ in 0..64 {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            result.push((packet.ip, bytes[..packet.len].to_vec()));
        }
        if !output.more_work {
            return result;
        }
    }
    panic!("endpoint failed to quiesce");
}

fn pump(a: &mut Endpoint, b: &mut Endpoint, now: u64) {
    for _ in 0..16 {
        let (ab, ba) = (packets(a, now), packets(b, now));
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        for (ip, bytes) in ab {
            b.input(now, ip, &bytes).unwrap();
        }
        for (ip, bytes) in ba {
            a.input(now, ip, &bytes).unwrap();
        }
    }
    panic!("unexpected infinite packet exchange");
}

struct Pair {
    a: Endpoint,
    b: Endpoint,
    listener: ListenerId,
    client: ConnectionId,
    server: ConnectionId,
}

/// An established pair at `START`; `client` last sent a timestamp at `START`.
const START: u64 = 10_000_000;

fn established(granularity: TimestampGranularity) -> Pair {
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config(granularity), [1; 32], START, |_| true).unwrap();
    let mut b = Endpoint::new(config(granularity), [2; 32], START, |_| true).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(START, local, remote).unwrap();
    pump(&mut a, &mut b, START);
    let server = b.accept(listener).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Established);
    Pair {
        a,
        b,
        listener,
        client,
        server,
    }
}

impl Pair {
    /// Both hosts suspend for the whole interval to `now`.
    fn suspend_to(&mut self, now: u64) {
        let suspended = now - self.a.now;
        self.a.resume(now, suspended).unwrap();
        self.b.resume(now, suspended).unwrap();
    }

    /// Data crosses in both directions, with the peer's TSval subject to the
    /// receiver's PAWS check.
    fn transfers(&mut self, now: u64) {
        assert_eq!(self.a.write(self.client, WRITE).unwrap(), WRITE.len());
        assert_eq!(self.b.write(self.server, WRITE).unwrap(), WRITE.len());
        pump(&mut self.a, &mut self.b, now);
        let mut out = [0; 64];
        assert_eq!(self.a.read(self.client, &mut out).unwrap(), WRITE.len());
        assert_eq!(self.b.read(self.server, &mut out).unwrap(), WRITE.len());
        assert_eq!(self.a.state(self.client).unwrap(), State::Established);
    }

    fn new_connection_proceeds(&mut self, now: u64) {
        let (local, remote) = addresses();
        let local = core::net::SocketAddr::new(local.ip(), local.port() + 1);
        let client = self.a.connect(now, local, remote).unwrap();
        pump(&mut self.a, &mut self.b, now);
        assert_eq!(self.a.state(client).unwrap(), State::Established);
        self.b.accept(self.listener).unwrap();
    }
}

fn assert_older_to_a_holder(ticks: u64) {
    assert!(ticks as u32 >= 1 << 31, "{ticks} ticks would appear newer");
}

fn assert_timed_out_silently(pair: &mut Pair, now: u64) {
    assert_eq!(pair.a.state(pair.client).unwrap(), State::Closed);
    assert_eq!(
        pair.a.close_reason(pair.client),
        Ok(Some(CloseReason::TimedOut))
    );
    assert!(packets(&mut pair.a, now).is_empty());
}

#[test]
fn half_range_jump_at_millisecond_cadence_outlives_the_peers_ts_recent() {
    // 2^31 ms is about 24.9 days: every peer has invalidated TS.Recent, and
    // both TSvals of the transfer appear older to the other side.
    let jump = (1 << 31) * MS_TICK;
    assert!(jump > 24 * DAY);
    let mut pair = established(TimestampGranularity::Milliseconds);
    let now = START + jump;
    pair.suspend_to(now);
    assert_eq!(pair.a.close_reason(pair.client), Ok(None));
    pair.transfers(now);
    pair.new_connection_proceeds(now);
}

#[test]
fn half_range_jump_at_microsecond_cadence_ends_a_connection_the_peer_may_hold() {
    // About 36 minutes: well within the 24 days of the peer's TS.Recent.
    let jump = 1 << 31;
    let mut pair = established(TimestampGranularity::Microseconds);
    let now = START + jump;
    pair.a.resume(now, jump).unwrap();
    assert_timed_out_silently(&mut pair, now);
    assert!(matches!(
        pair.a.next_event(),
        Some(Event::Connection(id, events))
            if id == pair.client && events.closed == Some(CloseReason::TimedOut)
    ));
    // The clock itself moved on: nothing is wedged.
    pair.a.on_timeout(now + 1, 8).unwrap();
    pair.b.resume(now, jump).unwrap();
    pair.b.abort(pair.server).unwrap();
    pump(&mut pair.a, &mut pair.b, now + 1);
    pair.new_connection_proceeds(now + 1);
}

#[test]
fn microsecond_cadence_idle_beyond_24_days_continues() {
    let wraps = (24 * DAY >> 32) + 1;
    let jump = (wraps << 32) + (1 << 31);
    assert!(jump > 24 * DAY);
    assert_older_to_a_holder(jump);
    let mut pair = established(TimestampGranularity::Microseconds);
    let now = START + jump;
    pair.suspend_to(now);
    pair.transfers(now);
    pair.new_connection_proceeds(now);
}

#[test]
fn the_24_day_limit_is_inclusive() {
    assert_older_to_a_holder(24 * DAY);
    let mut held = established(TimestampGranularity::Microseconds);
    let now = START + 24 * DAY;
    held.a.resume(now, 24 * DAY).unwrap();
    assert_timed_out_silently(&mut held, now);

    let mut expired = established(TimestampGranularity::Microseconds);
    expired.suspend_to(now + 1);
    expired.transfers(now + 1);
}

#[test]
fn a_tsval_that_wraps_to_newer_continues_at_microsecond_cadence() {
    // Serial order, the only thing a peer can compare, shows a newer value.
    let jump = 1 << 32;
    let mut pair = established(TimestampGranularity::Microseconds);
    let now = START + jump;
    pair.suspend_to(now);
    pair.transfers(now);
}

#[test]
fn awake_time_before_a_short_suspend_counts_towards_the_next_tsval() {
    // 30 minutes awake leave the jump itself far below the half-range; the
    // next TSval still appears older after 10 more minutes asleep.
    let awake = 1_800_000_000;
    let asleep = 600_000_000;
    let mut pair = established(TimestampGranularity::Microseconds);
    let woke = START + awake;
    let now = woke + asleep;
    pair.a.resume(woke, 0).unwrap();
    assert_eq!(pair.a.state(pair.client).unwrap(), State::Established);
    pair.a.resume(now, asleep).unwrap();
    assert_timed_out_silently(&mut pair, now);
}

#[test]
fn a_connection_without_timestamps_ignores_the_serial_order() {
    let mut config = config(TimestampGranularity::Microseconds);
    config.connection.timestamps = false;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config.clone(), [1; 32], START, |_| true).unwrap();
    let mut b = Endpoint::new(config, [2; 32], START, |_| true).unwrap();
    b.listen(remote, 4).unwrap();
    let client = a.connect(START, local, remote).unwrap();
    pump(&mut a, &mut b, START);
    let now = START + (1 << 31);
    // Without timestamps no jump is ambiguous.
    a.resume(now, 1 << 31).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Established);
}

#[test]
fn unsubstantiated_jumps_stay_ambiguous_at_both_cadences() {
    for (granularity, tick) in [
        (TimestampGranularity::Milliseconds, MS_TICK),
        (TimestampGranularity::Microseconds, 1),
    ] {
        let half = (1 << 31) * tick;
        let mut pair = established(granularity);
        let rtt = pair.a.transport_info(pair.client).unwrap().rtt_us;
        let ambiguous = Err(Error::AmbiguousTimeJump.into());
        // No suspend at all, and one that leaves the half-range awake.
        assert_eq!(pair.a.resume(START + half, 0), ambiguous);
        assert_eq!(pair.a.resume(START + 2 * half, half - tick), ambiguous);
        assert_eq!(
            pair.a.on_timeout(START + half, 8),
            Err(Error::AmbiguousTimeJump.into())
        );
        // Rejected samples have no effect, and a later valid one works.
        assert_eq!(pair.a.now, START);
        assert_eq!(pair.a.state(pair.client).unwrap(), State::Established);
        assert_eq!(pair.a.transport_info(pair.client).unwrap().rtt_us, rtt);
        pair.a.resume(START + half, tick).unwrap();
    }
}

#[test]
fn inconsistent_samples_have_no_effect() {
    let mut pair = established(TimestampGranularity::Milliseconds);
    assert_eq!(
        pair.a.resume(START - 1, 0),
        Err(Error::TimeWentBackwards.into())
    );
    assert_eq!(
        pair.a.resume(START + 5, 6),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(pair.a.now, START);
    pair.a.resume(START + 5, 5).unwrap();
    assert_eq!(pair.a.now, START + 5);
    pair.a.resume(START + 5, 0).unwrap();
}

#[test]
fn short_suspend_continues_without_sampling_rtt_across_it() {
    let mut pair = established(TimestampGranularity::Milliseconds);
    let rtt = |pair: &Pair| pair.a.transport_info(pair.client).unwrap().rtt_us;
    let measured = rtt(&pair);
    let sent = START + 1_000;
    assert_eq!(pair.a.write(pair.client, WRITE).unwrap(), WRITE.len());
    let data = packets(&mut pair.a, sent);
    assert_eq!(data.len(), 1);
    // Suspended with the segment in flight, just short of the first RTO.
    let now = sent + 500_000;
    pair.suspend_to(now);
    assert_eq!(pair.a.state(pair.client).unwrap(), State::Established);
    for (ip, bytes) in data {
        pair.b.input(now, ip, &bytes).unwrap();
    }
    // The peer's delayed ACK of a segment sent before the suspend.
    let acked = now + 200_000;
    pair.b.on_timeout(acked, 8).unwrap();
    let ack = packets(&mut pair.b, acked);
    assert_eq!(ack.len(), 1);
    for (ip, bytes) in ack {
        pair.a.input(acked, ip, &bytes).unwrap();
    }
    assert_eq!(rtt(&pair), measured);
    let unacknowledged = pair.a.transport_info(pair.client).unwrap().unacked;
    assert_eq!(unacknowledged, 0);
    // Time after the suspend measures the path again.
    let later = acked + 40_000;
    assert_eq!(pair.a.write(pair.client, WRITE).unwrap(), WRITE.len());
    let data = packets(&mut pair.a, acked);
    for (ip, bytes) in data {
        pair.b.input(later, ip, &bytes).unwrap();
    }
    pair.b.on_timeout(later + 200_000, 8).unwrap();
    pump(&mut pair.a, &mut pair.b, later + 200_000);
    assert_ne!(rtt(&pair), measured);
    let mut out = [0; 64];
    assert_eq!(pair.b.read(pair.server, &mut out).unwrap(), 2 * WRITE.len());
}

#[test]
fn timers_measure_the_suspended_time() {
    // The retransmission timer is real elapsed time: the first service after
    // a suspend longer than it fires it.
    let mut pair = established(TimestampGranularity::Milliseconds);
    assert_eq!(pair.a.write(pair.client, WRITE).unwrap(), WRITE.len());
    let original = packets(&mut pair.a, START);
    assert_eq!(original.len(), 1);
    let now = START + 60_000_000;
    pair.a.resume(now, 60_000_000).unwrap();
    pair.a.on_timeout(now, 8).unwrap();
    let retransmission = packets(&mut pair.a, now);
    assert_eq!(retransmission.len(), 1);
}

#[test]
fn a_reserved_connection_ends_once_its_reservation_is_settled() {
    let mut config = config(TimestampGranularity::Microseconds);
    config.connection.nagle = false;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(config.clone(), [1; 32], START, |_| true).unwrap();
    let mut b = Endpoint::new(config, [2; 32], START, |_| true).unwrap();
    a.enable_output_reservations().unwrap();
    b.listen(remote, 4).unwrap();
    let client = a.connect(START, local, remote).unwrap();
    let mut bytes = [0; 2048];
    for _ in 0..4 {
        let (output, attempt) = a.poll_reserved_transmit(START, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            let packet = (packet.ip, packet.len);
            a.accept_transmit(START, attempt.unwrap()).unwrap();
            b.input(START, packet.0, &bytes[..packet.1]).unwrap();
        }
        for (ip, reply) in packets(&mut b, START) {
            a.input(START, ip, &reply).unwrap();
        }
    }
    assert_eq!(a.state(client).unwrap(), State::Established);
    assert_eq!(a.write(client, WRITE).unwrap(), WRITE.len());
    let (output, attempt) = a.poll_reserved_transmit(START, &mut bytes, 16).unwrap();
    assert!(output.packet.is_some());

    let now = START + (1 << 31);
    a.resume(now, 1 << 31).unwrap();
    assert_eq!(a.state(client).unwrap(), State::Established);
    a.accept_transmit(now, attempt.unwrap()).unwrap();
    // Settled: output stays stopped until the owner's timeout service.
    let (output, _) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
    assert!(output.packet.is_none());
    assert!(a.next_deadline().is_some_and(|deadline| deadline <= now));
    a.on_timeout(now, 8).unwrap();
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::TimedOut)));
}

#[test]
fn time_wait_expires_across_the_suspend_without_a_timeout_error() {
    let mut pair = established(TimestampGranularity::Microseconds);
    pair.a.shutdown(pair.client).unwrap();
    pump(&mut pair.a, &mut pair.b, START);
    pair.b.shutdown(pair.server).unwrap();
    pump(&mut pair.a, &mut pair.b, START);
    assert_eq!(pair.a.state(pair.client).unwrap(), State::TimeWait);
    let now = START + (1 << 31);
    pair.a.resume(now, 1 << 31).unwrap();
    assert_eq!(pair.a.state(pair.client).unwrap(), State::Closed);
    assert_ne!(
        pair.a.close_reason(pair.client),
        Ok(Some(CloseReason::TimedOut))
    );
}
