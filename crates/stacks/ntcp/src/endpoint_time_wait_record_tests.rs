use super::*;

// Everything a reply can differ in: addresses, bytes, hop limit, DSCP, ECN
// and IPv4 options. Not the owner: a record's ACK leaves on the stateless
// lane.
type Sent = (IpMetadata, Vec<u8>, u8, u8, u8, OutgoingIpv4Options);

// Sequence, acknowledgment, flags, TSval and payload of a segment from the
// peer.
type Case = (u32, u32, u8, Option<u32>, &'static [u8]);

fn sent(endpoint: &mut Endpoint, now: u64) -> Vec<Sent> {
    let mut result = Vec::new();
    for _ in 0..256 {
        let mut bytes = [0; 2048];
        let output = endpoint.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(p) = output.packet {
            result.push((
                p.ip,
                bytes[..p.len].to_vec(),
                p.hop_limit,
                p.dscp,
                p.ecn,
                p.ipv4_options,
            ));
        }
        if !output.more_work {
            return result;
        }
    }
    panic!("output did not quiesce");
}

fn tuple() -> Tuple {
    Tuple {
        local: addresses().1,
        remote: addresses().0,
    }
}

// Two identical endpoints whose connection `b` closed first is in
// TIME-WAIT: the first's application still holds it (the whole connection
// stays), the second's released it (a TIME-WAIT record stays).
struct Twins {
    held: Endpoint,
    record: Endpoint,
    listener: ListenerId,
    ip: IpMetadata,
    h: wire::Header,
    ts: u32,
}

fn twins(cfg: &EndpointConfig, reuse: bool) -> Twins {
    let (held, listener, _, ip, h, ts) = time_wait_endpoint_with(cfg.clone(), reuse);
    let (mut record, _, old, ..) = time_wait_endpoint_with(cfg.clone(), reuse);
    let charge = record.buffer_bytes();
    record.release(old).unwrap();
    assert!(!record.connection_exists(old));
    assert_eq!(record.time_wait_connections(), 1);
    assert!(charge > 0);
    assert_eq!(record.buffer_bytes(), 0);
    Twins {
        held,
        record,
        listener,
        ip,
        h,
        ts,
    }
}

impl Twins {
    // Feeds both the same segment and returns what each answered, after
    // checking they answered alike.
    fn input(&mut self, now: u64, segment: &[u8]) -> Vec<Sent> {
        let held = self.held.input(now, self.ip, segment);
        let record = self.record.input(now, self.ip, segment);
        assert_eq!(held, record);
        let held = sent(&mut self.held, now);
        let record = sent(&mut self.record, now);
        assert_eq!(held, record);
        self.agree(now);
        record
    }

    fn agree(&mut self, now: u64) {
        assert_eq!(self.held.next_deadline(), self.record.next_deadline());
        assert_eq!(
            self.held.time_wait_connections(),
            self.record.time_wait_connections()
        );
        assert_eq!(
            self.held.connect(now, tuple().local, tuple().remote).err(),
            self.record
                .connect(now, tuple().local, tuple().remote)
                .err()
        );
    }

    fn segment(&self, seq: u32, ack: u32, flags: u8, ts: Option<u32>, payload: &[u8]) -> Vec<u8> {
        tw_segment_with_payload(
            self.ip,
            self.h,
            seq,
            ack,
            flags,
            ts.map(|v| (v, 0)),
            payload,
        )
    }
}

// Every kind of segment a TIME-WAIT connection can receive is answered by
// its record exactly as by the connection: the same reply bytes, timer and
// tuple ownership.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4
//= type=test
//# The only thing that can arrive in this state is a retransmission of the
//# remote FIN. Acknowledge it, and restart the 2 MSL timeout.
#[test]
fn a_time_wait_record_answers_every_segment_as_its_connection() {
    use wire::{ACK, FIN, PSH, RST, SYN};
    for timestamps in [false, true] {
        for reuse in [false, true] {
            let mut cfg = config();
            cfg.connection.timestamps = timestamps;
            let probe = twins(&cfg, reuse);
            let (rcv, snd, ts) = (probe.h.acknowledgment, probe.h.sequence, probe.ts);
            let fresh = Some(ts.wrapping_add(1));
            let cases: [Case; 22] = [
                (rcv - 1, snd, FIN | ACK, fresh, b""),
                (rcv - 1, snd, FIN | ACK, Some(ts.wrapping_sub(1)), b""),
                (rcv - 1, snd, FIN | ACK, None, b""),
                (rcv - 4, snd, FIN | ACK, fresh, b"abc"),
                (rcv, snd, ACK, fresh, b""),
                (rcv, snd, ACK, None, b""),
                (rcv, snd.wrapping_add(10), ACK, fresh, b""),
                (rcv, snd.wrapping_sub(1 << 20), ACK, fresh, b""),
                (rcv, snd, ACK | PSH, fresh, b"x"),
                (rcv - 10, snd, ACK, fresh, b"12345"),
                (rcv + 100, snd, ACK, fresh, b"late"),
                (rcv, 0, RST, None, b""),
                (rcv, snd, RST | ACK, fresh, b""),
                (rcv + 1, 0, RST, None, b""),
                (rcv - 1, 0, RST, None, b""),
                (rcv + 100, 0, SYN, fresh, b""),
                (rcv - 100, 0, SYN, None, b""),
                (rcv + 100, 0, SYN, Some(ts.wrapping_sub(1)), b""),
                (rcv + 100, snd, SYN | ACK, fresh, b""),
                (rcv, snd, 0, fresh, b""),
                (rcv, snd, FIN | ACK, fresh, b""),
                (rcv - 1, snd, FIN, fresh, b""),
            ];
            for (case, &(seq, ack, flags, ts, payload)) in cases.iter().enumerate() {
                let mut twins = twins(&cfg, reuse);
                let segment = twins.segment(seq, ack, flags, ts, payload);
                let replies = twins.input(4_000, &segment);
                if case == 0 {
                    // The FIN retransmission is acknowledged and restarts
                    // the timer.
                    assert_eq!(replies.len(), 1);
                    let ack = wire::parse(replies[0].0, &replies[0].1).unwrap().header;
                    assert_eq!(
                        (ack.flags, ack.sequence, ack.acknowledgment),
                        (ACK, snd, rcv)
                    );
                    assert_eq!(
                        twins.record.next_deadline(),
                        Some(4_000 + cfg.connection.time_wait_us)
                    );
                }
                if case == 11 {
                    // An acceptable RST ends TIME-WAIT.
                    assert_eq!(twins.record.time_wait_connections(), 0);
                }
                // A later FIN retransmission, then expiry, agree as well.
                let fin = twins.segment(
                    rcv - 1,
                    snd,
                    FIN | ACK,
                    Some(ts.unwrap_or(0).wrapping_add(2)),
                    b"",
                );
                twins.input(5_000, &fin);
                // Every timer up to the restarted TIME-WAIT's end.
                let end = 5_000 + cfg.connection.time_wait_us;
                while let Some(deadline) = twins.record.next_deadline().filter(|&d| d <= end) {
                    twins.held.on_timeout(deadline, 64).unwrap();
                    twins.record.on_timeout(deadline, 64).unwrap();
                    twins.agree(deadline);
                    assert_eq!(
                        sent(&mut twins.held, deadline),
                        sent(&mut twins.record, deadline)
                    );
                }
                if case == 0 {
                    assert_eq!(twins.record.time_wait_connections(), 0);
                }
            }
        }
    }
}

// Challenge ACKs keep the connection's budget, carried into the record.
//= https://www.rfc-editor.org/rfc/rfc5961#section-7
//= type=test
//# An implementation SHOULD include an ACK throttling mechanism to be
//# conservative.
#[test]
fn a_time_wait_record_keeps_the_challenge_ack_budget() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.connection.challenge_ack_limit = 3;
    let mut twins = twins(&cfg, false);
    let rcv = twins.h.acknowledgment;
    let mut answered = 0;
    for step in 0..6 {
        let syn = twins.segment(rcv + 100, 0, wire::SYN, Some(twins.ts + 1), b"");
        answered += twins.input(4_000 + step, &syn).len();
    }
    assert_eq!(answered, 3);
    let interval = cfg.connection.challenge_ack_interval_us;
    let syn = twins.segment(rcv + 100, 0, wire::SYN, Some(twins.ts + 1), b"");
    assert_eq!(twins.input(4_000 + interval, &syn).len(), 1);
}

// A fresh SYN reopens a record's tuple as it reopens a connection's (RFC
// 6191), and an old duplicate's failure returns the tuple to TIME-WAIT.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.6.1
//= type=test
//# (2)  returns to TIME-WAIT state if the SYN turns out to be an old
//#      duplicate.
#[test]
fn a_time_wait_record_reopens_and_takes_its_tuple_back_as_its_connection() {
    for timestamps in [false, true] {
        let mut cfg = config();
        cfg.connection.timestamps = timestamps;
        let mut twins = twins(&cfg, true);
        let (rcv, snd) = (twins.h.acknowledgment, twins.h.sequence);
        let fresh = timestamps.then_some(twins.ts + 1);
        let syn = twins.segment(rcv + 100, 0, wire::SYN, fresh, b"");
        let synack = twins.input(4_000, &syn);
        assert_eq!(synack.len(), 1);
        let synack = wire::parse(synack[0].0, &synack[0].1).unwrap().header;
        assert_eq!(synack.flags, wire::SYN | wire::ACK);
        // Superseded, the incarnation stays counted until its own expiry.
        assert_eq!(twins.record.time_wait_connections(), 1);
        let rst = twins.segment(rcv + 101, synack.sequence + 1, wire::RST, None, b"");
        twins.input(5_000, &rst);
        assert_eq!(
            twins.record.accept(twins.listener),
            Err(EndpointError::Connection(Error::WouldBlock))
        );
        let fin = twins.segment(
            rcv - 1,
            snd,
            wire::FIN | wire::ACK,
            fresh.map(|v| v + 1),
            b"",
        );
        let ack = twins.input(6_000, &fin);
        assert_eq!(ack.len(), 1);
        assert_eq!(
            wire::parse(ack[0].0, &ack[0].1)
                .unwrap()
                .header
                .acknowledgment,
            rcv
        );
        // A reincarnation that establishes leaves the old record to expire.
        let mut twins = self::twins(&cfg, true);
        let syn = twins.segment(rcv + 100, 0, wire::SYN, fresh, b"");
        let synack = twins.input(4_000, &syn);
        let synack = wire::parse(synack[0].0, &synack[0].1).unwrap().header;
        let ack = twins.segment(rcv + 101, synack.sequence + 1, wire::ACK, fresh, b"");
        twins.input(4_100, &ack);
        let held = twins.held.accept(twins.listener).unwrap();
        let child = twins.record.accept(twins.listener).unwrap();
        assert_eq!(twins.record.state(child), Ok(State::Established));
        assert_eq!(twins.record.time_wait_connections(), 1);
        let expiry = 3_000 + cfg.connection.time_wait_us;
        twins.held.on_timeout(expiry, 64).unwrap();
        twins.record.on_timeout(expiry, 64).unwrap();
        assert_eq!(twins.record.time_wait_connections(), 0);
        assert_eq!(twins.held.time_wait_connections(), 0);
        assert_eq!(twins.held.state(held), twins.record.state(child));
        assert_eq!(twins.record.connection_id(tuple()), Some(child));
    }
}

// `server` closes first, `client` follows; returns both once they are
// released, the server's connection in TIME-WAIT.
fn server_closes(
    a: &mut Endpoint,
    b: &mut Endpoint,
    listener: ListenerId,
    port: u16,
    now: u64,
) -> (ConnectionId, ConnectionId) {
    let local = core::net::SocketAddr::new(addresses().0.ip(), port);
    let client = a.connect(now, local, addresses().1).unwrap();
    pump(a, b, now);
    let server = b.accept(listener).unwrap();
    b.shutdown(server).unwrap();
    pump(a, b, now);
    a.shutdown(client).unwrap();
    pump(a, b, now);
    assert_eq!(b.state(server), Ok(State::TimeWait));
    assert_eq!(a.state(client), Ok(State::Closed));
    b.release(server).unwrap();
    a.release(client).unwrap();
    (client, server)
}

// A server that closes first keeps no connection slot through TIME-WAIT:
// ten times its connection table closes within one TIME-WAIT period.
#[test]
fn server_closed_connections_beyond_the_connection_table_within_time_wait() {
    let mut client_cfg = config();
    client_cfg.max_connections = 64;
    let mut server_cfg = config();
    server_cfg.max_connections = 2;
    let mut a = Endpoint::new(client_cfg, [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(server_cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(addresses().1, 2).unwrap();
    for i in 0..20 {
        server_closes(&mut a, &mut b, listener, 40_000 + i, 1_000 * u64::from(i));
        assert_eq!(b.time_wait_connections(), usize::from(i) + 1);
        assert_eq!(b.buffer_bytes(), 0);
    }
    assert!(b.next_deadline().unwrap() < config().connection.time_wait_us + 1_000);
    b.on_timeout(19_000 + config().connection.time_wait_us, 64)
        .unwrap();
    assert_eq!(b.time_wait_connections(), 0);
}

// Beyond `max_time_wait` records a released connection closes without
// TIME-WAIT, as Linux's beyond tcp_max_tw_buckets: its tuple is unknown and
// a retransmitted FIN draws a reset rather than an ACK.
#[test]
fn time_wait_records_are_bounded_and_overflow_closes() {
    for limit in [0, 2] {
        let mut server_cfg = config();
        server_cfg.max_time_wait = limit;
        let mut a = Endpoint::new(config(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(server_cfg, [2; 32], 0, test_policy).unwrap();
        let listener = b.listen(addresses().1, 2).unwrap();
        for i in 0..4 {
            server_closes(&mut a, &mut b, listener, 40_000 + i, 1_000);
        }
        assert_eq!(b.time_wait_connections(), limit);
        assert_eq!(b.time_wait_overflows(), 4 - limit as u64);
        assert_eq!(b.buffer_bytes(), 0);
        for (port, kept) in [(40_000, limit != 0), (40_003, false)] {
            let ip = IpMetadata {
                source: addresses().0.ip(),
                destination: addresses().1.ip(),
            };
            assert_eq!(b.time_wait_holds_port(addresses().1.port()), limit != 0);
            // Learn the tuple's sequence numbers from a duplicate FIN the
            // record (if any) answers; then the flags tell the two apart.
            let h = wire::Header {
                source_port: addresses().1.port(),
                destination_port: port,
                sequence: 0,
                acknowledgment: 0,
                flags: 0,
                window: 0,
                urgent_pointer: 0,
            };
            let fin = tw_segment(ip, h, 1, 1, wire::FIN | wire::ACK, None);
            b.input(2_000, ip, &fin).unwrap();
            let reply = packets(&mut b, 2_000);
            assert_eq!(reply.len(), 1);
            let flags = wire::parse(reply[0].0, &reply[0].1).unwrap().header.flags;
            assert_eq!(flags & wire::RST != 0, !kept, "port {port}");
        }
    }
}

// Every end of a connection's slot is in `reclaimed_since` once, in order:
// a TIME-WAIT record taking over, a close without TIME-WAIT past the record
// limit, a released closed connection, an abort and a rolled back open.
// Past `max_connections` reclaims it keeps none.
#[test]
fn reclaimed_since_lists_every_reclaim_once() {
    for limit in [0, 2] {
        let mut cfg = config();
        cfg.max_connections = 4;
        cfg.max_time_wait = limit;
        let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
        let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
        let listener = b.listen(addresses().1, 2).unwrap();
        let (mut clients, mut servers) = (Vec::new(), Vec::new());
        for i in 0..4 {
            let (client, server) = server_closes(&mut a, &mut b, listener, 40_000 + i, 1_000);
            clients.push(client);
            servers.push(server);
        }
        pump(&mut a, &mut b, 1_000);
        assert_eq!(b.time_wait_overflows(), 4 - limit as u64);
        let since = |e: &Endpoint, n| e.reclaimed_since(n).map(Iterator::collect::<Vec<_>>);
        assert_eq!(since(&a, 0), Some(clients.clone()));
        assert_eq!(since(&b, 0), Some(servers));
        let local = core::net::SocketAddr::new(addresses().0.ip(), 40_010);
        let aborted = a.connect(2_000, local, addresses().1).unwrap();
        pump(&mut a, &mut b, 2_000);
        a.abort(aborted).unwrap();
        a.release(aborted).unwrap();
        // Its reset holds the slot as long as TIME-WAIT.
        packets(&mut a, 2_000);
        assert!(a.connection_exists(aborted));
        let end = 2_000 + config().connection.time_wait_us;
        a.on_timeout(end, 64).unwrap();
        packets(&mut a, end);
        let local = core::net::SocketAddr::new(addresses().0.ip(), 40_011);
        let cancelled = a.connect(end, local, addresses().1).unwrap();
        a.cancel_unsubmitted_open(cancelled).unwrap();
        assert!(!a.connection_exists(aborted) && !a.connection_exists(cancelled));
        assert_eq!(a.reclaimed(), 6);
        assert_eq!(since(&a, 4), Some(vec![aborted, cancelled]));
        assert_eq!(
            since(&a, 2),
            Some(vec![clients[2], clients[3], aborted, cancelled])
        );
        assert_eq!(since(&a, 1), None);
        assert_eq!(since(&a, 6), Some(Vec::new()));
    }
}

// A port stays bound while a TIME-WAIT record uses it, as in a Linux bind
// bucket.
#[test]
fn a_time_wait_record_holds_its_local_port_until_it_ends() {
    let (mut b, _, old, ..) = time_wait_endpoint(config());
    let port = tuple().local.port();
    assert!(!b.time_wait_holds_port(port));
    b.release(old).unwrap();
    assert!(b.time_wait_holds_port(port));
    assert!(!b.time_wait_holds_port(port + 1));
    b.on_timeout(3_000 + config().connection.time_wait_us, 64)
        .unwrap();
    assert!(!b.time_wait_holds_port(port));
}

// A record whose next TSval would look older across a suspend ends as its
// connection does.
#[test]
fn a_time_wait_record_ends_with_its_connection_across_an_ambiguous_suspend() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.connection.timestamp_granularity = crate::TimestampGranularity::Microseconds;
    // Longer than the 2^31 us the timestamp clock takes to look older.
    cfg.connection.time_wait_us = 3_000_000_000;
    let mut twins = twins(&cfg, false);
    let now = 3_000 + 2_200_000_000;
    twins.held.resume(now, now - 3_000).unwrap();
    twins.record.resume(now, now - 3_000).unwrap();
    assert_eq!(twins.record.time_wait_connections(), 0);
    twins.agree(now);
}
