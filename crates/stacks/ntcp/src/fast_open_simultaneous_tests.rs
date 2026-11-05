extern crate std;

use super::*;
use crate::{CallerTimebase, FastOpenClientPolicy, InitialWindow, wire::FastOpenCookie};
use std::{vec, vec::Vec};

type Packet = (IpMetadata, Vec<u8>);

fn poll(e: &mut Endpoint, now: u64, reserved: bool) -> Option<Packet> {
    let mut bytes = [0; 4096];
    let (out, ticket) = if reserved {
        e.poll_reserved_transmit(now, &mut bytes, 128).unwrap()
    } else {
        (e.poll_transmit(now, &mut bytes, 128).unwrap(), None)
    };
    let tx = out.packet?;
    if let Some(ticket) = ticket {
        assert!(e.accept_transmit(now, ticket).unwrap());
    }
    Some((tx.ip, bytes[..tx.len].to_vec()))
}
fn packet(e: &mut Endpoint, now: u64, reserved: bool) -> Packet {
    poll(e, now, reserved).expect("physical packet")
}
fn deliver(e: &mut Endpoint, now: u64, p: &Packet) {
    assert_eq!(
        e.input(now, p.0, &p.1).unwrap(),
        InputDisposition::Processed
    );
}
fn rewrite(p: &Packet, header: wire::Header, options: &[u8], payload: &[u8]) -> Packet {
    let mut bytes = vec![0; 60 + payload.len()];
    let n = wire::encode(p.0, header, options, payload, &mut bytes).unwrap();
    bytes.truncate(n);
    (p.0, bytes)
}
fn pump(a: &mut Endpoint, b: &mut Endpoint, now: u64, reserved: bool) {
    for _ in 0..128 {
        let x = poll(a, now, reserved);
        let y = poll(b, now, reserved);
        if x.is_none() && y.is_none() {
            return;
        }
        if let Some(p) = x {
            deliver(b, now, &p);
        }
        if let Some(p) = y {
            deliver(a, now, &p);
        }
    }
    panic!("exchange did not quiesce");
}
fn endpoint(key: u8, nano: bool, reserved: bool) -> Endpoint {
    let mut e = Endpoint::new(
        EndpointConfig {
            max_connections: 32,
            max_listeners: 4,
            connection: crate::ConnectionConfig {
                mss: 1460,
                initial_window: InitialWindow::Iw10,
                timebase: CallerTimebase {
                    units_per_second: if nano { 1_000_000_000 } else { 1_000_000 },
                    ..Default::default()
                },
                send_capacity: 8192,
                receive_capacity: 2048,
                nagle: false,
                delayed_ack_us: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        [key; 32],
        0,
        |_| true,
    )
    .unwrap();
    e.enable_fast_open().unwrap();
    if reserved {
        e.enable_output_reservations().unwrap();
    }
    e
}
struct Peers {
    a: Endpoint,
    b: Endpoint,
    la: ListenerId,
    lb: ListenerId,
    aa: SocketAddr,
    ba: SocketAddr,
    ca: FastOpenCookie,
    cb: FastOpenCookie,
    reserved: bool,
}
fn warm(
    client: &mut Endpoint,
    server: &mut Endpoint,
    local: SocketAddr,
    remote: SocketAddr,
    listener: ListenerId,
    reserved: bool,
) -> FastOpenCookie {
    let (id, n) = client.connect_fast_open(0, local, remote, &[]).unwrap();
    assert_eq!(n, 0);
    let syn = packet(client, 0, reserved);
    assert!(
        wire::parse(syn.0, &syn.1)
            .unwrap()
            .options
            .fast_open
            .unwrap()
            .as_bytes()
            .is_empty()
    );
    deliver(server, 0, &syn);
    let reply = packet(server, 0, reserved);
    let cookie = wire::parse(reply.0, &reply.1)
        .unwrap()
        .options
        .fast_open
        .unwrap();
    deliver(client, 0, &reply);
    deliver(server, 0, &packet(client, 0, reserved));
    let child = server.accept(listener).unwrap();
    assert_eq!(client.state(id), Ok(State::Established));
    assert_eq!(server.state(child), Ok(State::Established));
    cookie
}
impl Peers {
    fn new(v6: bool, linux: bool, reserved: bool, nano: bool) -> Self {
        let mut a = endpoint(11, nano, reserved);
        let mut b = endpoint(29, nano, reserved);
        #[cfg(feature = "tfo-linux-cookie")]
        if linux {
            a.set_fast_open_cookie_policy(crate::FastOpenCookiePolicy::LinuxSipHash24(
                crate::LinuxSipHash24Key::new([17; 16]),
            ));
            b.set_fast_open_cookie_policy(crate::FastOpenCookiePolicy::LinuxSipHash24(
                crate::LinuxSipHash24Key::new([31; 16]),
            ));
        }
        let _ = linux;
        let aa = SocketAddr::new(
            if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            42000,
        );
        let ba = SocketAddr::new(
            if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
            42001,
        );
        let la = a.listen(SocketAddr::new(aa.ip(), 9000), 16).unwrap();
        let lb = b.listen(SocketAddr::new(ba.ip(), 9001), 16).unwrap();
        a.set_listener_fast_open(la, 4).unwrap();
        b.set_listener_fast_open(lb, 4).unwrap();
        let cb = warm(
            &mut a,
            &mut b,
            SocketAddr::new(aa.ip(), 41000),
            SocketAddr::new(ba.ip(), 9001),
            lb,
            reserved,
        );
        let ca = warm(
            &mut b,
            &mut a,
            SocketAddr::new(ba.ip(), 41001),
            SocketAddr::new(aa.ip(), 9000),
            la,
            reserved,
        );
        assert_ne!(ca, cb);
        Self {
            a,
            b,
            la,
            lb,
            aa,
            ba,
            ca,
            cb,
            reserved,
        }
    }
    fn open(&mut self, now: u64, select_a: bool, select_b: bool) -> (ConnectionId, ConnectionId) {
        self.open_with_peer_options(
            now,
            select_a,
            select_b,
            ActiveOpenOptions::from(&self.b.config.connection),
        )
    }
    fn open_with_peer_options(
        &mut self,
        now: u64,
        select_a: bool,
        select_b: bool,
        peer_options: ActiveOpenOptions,
    ) -> (ConnectionId, ConnectionId) {
        let opts = ActiveOpenOptions::from(&self.a.config.connection);
        // Set the pre-construction ISN clock to exercise real sequence wrap.
        for (e, local, remote) in [
            (&mut self.a, self.aa, self.ba),
            (&mut self.b, self.ba, self.aa),
        ] {
            let tag = e.digest(b"ntcp initial sequence", crate::ScopedTuple::unscoped(Tuple { local, remote }));
            let ticks = (now / e.config.connection.timebase.ticks_from_us(4))
                .saturating_sub(e.last_isn_time / e.config.connection.timebase.ticks_from_us(4))
                .max(1);
            e.isn_clock = (u32::MAX - 4)
                .wrapping_sub(u32::from_be_bytes(tag[..4].try_into().unwrap()))
                .wrapping_sub(ticks as u32);
        }
        let (a, na) = self
            .a
            .connect_fast_open_with_receive_authority(
                now,
                self.aa,
                self.ba,
                b"from-A",
                opts,
                Some(self.cb),
                FastOpenClientPolicy::RequireCookie,
                select_a.then_some(self.la),
            )
            .unwrap();
        let (b, nb) = self
            .b
            .connect_fast_open_with_receive_authority(
                now,
                self.ba,
                self.aa,
                b"from-B",
                peer_options,
                Some(self.ca),
                FastOpenClientPolicy::RequireCookie,
                select_b.then_some(self.lb),
            )
            .unwrap();
        assert_eq!((na, nb), (6, 6));
        for (e, id, selected) in [(&self.a, a, select_a), (&self.b, b, select_b)] {
            let info = e.transport_info(id).unwrap();
            assert_eq!(info.cwnd, info.mss * if selected { 3 } else { 10 });
            assert!(e.slots[id.slot].as_ref().unwrap().fast_open_owner.is_none());
        }
        (a, b)
    }
    fn cross(&mut self, ids: (ConnectionId, ConnectionId), now: u64) -> (Packet, Packet) {
        let sa = packet(&mut self.a, now, self.reserved);
        let sb = packet(&mut self.b, now, self.reserved);
        if let Some(cookie) = wire::parse(sa.0, &sa.1).unwrap().options.fast_open {
            assert_eq!(cookie, self.cb);
        }
        if let Some(cookie) = wire::parse(sb.0, &sb.1).unwrap().options.fast_open {
            assert_eq!(cookie, self.ca);
        }
        deliver(&mut self.b, now, &sa);
        deliver(&mut self.a, now, &sb);
        for (e, id, l) in [(&self.a, ids.0, self.la), (&self.b, ids.1, self.lb)] {
            assert_eq!(e.state(id), Ok(State::SynReceived));
            assert!(!e.slot(id).unwrap().connection.handshake_complete());
            assert!(e.slot(id).unwrap().listener.is_none());
            assert_eq!(e.listener_queue_info(l), Ok((0, 16)));
            assert!(e.listener(l).unwrap().children.is_empty());
        }
        (sa, sb)
    }
    fn complete(
        &mut self,
        ids: (ConnectionId, ConnectionId),
        now: u64,
        mut at_a: Vec<u8>,
        mut at_b: Vec<u8>,
    ) {
        pump(&mut self.a, &mut self.b, now, self.reserved);
        assert_eq!(self.a.state(ids.0), Ok(State::Established));
        assert_eq!(self.b.state(ids.1), Ok(State::Established));
        assert!(self.a.slot(ids.0).unwrap().fast_open_owner.is_none());
        assert!(self.b.slot(ids.1).unwrap().fast_open_owner.is_none());
        let mut buf = [0; 2048];
        if let Ok(n) = self.a.read(ids.0, &mut buf) {
            at_a.extend_from_slice(&buf[..n]);
        }
        if let Ok(n) = self.b.read(ids.1, &mut buf) {
            at_b.extend_from_slice(&buf[..n]);
        }
        assert_eq!(at_a, b"from-B");
        assert_eq!(at_b, b"from-A");
        let more_a: Vec<_> = (0..3000).map(|i| (i % 251) as u8).collect();
        let more_b: Vec<_> = (0..3000).map(|i| (i % 239) as u8).collect();
        assert_eq!(self.a.write(ids.0, &more_a), Ok(more_a.len()));
        assert_eq!(self.b.write(ids.1, &more_b), Ok(more_b.len()));
        let mut got_a = Vec::new();
        let mut got_b = Vec::new();
        for _ in 0..32 {
            pump(&mut self.a, &mut self.b, now, self.reserved);
            if let Ok(n) = self.a.read(ids.0, &mut buf) {
                got_a.extend_from_slice(&buf[..n]);
            }
            if let Ok(n) = self.b.read(ids.1, &mut buf) {
                got_b.extend_from_slice(&buf[..n]);
            }
            if got_a.len() == more_b.len() && got_b.len() == more_a.len() {
                break;
            }
        }
        assert_eq!(got_a, more_b);
        assert_eq!(got_b, more_a);
        pump(&mut self.a, &mut self.b, now, self.reserved);
        assert_eq!(self.a.transport_info(ids.0).unwrap().unacked, 0);
        assert_eq!(self.b.transport_info(ids.1).unwrap().unacked, 0);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.2.2
//= type=test
//= reason=Explicit live local ListenerId selection authorizes only the first acceptable crossing SYN using current finite listener credentials, protected policy and shared pending/reset-debt limits. Active identity, RFC5681 construction, early reads and frozen rejection remain independent of outgoing cookies; local SYN-ACK cookies require actual departure and never train client request provenance. Two actual Endpoint listeners issue asymmetric credentials, and core/native PacketIo and public-fd tests complete both streams through fallback, expiry, wrap, duplicates, loss and reserved output without false connect completion.
//# A special case is simultaneous open where the SYN receiver is a client in SYN-SENT state. The protocol remains the same because [RFC793] already supports both data in the SYN and simultaneous open.
fn simultaneous_independent_authorities_complete_both_streams() {
    for (v6, reserved, nano) in [
        (false, false, false),
        (true, true, true),
        (true, false, false),
        (false, true, true),
    ] {
        for linux in [false, cfg!(feature = "tfo-linux-cookie")] {
            let mut p = Peers::new(v6, linux, reserved, nano);
            let ids = p.open(100, true, true);
            let (sa, sb) = p.cross(ids, 100);
            let mut early_a = [0; 2];
            let mut early_b = [0; 3];
            assert_eq!(p.a.peek(ids.0, &mut early_a), Ok(2));
            assert_eq!(&early_a, b"fr");
            assert_eq!(p.a.read(ids.0, &mut early_a), Ok(2));
            assert_eq!(p.b.read(ids.1, &mut early_b), Ok(3));
            for (e, id, l) in [(&mut p.a, ids.0, p.la), (&mut p.b, ids.1, p.lb)] {
                assert_eq!(e.slot(id).unwrap().fast_open_owner, Some(l));
                let event = e.slot_mut(id).unwrap().connection.take_events();
                assert!(event.readable && !event.connected);
                assert!(e.accept(l).is_err());
                assert!(!e.transport_info(id).unwrap().syn_data_acked);
            }
            // Duplicate SYNs cannot relearn the receive frontier or redeliver.
            deliver(&mut p.a, 100, &sb);
            deliver(&mut p.b, 100, &sa);
            assert_eq!(p.a.readable_bytes(ids.0), Ok(4));
            assert_eq!(p.b.readable_bytes(ids.1), Ok(3));
            let ra = packet(&mut p.a, 100, reserved);
            let rb = packet(&mut p.b, 100, reserved);
            for (r, expected) in [(&ra, p.ca), (&rb, p.cb)] {
                let s = wire::parse(r.0, &r.1).unwrap();
                assert_eq!(s.header.flags & (SYN | ACK), SYN | ACK);
                assert!(s.payload.is_empty());
                assert_eq!(
                    s.options.fast_open,
                    if linux { None } else { Some(expected) }
                );
            }
            // A crossing pure SYN carried our own cookie; it did not replace
            // the independently learned peer credential in the client cache.
            assert_eq!(
                p.a.fast_open
                    .as_ref()
                    .unwrap()
                    .get(100, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip())
                    .unwrap()
                    .cookie,
                p.cb
            );
            deliver(&mut p.a, 100, &rb);
            deliver(&mut p.b, 100, &ra);
            p.complete(ids, 100, early_a.to_vec(), early_b.to_vec());
            std::println!(
                "T4_STREAM {{\"v6\":{v6},\"reserved\":{reserved},\"nano\":{nano},\"linux\":{linux},\"syn_a\":{:?},\"syn_b\":{:?},\"early\":[2,3],\"complete_each\":3006}}",
                p.cb.as_bytes(),
                p.ca.as_bytes()
            );
        }
    }
}

#[test]
fn simultaneous_plain_final_ack_preserves_rejection_and_positive_progress() {
    let mut policy_mismatches = 0;
    for v6 in [false, true] {
        for reserved in [false, true] {
            for accepted_at_b in [0, 4, 6] {
                let now = 100;
                let mut p = Peers::new(v6, false, reserved, false);
                p.a.config.connection.timestamps = true;
                p.b.config.connection.timestamps = true;
                if accepted_at_b == 0 {
                    // An authenticated, data-less passive early child consumes
                    // the same authority quota as the selected active opener.
                    p.b.set_listener_fast_open(p.lb, 1).unwrap();
                    let (pending, n) = p.a.connect_fast_open_with_server_cookie(
                        now,
                        SocketAddr::new(p.aa.ip(), 43000),
                        SocketAddr::new(p.ba.ip(), 9001),
                        &[],
                        ActiveOpenOptions::from(&p.a.config.connection),
                        Some(p.cb),
                    ).unwrap();
                    assert_eq!(n, 0);
                    let syn = packet(&mut p.a, now, reserved);
                    deliver(&mut p.b, now, &syn);
                    let child = p.b.accept(p.lb).unwrap();
                    assert_eq!(p.b.state(child), Ok(State::SynReceived));
                    assert_eq!(p.b.slot(child).unwrap().fast_open_owner, Some(p.lb));
                    packet(&mut p.b, now, reserved); // Lose its SYN-ACK; retain quota.
                    assert_eq!(p.a.state(pending), Ok(State::SynSent));
                }
                let opts = ActiveOpenOptions {
                    receive_capacity: if accepted_at_b == 4 { 4 } else { 2048 },
                    ..ActiveOpenOptions::from(&p.b.config.connection)
                };
                let ids = p.open_with_peer_options(now, true, true, opts);
                let (sa, _) = p.cross(ids, now);
                let iss = wire::parse(sa.0, &sa.1).unwrap().header.sequence;
                assert_eq!(iss, u32::MAX - 4);
                assert_eq!(p.a.readable_bytes(ids.0), Ok(6));
                assert_eq!(p.b.readable_bytes(ids.1), Ok(accepted_at_b));
                let mut prefix = [0; 2];
                assert_eq!(p.a.read(ids.0, &mut prefix), Ok(2));
                assert_eq!(&prefix, b"fr");
                let mut at_a = prefix.to_vec();
                let mut at_b = Vec::new();
                // Only A selects a SYN-ACK. B completes before it selects its
                // own response, and therefore sends a plain final ACK instead.
                let ra = packet(&mut p.a, now, reserved);
                assert_eq!(wire::parse(ra.0, &ra.1).unwrap().header.flags & (SYN | ACK), SYN | ACK);
                deliver(&mut p.b, now, &ra);
                assert_eq!(p.b.state(ids.1), Ok(State::Established));
                let final_ack = packet(&mut p.b, now, reserved);
                let s = wire::parse(final_ack.0, &final_ack.1).unwrap();
                assert_eq!(s.header.flags & (SYN | ACK), ACK);
                assert_eq!(s.header.acknowledgment, iss.wrapping_add(1 + accepted_at_b as u32));
                assert_eq!(s.header.window, opts.receive_capacity as u16 - accepted_at_b as u16);
                assert!(s.payload.is_empty() && s.options.fast_open.is_none());
                let cached = p.a.fast_open.as_ref().unwrap().get(
                    now, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip(),
                ).unwrap();
                assert_eq!(cached.cookie, p.cb);
                assert!(cached.mss.is_some());
                for invalid in ["checksum", "sequence", "beyond-sent", "nonadvancing", "stale-ts"] {
                    let mut header = s.header;
                    let mut options = s.raw_options.to_vec();
                    match invalid {
                        "sequence" => header.sequence = header.sequence.wrapping_sub(1),
                        "beyond-sent" => header.acknowledgment = iss.wrapping_add(8),
                        "nonadvancing" => header.acknowledgment = iss,
                        "stale-ts" => {
                            let (value, echo) = s.options.timestamps.unwrap();
                            options = vec![1, 1, 8, 10];
                            options.extend_from_slice(&value.wrapping_sub(1).to_be_bytes());
                            options.extend_from_slice(&echo.to_be_bytes());
                        }
                        _ => {}
                    }
                    let mut bad = rewrite(&final_ack, header, &options, &[]);
                    if invalid == "checksum" {
                        bad.1[16] ^= 1;
                        p.a.input(now, bad.0, &bad.1).unwrap();
                    } else {
                        deliver(&mut p.a, now, &bad);
                    }
                    assert_eq!(p.a.state(ids.0), Ok(State::SynReceived), "{invalid}");
                    assert!(p.a.can_defer_fast_open_with_server_cookie(
                        now, p.aa.ip(), p.ba, Some(p.cb),
                    ).unwrap(), "{invalid}");
                    // Discard challenges/resets caused by deliberately invalid
                    // input rather than deliver them to the real peer.
                    while poll(&mut p.a, now, reserved).is_some() {}
                }
                deliver(&mut p.a, now, &final_ack);
                assert_eq!(p.a.state(ids.0), Ok(State::Established));
                let allowed = p.a.can_defer_fast_open_with_server_cookie(
                    now, p.aa.ip(), p.ba, Some(p.cb),
                ).unwrap();
                let after = p.a.fast_open.as_ref().unwrap().get(
                    now, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip(),
                ).unwrap();
                assert_eq!((after.cookie, after.mss), (cached.cookie, cached.mss));
                if accepted_at_b == 4 {
                    // The real receiver's zero window blocks residual SYN data
                    // until reading the accepted prefix advertises new space.
                    if let Some(ack) = poll(&mut p.a, now, reserved) {
                        assert!(wire::parse(ack.0, &ack.1).unwrap().payload.is_empty());
                        deliver(&mut p.b, now, &ack);
                    }
                    assert!(poll(&mut p.a, now, reserved).is_none());
                }
                let mut buf = [0; 16];
                for _ in 0..16 {
                    if let Ok(n) = p.a.read(ids.0, &mut buf) {
                        at_a.extend_from_slice(&buf[..n]);
                    }
                    if let Ok(n) = p.b.read(ids.1, &mut buf) {
                        at_b.extend_from_slice(&buf[..n]);
                    }
                    pump(&mut p.a, &mut p.b, now, reserved);
                    if at_a.len() == 6 && at_b.len() == 6 {
                        break;
                    }
                }
                assert_eq!(at_a, b"from-B");
                assert_eq!(at_b, b"from-A");
                assert_eq!(p.a.read(ids.0, &mut buf), Err(Error::WouldBlock.into()));
                assert_eq!(p.b.read(ids.1, &mut buf), Err(Error::WouldBlock.into()));
                assert_eq!(p.a.acknowledged(ids.0), Ok(6));
                assert_eq!(p.b.acknowledged(ids.1), Ok(6));
                let (next, n) = p.a.connect_fast_open_with_server_cookie(
                    now, SocketAddr::new(p.aa.ip(), 42002), p.ba, b"next",
                    ActiveOpenOptions::from(&p.a.config.connection), Some(p.cb),
                ).unwrap();
                assert_eq!(p.a.state(next), Ok(State::SynSent));
                let next_syn = packet(&mut p.a, now, reserved);
                let next_syn = wire::parse(next_syn.0, &next_syn.1).unwrap();
                assert_eq!(next_syn.header.flags & (SYN | ACK), SYN);
                assert_eq!(next_syn.payload.len(), n);
                let expected_allowed = accepted_at_b != 0;
                policy_mismatches += usize::from(
                    allowed != expected_allowed
                        || n != if expected_allowed { 4 } else { 0 }
                        || next_syn.options.fast_open.is_some() != expected_allowed,
                );
                std::println!(
                    "T4_FINAL_ACK_ORDER {{\"v6\":{v6},\"reserved\":{reserved},\"accepted_at_b\":{accepted_at_b},\"ack\":{},\"expected_defer\":{expected_allowed},\"actual_defer\":{allowed},\"next_accepted\":{n},\"next_cookie\":{},\"cache_unchanged\":true,\"invalid_guards\":5,\"delivered_each\":6,\"rto_serviced\":false}}",
                    s.header.acknowledgment, next_syn.options.fast_open.is_some(),
                );
            }
        }
    }
    assert_eq!(policy_mismatches, 0, "validated final ACK must preserve SYN-data rejection evidence");
}

#[test]
fn simultaneous_rejection_is_frozen_and_other_direction_survives() {
    for mode in [
        "none",
        "disabled",
        "revoked",
        "expired",
        "wrong-codec",
        "outgoing-only",
        "quota",
        "stale",
        "malformed",
    ] {
        let mut p = Peers::new(false, false, mode == "quota", false);
        let mut now = 100;
        if mode == "expired" {
            now = crate::fast_open::LIFETIME_US * 2;
        }
        if mode == "quota" {
            p.a.set_listener_fast_open(p.la, 1).unwrap();
            let opts = ActiveOpenOptions::from(&p.b.config.connection);
            let (pending, _) =
                p.b.connect_fast_open_with_server_cookie(
                    now,
                    SocketAddr::new(p.ba.ip(), 43000),
                    SocketAddr::new(p.aa.ip(), 9000),
                    &[],
                    opts,
                    Some(p.ca),
                )
                .unwrap();
            let syn = packet(&mut p.b, now, p.reserved);
            deliver(&mut p.a, now, &syn);
            let child = p.a.accept(p.la).unwrap();
            assert_eq!(p.a.slot(child).unwrap().fast_open_owner, Some(p.la));
            packet(&mut p.a, now, p.reserved); // Lost passive SYN-ACK keeps its quota.
            assert_eq!(p.b.state(pending), Ok(State::SynSent));
        }
        let ids = p.open(now, mode != "none", true);
        if mode == "disabled" {
            p.a.set_listener_fast_open(p.la, 0).unwrap();
        }
        if mode == "revoked" {
            p.a.set_fast_open_hmac_key([88; 32]);
        }
        if mode == "stale" {
            p.a.close_listener(p.la).unwrap();
            p.a.cleanup_one();
            let replacement = p.a.listen(SocketAddr::new(p.aa.ip(), 9000), 16).unwrap();
            assert_ne!(replacement, p.la);
            p.a.set_listener_fast_open(replacement, 4).unwrap();
        }
        let sa = packet(&mut p.a, now, p.reserved);
        let mut sb = packet(&mut p.b, now, p.reserved);
        if ["wrong-codec", "outgoing-only", "malformed"].contains(&mode) {
            let syn = wire::parse(sb.0, &sb.1).unwrap();
            let mut raw = syn.raw_options.to_vec();
            let cookie = if mode == "outgoing-only" {
                p.cb.as_bytes()
            } else {
                &[1, 2, 3, 4]
            };
            raw.clear();
            raw.extend_from_slice(&[2, 4, 5, 180, 34, (cookie.len() + 2) as u8]);
            raw.extend_from_slice(cookie);
            while raw.len() % 4 != 0 {
                raw.push(1);
            }
            // Keep negotiated timestamps for the subsequent real SYN-ACK.
            if let Some((value, echo)) = syn.options.timestamps {
                raw.extend_from_slice(&[1, 1, 8, 10]);
                raw.extend_from_slice(&value.to_be_bytes());
                raw.extend_from_slice(&echo.to_be_bytes());
            }
            sb = rewrite(&sb, syn.header, &raw, syn.payload);
            if mode == "malformed" {
                // A fully framed data offset, with an ignored malformed Kind34.
                let at =
                    sb.1.iter()
                        .enumerate()
                        .skip(20)
                        .find(|(_, x)| **x == 34)
                        .unwrap()
                        .0;
                sb.1[at + 1] = 1;
                let ip = sb.0;
                sb.1[16..18].fill(0);
                let sum = wire::checksum(ip, &sb.1).unwrap();
                sb.1[16..18].copy_from_slice(&sum.to_be_bytes());
            }
        }
        deliver(&mut p.a, now, &sb);
        deliver(&mut p.b, now, &sa);
        assert_eq!(p.a.readable_bytes(ids.0), Ok(0), "{mode}");
        // Expiry affects both independent credentials; all other failures are local.
        let valid_b = mode != "expired";
        assert_eq!(
            p.b.readable_bytes(ids.1),
            Ok(if valid_b { 6 } else { 0 }),
            "{mode}"
        );
        if mode != "none" && mode != "stale" {
            p.a.set_listener_fast_open(p.la, 4).unwrap();
            p.a.set_listener_fast_open_early_data_policy(
                p.la,
                crate::FastOpenEarlyDataPolicy::ApplicationProtected,
            )
            .unwrap();
        }
        // Neither a changed policy nor the original valid cookie upgrades the
        // first accepted SYN's rejection.
        let original = wire::parse(sb.0, &sb.1).unwrap();
        let mut raw = vec![34, (p.ca.as_bytes().len() + 2) as u8];
        raw.extend_from_slice(p.ca.as_bytes());
        while raw.len() % 4 != 0 {
            raw.push(1);
        }
        if let Some((value, echo)) = original.options.timestamps {
            raw.extend_from_slice(&[1, 1, 8, 10]);
            raw.extend_from_slice(&value.to_be_bytes());
            raw.extend_from_slice(&echo.to_be_bytes());
        }
        deliver(
            &mut p.a,
            now,
            &rewrite(&sb, original.header, &raw, b"forged"),
        );
        assert_eq!(p.a.readable_bytes(ids.0), Ok(0));
        p.complete(ids, now, vec![], vec![]);
        std::println!(
            "T4_FALLBACK {{\"cause\":\"{mode}\",\"early_b\":{valid_b},\"complete_each\":3006}}"
        );
    }
}

#[test]
fn simultaneous_protected_and_mixed_policies_are_independent() {
    for mask in 0..4 {
        let mut p = Peers::new(false, false, mask == 3, false);
        for (e, listener, protected) in [
            (&mut p.a, p.la, mask & 1 != 0),
            (&mut p.b, p.lb, mask & 2 != 0),
        ] {
            if protected {
                e.set_listener_fast_open_early_data_policy(
                    listener,
                    crate::FastOpenEarlyDataPolicy::ApplicationProtected,
                )
                .unwrap();
            }
        }
        let opts = ActiveOpenOptions::from(&p.a.config.connection);
        let (a, _) =
            p.a.connect_fast_open_with_receive_authority(
                100,
                p.aa,
                p.ba,
                b"from-A",
                opts,
                None,
                if mask & 2 != 0 {
                    FastOpenClientPolicy::ApplicationProtected
                } else {
                    FastOpenClientPolicy::RequireCookie
                },
                Some(p.la),
            )
            .unwrap();
        let (b, _) =
            p.b.connect_fast_open_with_receive_authority(
                100,
                p.ba,
                p.aa,
                b"from-B",
                opts,
                None,
                if mask & 1 != 0 {
                    FastOpenClientPolicy::ApplicationProtected
                } else {
                    FastOpenClientPolicy::RequireCookie
                },
                Some(p.lb),
            )
            .unwrap();
        p.cross((a, b), 100);
        assert_eq!(p.a.readable_bytes(a), Ok(6));
        assert_eq!(p.b.readable_bytes(b), Ok(6));
        p.complete((a, b), 100, vec![], vec![]);
    }
}

#[test]
fn simultaneous_first_response_departure_and_genuine_rto_provenance() {
    for reserved in [false, true] {
        // Peer SYN arrives before our original SYN is selected. Our first
        // physical packet is a data-free response with a local cookie.
        let mut p = Peers::new(false, false, reserved, false);
        let ids = p.open(100, true, true);
        let sb = packet(&mut p.b, 100, reserved);
        deliver(&mut p.a, 100, &sb);
        assert_eq!(p.a.readable_bytes(ids.0), Ok(6));
        let ra = packet(&mut p.a, 100, reserved);
        let parsed = wire::parse(ra.0, &ra.1).unwrap();
        assert_eq!(parsed.options.fast_open, Some(p.ca));
        assert!(parsed.payload.is_empty());
        deliver(&mut p.b, 100, &ra);
        p.complete(ids, 100, vec![], vec![]);

        // An actually transmitted request trains cooldown on its first RTO,
        // but does not suppress the independent first local response cookie.
        let mut p = Peers::new(false, false, reserved, false);
        let ids = p.open(100, true, true);
        let sa = packet(&mut p.a, 100, reserved);
        let sb = packet(&mut p.b, 100, reserved);
        let now =
            p.a.next_deadline()
                .unwrap()
                .max(p.b.next_deadline().unwrap());
        p.a.on_timeout(now, 128).unwrap();
        p.b.on_timeout(now, 128).unwrap();
        for e in [&mut p.a, &mut p.b] {
            let retry = packet(e, now, reserved);
            let s = wire::parse(retry.0, &retry.1).unwrap();
            assert!(s.options.fast_open.is_none() && s.payload.is_empty());
        }
        deliver(&mut p.a, now, &sb);
        deliver(&mut p.b, now, &sa);
        assert_eq!(p.a.readable_bytes(ids.0), Ok(6));
        let ra = packet(&mut p.a, now, reserved);
        let rb = packet(&mut p.b, now, reserved);
        assert_eq!(
            wire::parse(ra.0, &ra.1).unwrap().options.fast_open,
            Some(p.ca)
        );
        assert_eq!(
            wire::parse(rb.0, &rb.1).unwrap().options.fast_open,
            Some(p.cb)
        );
        // Drop both first SYN-ACKs and retransmit the original peer SYNs.
        deliver(&mut p.a, now, &sb);
        deliver(&mut p.b, now, &sa);
        for e in [&mut p.a, &mut p.b] {
            let retry = packet(e, now, reserved);
            assert!(
                wire::parse(retry.0, &retry.1)
                    .unwrap()
                    .options
                    .fast_open
                    .is_none()
            );
        }
        let later =
            p.a.next_deadline()
                .unwrap()
                .max(p.b.next_deadline().unwrap());
        p.a.on_timeout(later, 128).unwrap();
        p.b.on_timeout(later, 128).unwrap();
        p.complete(ids, later, vec![], vec![]);
    }
}

#[test]
fn simultaneous_held_response_survives_revocation_and_only_commit_consumes_cookie() {
    let mut p = Peers::new(false, false, true, false);
    let ids = p.open(100, true, true);
    let sa = packet(&mut p.a, 100, true);
    let sb = packet(&mut p.b, 100, true);
    let mut bytes = [0; 4096];
    // Held response output must reject ingress without changing the already
    // committed receive admission or publishing ACK departure diagnostics.
    deliver(&mut p.b, 100, &sa);
    let (out, ticket) =
        p.b.poll_reserved_transmit_for(100, ids.1, &mut bytes, 128)
            .unwrap();
    let tx = out.packet.unwrap();
    let response = (tx.ip, bytes[..tx.len].to_vec());
    let ticket = ticket.unwrap();
    assert_eq!(
        p.b.input(100, sa.0, &sa.1),
        Err(EndpointError::OutputReserved)
    );
    assert!(!p.b.transport_info(ids.1).unwrap().syn_data_acked);
    p.b.reject_unsubmitted(ticket).unwrap();
    assert_eq!(p.b.accept_transmit(100, ticket), Ok(false));
    let (out, ticket) =
        p.b.poll_reserved_transmit_for(100, ids.1, &mut bytes, 128)
            .unwrap();
    let tx = out.packet.unwrap();
    let retry = (tx.ip, bytes[..tx.len].to_vec());
    let first = wire::parse(response.0, &response.1).unwrap();
    let second = wire::parse(retry.0, &retry.1).unwrap();
    assert_eq!(first.header, second.header);
    assert_eq!(first.options.fast_open, second.options.fast_open);
    let response = retry;
    let ticket = ticket.unwrap();
    p.b.set_fast_open_hmac_key([99; 32]);
    p.b.close_listener(p.lb).unwrap();
    assert!(p.b.accept_transmit(100, ticket).unwrap());
    assert_eq!(p.b.readable_bytes(ids.1), Ok(6));
    deliver(&mut p.a, 100, &sb);
    deliver(&mut p.a, 100, &response);
    p.complete(ids, 100, vec![], vec![]);
}

#[test]
fn simultaneous_active_reset_debt_shared_quota_and_generation() {
    let mut p = Peers::new(false, false, false, false);
    p.a.set_listener_fast_open(p.la, 1).unwrap();
    let ids = p.open(100, true, true);
    let (_, sb) = p.cross(ids, 100);
    let s = wire::parse(sb.0, &sb.1).unwrap();
    let next = s.header.sequence.wrapping_add(7);
    let header = wire::Header {
        sequence: next.wrapping_add(1),
        flags: RST,
        ..s.header
    };
    deliver(&mut p.a, 100, &rewrite(&sb, header, &[], &[]));
    assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
    assert_eq!(p.a.listener(p.la).unwrap().reset_debt, 0);
    assert_eq!(p.a.slot(ids.0).unwrap().fast_open_owner, Some(p.la));
    let mut buf = [0; 6];
    assert_eq!(p.a.read(ids.0, &mut buf), Ok(6));
    assert_eq!(p.a.slot(ids.0).unwrap().fast_open_owner, Some(p.la));
    deliver(
        &mut p.a,
        100,
        &rewrite(
            &sb,
            wire::Header {
                sequence: next,
                ..header
            },
            &[],
            &[],
        ),
    );
    assert_eq!(p.a.state(ids.0), Ok(State::Closed));
    assert_eq!(p.a.close_reason(ids.0), Ok(Some(crate::CloseReason::Reset)));
    assert_eq!(p.a.listener(p.la).unwrap().reset_debt, 1);
    assert!(p.a.slot(ids.0).unwrap().fast_open_owner.is_none());
    let expiry = p.a.listener(p.la).unwrap().reset_debt_expiry.unwrap();
    // An actual passive request shares debt left by the active opener.
    packet(&mut p.b, 100, false); // Drop the other active opener's SYN-ACK.
    let opts = ActiveOpenOptions::from(&p.b.config.connection);
    let (_, _) =
        p.b.connect_fast_open_with_server_cookie(
            100,
            SocketAddr::new(p.ba.ip(), 43000),
            SocketAddr::new(p.aa.ip(), 9000),
            b"blocked",
            opts,
            Some(p.ca),
        )
        .unwrap();
    let pending = packet(&mut p.b, 100, false);
    deliver(&mut p.a, 100, &pending);
    assert!(p.a.accept(p.la).is_err());
    assert_eq!(p.a.listener(p.la).unwrap().reset_debt_expiry, Some(expiry));
    assert_eq!(
        p.a.listeners[p.la.slot]
            .as_mut()
            .unwrap()
            .reset_debt(expiry),
        0
    );
    p.a.close_listener(p.la).unwrap();
    while p.a.listeners[p.la.slot].is_some() {
        p.a.cleanup_one();
    }
    let new = p.a.listen(SocketAddr::new(p.aa.ip(), 9000), 4).unwrap();
    assert_ne!(new, p.la);
    assert_eq!(p.a.listener(new).unwrap().reset_debt, 0);
    assert!(
        p.a.validate_fast_open_receive_authority(p.la, p.aa.ip())
            .is_err()
    );
}

#[test]
fn simultaneous_dataless_admission_and_ordinary_selected_open() {
    let mut p = Peers::new(false, false, false, false);
    let opts = ActiveOpenOptions::from(&p.a.config.connection);
    let a =
        p.a.connect_with_receive_authority(100, p.aa, p.ba, opts, Some(p.la))
            .unwrap();
    let (b, n) =
        p.b.connect_fast_open_with_receive_authority(
            100,
            p.ba,
            p.aa,
            &[],
            opts,
            Some(p.ca),
            FastOpenClientPolicy::RequireCookie,
            Some(p.lb),
        )
        .unwrap();
    assert_eq!(n, 0);
    let sa = packet(&mut p.a, 100, false);
    let sb = packet(&mut p.b, 100, false);
    deliver(&mut p.a, 100, &sb);
    deliver(&mut p.b, 100, &sa);
    assert_eq!(p.a.slot(a).unwrap().fast_open_owner, Some(p.la));
    assert_eq!(p.a.readable_bytes(a), Ok(0));
    assert_eq!(p.a.peek(a, &mut [0; 1]), Err(Error::WouldBlock.into()));
    assert!(p.b.slot(b).unwrap().fast_open_owner.is_none());
    pump(&mut p.a, &mut p.b, 100, false);
    assert!(p.a.slot(a).unwrap().fast_open_owner.is_none());
    assert_eq!(p.a.write(a, b"from-A"), Ok(6));
    assert_eq!(p.b.write(b, b"from-B"), Ok(6));
    p.complete((a, b), 100, vec![], vec![]);
    let wrong = p.a.listen("192.0.2.8:9008".parse().unwrap(), 4).unwrap();
    assert!(
        p.a.validate_fast_open_receive_authority(wrong, p.aa.ip())
            .is_err()
    );
    let wildcard = p.a.listen("0.0.0.0:9009".parse().unwrap(), 4).unwrap();
    assert!(
        p.a.validate_fast_open_receive_authority(wildcard, p.aa.ip())
            .is_ok()
    );
    assert!(
        p.a.validate_fast_open_receive_authority(wildcard, "2001:db8::1".parse().unwrap())
            .is_err()
    );
}

#[test]
fn simultaneous_selected_authority_defers_ordinary_syn_text_and_controls() {
    for reserved in [false, true] {
        for authority_state in ["enabled", "disabled", "stale"] {
            for fin in [false, true] {
                let mut p = Peers::new(false, false, reserved, false);
                let opts = ActiveOpenOptions::from(&p.a.config.connection);
                let a = p.a.connect_with_receive_authority(
                    100, p.aa, p.ba, opts, Some(p.la),
                ).unwrap();
                let b = p.b.connect_with_receive_authority(
                    100, p.ba, p.aa, opts, None,
                ).unwrap();
                match authority_state {
                    "disabled" => p.a.set_listener_fast_open(p.la, 0).unwrap(),
                    "stale" => {
                        p.a.close_listener(p.la).unwrap();
                        while p.a.listeners[p.la.slot].is_some() {
                            p.a.cleanup_one();
                        }
                        let replacement = p.a.listen(SocketAddr::new(p.aa.ip(), 9000), 16).unwrap();
                        assert_ne!(replacement, p.la);
                        p.a.set_listener_fast_open(replacement, 4).unwrap();
                    }
                    _ => {}
                }
                let sa = packet(&mut p.a, 100, reserved);
                let sb = packet(&mut p.b, 100, reserved);
                let s = wire::parse(sb.0, &sb.1).unwrap();
                assert!(s.options.fast_open.is_none());
                let text = rewrite(&sb, wire::Header {
                    flags: s.header.flags | wire::PSH | wire::URG | if fin { wire::FIN } else { 0 },
                    urgent_pointer: 4,
                    ..s.header
                }, s.raw_options, b"abc");
                while p.a.next_event().is_some() {}
                deliver(&mut p.a, 100, &text);
                assert_eq!(p.a.state(a), Ok(State::SynReceived));
                assert_eq!(p.a.readable_bytes(a), Ok(0));
                assert_eq!(p.a.urgent_remaining(a), Ok(0));
                assert_eq!(p.a.read(a, &mut [0; 8]), Err(Error::WouldBlock.into()));
                assert!(p.a.slot(a).unwrap().fast_open_owner.is_none());
                assert!(p.a.next_event().is_none());
                // A retry cannot replace the deferred prefix or its controls.
                deliver(&mut p.a, 100, &rewrite(&sb, s.header, s.raw_options, b"BAD"));
                let response = packet(&mut p.a, 100, reserved);
                let r = wire::parse(response.0, &response.1).unwrap();
                assert_eq!(r.header.acknowledgment, s.header.sequence.wrapping_add(1));
                deliver(&mut p.b, 100, &sa);
                let peer_response = packet(&mut p.b, 100, reserved);
                // A real SYN-ACK completes the handshake without retransmitting text.
                deliver(&mut p.a, 100, &peer_response);
                assert!(p.a.slot(a).unwrap().connection.handshake_complete());
                assert_eq!(p.b.state(b), Ok(State::SynReceived));
                let mut connected = false;
                let mut pushed = false;
                let mut urgent = None;
                let mut half_closed = false;
                while let Some(event) = p.a.next_event() {
                    if let Event::Connection(id, e) = event {
                        assert_eq!(id, a);
                        connected |= e.connected;
                        pushed |= e.pushed;
                        urgent = urgent.or(e.urgent);
                        half_closed |= e.half_closed;
                    }
                }
                assert!(connected && pushed);
                assert_eq!(urgent, Some(3));
                assert_eq!(half_closed, fin);
                let mut out = [0; 8];
                assert_eq!(p.a.read(a, &mut out), Ok(3));
                assert_eq!(&out[..3], b"abc");
                assert_eq!(p.a.read(a, &mut out), if fin { Ok(0) } else { Err(Error::WouldBlock.into()) });
            }
        }
    }
}

#[test]
fn simultaneous_clipped_prefix_metadata_duplicate_and_window_repair() {
    let mut p = Peers::new(false, false, true, true);
    let opts = ActiveOpenOptions {
        receive_capacity: 4,
        ..ActiveOpenOptions::from(&p.a.config.connection)
    };
    let (a, _) =
        p.a.connect_fast_open_with_receive_authority(
            100,
            p.aa,
            p.ba,
            b"from-A",
            opts,
            None,
            FastOpenClientPolicy::RequireCookie,
            Some(p.la),
        )
        .unwrap();
    let (b, _) =
        p.b.connect_fast_open_with_receive_authority(
            100,
            p.ba,
            p.aa,
            b"from-B",
            opts,
            None,
            FastOpenClientPolicy::RequireCookie,
            Some(p.lb),
        )
        .unwrap();
    p.a.set_rx_timestamp_capacity(a, 8).unwrap();
    p.b.set_rx_timestamp_capacity(b, 8).unwrap();
    let sa = packet(&mut p.a, 100, true);
    let sb = packet(&mut p.b, 100, true);
    let stamp = crate::RxTimestamp {
        value: 123,
        clock: crate::TimestampClock::RealtimeNanoseconds,
    };
    let metadata = crate::RxPacketMetadata {
        timestamps: crate::RxPacketTimestamps {
            software: Some(stamp),
            ..Default::default()
        },
        tcp_segment_size: None,
    };
    for (e, id, incoming) in [(&mut p.a, a, &sb), (&mut p.b, b, &sa)] {
        let s = wire::parse(incoming.0, &incoming.1).unwrap();
        let flagged = rewrite(
            incoming,
            wire::Header {
                flags: s.header.flags | wire::PSH | wire::URG | wire::FIN,
                urgent_pointer: 5,
                ..s.header
            },
            s.raw_options,
            s.payload,
        );
        while e.next_event().is_some() {}
        e.input_with_metadata(
            100,
            flagged.0,
            0,
            Ipv4Options::default(),
            &flagged.1,
            metadata,
        )
        .unwrap();
        assert_eq!(e.readable_bytes(id), Ok(4));
        assert_eq!(e.state(id), Ok(State::SynReceived));
        let mut urgent = None;
        while let Some(event) = e.next_event() {
            if let Event::Connection(event_id, events) = event {
                assert_eq!(event_id, id);
                assert!(!events.connected);
                urgent = urgent.or(events.urgent);
            }
        }
        assert_eq!(urgent, Some(4));
        assert_eq!(
            e.peek_rx_timestamps(id, 2)
                .unwrap()
                .unwrap()
                .timestamps
                .software,
            Some(stamp)
        );
        let mut prefix = [0; 2];
        assert_eq!(e.read(id, &mut prefix), Ok(2));
        assert_eq!(&prefix, b"fr");
        assert_eq!(e.urgent_remaining(id), Ok(2));
        // Duplicate changes payload and flags, but keeps the same first SYN.
        let altered = rewrite(incoming, s.header, s.raw_options, b"BADBAD");
        deliver(e, 100, &altered);
        assert_eq!(e.readable_bytes(id), Ok(2));
        while let Some(event) = e.next_event() {
            if let Event::Connection(_, events) = event {
                assert_eq!(events.urgent, None);
                assert!(!events.connected);
            }
        }
    }
    let mut at_a = b"fr".to_vec();
    let mut at_b = b"fr".to_vec();
    let mut buf = [0; 16];
    for _ in 0..16 {
        pump(&mut p.a, &mut p.b, 100, true);
        if let Ok(n) = p.a.read(a, &mut buf) {
            at_a.extend_from_slice(&buf[..n]);
        }
        if let Ok(n) = p.b.read(b, &mut buf) {
            at_b.extend_from_slice(&buf[..n]);
        }
        if at_a.len() == 6 && at_b.len() == 6 {
            break;
        }
    }
    assert_eq!(at_a, b"from-B");
    assert_eq!(at_b, b"from-A");
    pump(&mut p.a, &mut p.b, 100, true);
    assert_eq!(p.a.state(a), Ok(State::Established));
    assert_eq!(p.b.state(b), Ok(State::Established));
    // The clipped FIN never entered the stream, and neither duplicate SYN
    // flags nor the simultaneous SYN-ACK can promote that discarded control.
    assert_eq!(p.a.read(a, &mut buf), Err(Error::WouldBlock.into()));
    assert_eq!(p.b.read(b, &mut buf), Err(Error::WouldBlock.into()));
    for e in [&mut p.a, &mut p.b] {
        while let Some(event) = e.next_event() {
            if let Event::Connection(_, events) = event {
                assert_eq!(events.urgent, None, "establishment must not repeat early URG");
            }
        }
    }
}

#[test]
fn simultaneous_early_push_notification_is_once_before_connected_or_reset() {
    for reserved in [false, true] {
        for reset in [false, true] {
            let mut p = Peers::new(false, false, reserved, false);
            let ids = p.open(100, true, true);
            let sa = packet(&mut p.a, 100, reserved);
            let sb = packet(&mut p.b, 100, reserved);
            let s = wire::parse(sb.0, &sb.1).unwrap();
            let pushed = rewrite(&sb, wire::Header {
                flags: s.header.flags | wire::PSH,
                ..s.header
            }, s.raw_options, s.payload);
            while p.a.next_event().is_some() {}
            deliver(&mut p.b, 100, &sa);
            deliver(&mut p.a, 100, &pushed);
            assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
            assert!(!p.a.slot(ids.0).unwrap().connection.handshake_complete());
            let mut notices = 0;
            while let Some(event) = p.a.next_event() {
                if let Event::Connection(id, e) = event {
                    assert_eq!(id, ids.0);
                    assert!(e.readable);
                    assert!(!e.connected);
                    notices += usize::from(e.pushed);
                }
            }
            assert_eq!(notices, 1, "accepted SYN push must precede connection completion");
            let mut prefix = [0; 2];
            assert_eq!(p.a.read(ids.0, &mut prefix), Ok(2));
            assert_eq!(&prefix, b"fr");
            deliver(&mut p.a, 100, &pushed);
            assert_eq!(p.a.readable_bytes(ids.0), Ok(4));
            while let Some(event) = p.a.next_event() {
                if let Event::Connection(_, e) = event {
                    assert!(!e.connected);
                    assert!(!e.pushed, "duplicate SYN must not repeat early PUSH");
                }
            }
            if reset {
                let rst = rewrite(&sb, wire::Header {
                    sequence: s.header.sequence.wrapping_add(1 + s.payload.len() as u32),
                    flags: RST,
                    ..s.header
                }, &[], &[]);
                deliver(&mut p.a, 100, &rst);
                assert_eq!(p.a.close_reason(ids.0), Ok(Some(crate::CloseReason::Reset)));
                assert_eq!(p.a.terminal_readable_bytes(ids.0), Ok(4));
                while let Some(event) = p.a.next_event() {
                    if let Event::Connection(_, e) = event {
                        assert!(!e.connected);
                        assert!(!e.pushed, "reset must not repeat early PUSH");
                    }
                }
                let mut rest = [0; 8];
                assert_eq!(p.a.read_terminal(ids.0, &mut rest), Ok(4));
                assert_eq!(&rest[..4], b"om-B");
            } else {
                pump(&mut p.a, &mut p.b, 100, reserved);
                assert!(p.a.slot(ids.0).unwrap().connection.handshake_complete());
                let mut connected = false;
                while let Some(event) = p.a.next_event() {
                    if let Event::Connection(_, e) = event {
                        connected |= e.connected;
                        assert!(!e.pushed, "establishment must not repeat early PUSH");
                    }
                }
                assert!(connected);
                p.complete(ids, 100, prefix.to_vec(), Vec::new());
            }
        }
    }
}

#[test]
fn simultaneous_early_urgent_notification_precedes_read_and_reset() {
    for reserved in [false, true] {
        let mut p = Peers::new(false, false, reserved, false);
        let ids = p.open(100, true, true);
        let sb = packet(&mut p.b, 100, reserved);
        let s = wire::parse(sb.0, &sb.1).unwrap();
        let urgent = rewrite(&sb, wire::Header {
            flags: s.header.flags | wire::URG,
            urgent_pointer: 7,
            ..s.header
        }, s.raw_options, s.payload);
        while p.a.next_event().is_some() {}
        deliver(&mut p.a, 100, &urgent);
        assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
        assert!(!p.a.slot(ids.0).unwrap().connection.handshake_complete());
        let mut notice = None;
        while let Some(event) = p.a.next_event() {
            if let Event::Connection(id, e) = event {
                assert_eq!(id, ids.0);
                assert!(!e.connected);
                notice = notice.or(e.urgent);
            }
        }
        assert_eq!(notice, Some(6));
        assert_eq!(p.a.urgent_remaining(ids.0), Ok(6));
        // No read or handshake completion occurs before the exact-sequence reset.
        let reset = rewrite(&sb, wire::Header {
            sequence: s.header.sequence.wrapping_add(7),
            flags: RST,
            ..s.header
        }, &[], &[]);
        deliver(&mut p.a, 100, &reset);
        assert_eq!(p.a.close_reason(ids.0), Ok(Some(crate::CloseReason::Reset)));
        assert_eq!(p.a.terminal_readable_bytes(ids.0), Ok(6));
        while let Some(event) = p.a.next_event() {
            if let Event::Connection(_, e) = event {
                assert!(!e.connected);
                assert_eq!(e.urgent, None);
            }
        }
        let mut buf = [0; 8];
        assert_eq!(p.a.read_terminal(ids.0, &mut buf), Ok(6));
        assert_eq!(&buf[..6], b"from-B");
    }
}

#[test]
fn simultaneous_zero_window_synack_blocks_repair_until_real_reads() {
    for reserved in [false, true] {
        let mut p = Peers::new(false, false, reserved, false);
        let opts = ActiveOpenOptions {
            receive_capacity: 128,
            ..ActiveOpenOptions::from(&p.a.config.connection)
        };
        let data_a = vec![17; 400];
        let data_b = vec![29; 400];
        let (a, _) = p.a.connect_fast_open_with_receive_authority(
            100, p.aa, p.ba, &data_a, opts, None,
            FastOpenClientPolicy::RequireCookie, Some(p.la),
        ).unwrap();
        let (b, _) = p.b.connect_fast_open_with_receive_authority(
            100, p.ba, p.aa, &data_b, opts, None,
            FastOpenClientPolicy::RequireCookie, Some(p.lb),
        ).unwrap();
        let (sa, sb) = p.cross((a, b), 100);
        for syn in [&sa, &sb] {
            let s = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(s.payload.len(), 400);
            assert_eq!(s.header.window, 128);
        }
        let ra = packet(&mut p.a, 100, reserved);
        let rb = packet(&mut p.b, 100, reserved);
        for (reply, syn) in [(&ra, &sb), (&rb, &sa)] {
            let r = wire::parse(reply.0, &reply.1).unwrap();
            let s = wire::parse(syn.0, &syn.1).unwrap();
            assert_eq!(r.header.window, 0);
            assert_eq!(r.header.acknowledgment, s.header.sequence.wrapping_add(129));
        }
        deliver(&mut p.a, 100, &rb);
        deliver(&mut p.b, 100, &ra);
        for e in [&mut p.a, &mut p.b] {
            let ack = packet(e, 100, reserved);
            assert!(wire::parse(ack.0, &ack.1).unwrap().payload.is_empty(),
                "the first ACK must respect the SYN-ACK's zero window");
            assert!(poll(e, 100, reserved).is_none());
        }
        let mut got_a = Vec::new();
        let mut got_b = Vec::new();
        let mut buf = [0; 128];
        for _ in 0..16 {
            if let Ok(n) = p.a.read(a, &mut buf) {
                got_a.extend_from_slice(&buf[..n]);
            }
            if let Ok(n) = p.b.read(b, &mut buf) {
                got_b.extend_from_slice(&buf[..n]);
            }
            pump(&mut p.a, &mut p.b, 100, reserved);
            if got_a.len() == 400 && got_b.len() == 400 {
                break;
            }
        }
        assert_eq!(got_a, data_b);
        assert_eq!(got_b, data_a);
        assert_eq!(p.a.transport_info(a).unwrap().unacked, 0);
        assert_eq!(p.b.transport_info(b).unwrap().unacked, 0);
        std::println!("T4_ZERO_WINDOW {{\"reserved\":{reserved},\"syn_bytes\":400,\"accepted\":128,\"synack_window\":0,\"first_ack_bytes\":0,\"complete_each\":400}}");
    }
}

#[test]
fn simultaneous_authorized_fin_is_readable_before_connected() {
    for payload in [b"".as_slice(), b"from-B".as_slice()] {
        let mut p = Peers::new(false, false, false, false);
        let ids = p.open(100, true, true);
        let sb = packet(&mut p.b, 100, false);
        let s = wire::parse(sb.0, &sb.1).unwrap();
        let fin = rewrite(&sb, wire::Header {
            flags: s.header.flags | wire::FIN,
            ..s.header
        }, s.raw_options, payload);
        // Ignore setup events; only the checked crossing SYN can publish EOF.
        while p.a.next_event().is_some() {}
        deliver(&mut p.a, 100, &fin);
        assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
        let mut readable = false;
        let mut half_closed = false;
        while let Some(event) = p.a.next_event() {
            if let Event::Connection(id, e) = event {
                assert_eq!(id, ids.0);
                assert!(!e.connected);
                readable |= e.readable;
                half_closed |= e.half_closed;
            }
        }
        assert!(readable && half_closed);
        let mut buf = [0; 16];
        assert_eq!(p.a.read(ids.0, &mut buf), Ok(payload.len()));
        assert_eq!(&buf[..payload.len()], payload);
        assert_eq!(p.a.peek(ids.0, &mut buf), Ok(0));
        assert_eq!(p.a.read(ids.0, &mut buf), Ok(0));
        assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
        let _response = packet(&mut p.a, 100, false);
        assert_eq!(p.a.transport_info(ids.0).unwrap().syn_data_acked, !payload.is_empty());
    }
}

#[test]
fn simultaneous_replacement_cache_requires_valid_synack_and_real_request() {
    let mut p = Peers::new(false, false, false, false);
    let ids = p.open(100, true, true);
    let sa = packet(&mut p.a, 100, false);
    let sb = packet(&mut p.b, 100, false);
    p.a.set_fast_open_hmac_key([71; 32]);
    p.b.set_fast_open_hmac_key([89; 32]);
    deliver(&mut p.a, 100, &sb);
    deliver(&mut p.b, 100, &sa);
    assert_eq!(p.a.readable_bytes(ids.0), Ok(0));
    assert_eq!(p.b.readable_bytes(ids.1), Ok(0));
    let ra = packet(&mut p.a, 100, false);
    let rb = packet(&mut p.b, 100, false);
    let fresh_a = wire::parse(ra.0, &ra.1).unwrap().options.fast_open.unwrap();
    let fresh_b = wire::parse(rb.0, &rb.1).unwrap().options.fast_open.unwrap();
    assert_ne!(fresh_a, p.ca);
    assert_ne!(fresh_b, p.cb);
    assert_eq!(
        p.a.fast_open
            .as_ref()
            .unwrap()
            .get(100, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip())
            .unwrap()
            .cookie,
        p.cb
    );
    let s = wire::parse(rb.0, &rb.1).unwrap();
    // Wrong IRS and an ACK beyond physically sent sequence cannot learn a key.
    let wrong = rewrite(
        &rb,
        wire::Header {
            sequence: s.header.sequence.wrapping_add(1),
            ..s.header
        },
        s.raw_options,
        &[],
    );
    deliver(&mut p.a, 100, &wrong);
    let wrong = rewrite(
        &rb,
        wire::Header {
            acknowledgment: s.header.acknowledgment.wrapping_add(10000),
            ..s.header
        },
        s.raw_options,
        &[],
    );
    deliver(&mut p.a, 100, &wrong);
    assert_eq!(
        p.a.fast_open
            .as_ref()
            .unwrap()
            .get(100, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip())
            .unwrap()
            .cookie,
        p.cb
    );
    deliver(&mut p.a, 100, &rb);
    deliver(&mut p.b, 100, &ra);
    assert_eq!(
        p.a.fast_open
            .as_ref()
            .unwrap()
            .get(100, p.a.fast_open_lifetime(), p.aa.ip(), p.ba.ip())
            .unwrap()
            .cookie,
        fresh_b
    );
    assert_eq!(
        p.b.fast_open
            .as_ref()
            .unwrap()
            .get(100, p.b.fast_open_lifetime(), p.ba.ip(), p.aa.ip())
            .unwrap()
            .cookie,
        fresh_a
    );
    p.complete(ids, 100, vec![], vec![]);
}

#[test]
fn simultaneous_abort_timeout_and_listener_close_keep_active_ownership() {
    for timeout in [false, true] {
        let mut p = Peers::new(false, false, false, false);
        let ids = p.open(100, true, true);
        p.cross(ids, 100);
        assert_eq!(p.a.slot(ids.0).unwrap().fast_open_owner, Some(p.la));
        if timeout {
            p.a.set_handshake_retransmission_limit(ids.0, core::num::NonZeroU8::new(1))
                .unwrap();
            packet(&mut p.a, 100, false);
            for _ in 0..8 {
                let deadline = p.a.next_deadline().unwrap();
                p.a.on_timeout(deadline, 128).unwrap();
                if p.a.state(ids.0) == Ok(State::Closed) {
                    break;
                }
                poll(&mut p.a, deadline, false);
            }
            assert_eq!(p.a.state(ids.0), Ok(State::Closed));
        } else {
            p.a.close_listener(p.la).unwrap();
            p.a.cleanup_one();
            assert_eq!(p.a.state(ids.0), Ok(State::SynReceived));
            assert_eq!(p.a.readable_bytes(ids.0), Ok(6));
            p.a.abort(ids.0).unwrap();
        }
        assert!(p.a.slot(ids.0).unwrap().fast_open_owner.is_none());
        if timeout {
            assert_eq!(p.a.listener(p.la).unwrap().reset_debt, 0);
        }
    }
}

#[test]
fn simultaneous_original_reservation_and_failed_encode_cannot_admit() {
    let mut p = Peers::new(false, false, true, false);
    let ids = p.open(100, true, true);
    let mut small = [0; 1];
    assert!(
        p.a.poll_reserved_transmit_for(100, ids.0, &mut small, 128)
            .is_err()
    );
    assert!(!p.a.is_output_reserved(ids.0));
    let mut bytes = [0; 4096];
    let (_, ticket) =
        p.a.poll_reserved_transmit_for(100, ids.0, &mut bytes, 128)
            .unwrap();
    let ticket = ticket.unwrap();
    let sb = packet(&mut p.b, 100, true);
    assert_eq!(
        p.a.input(100, sb.0, &sb.1),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(p.a.readable_bytes(ids.0), Ok(0));
    assert!(p.a.slot(ids.0).unwrap().fast_open_owner.is_none());
    p.a.reject_unsubmitted(ticket).unwrap();
    assert_eq!(p.a.accept_transmit(100, ticket), Ok(false));
    assert!(p.a.abandon_transmit(ticket).unwrap());
    assert_eq!(p.a.state(ids.0), Ok(State::Closed));
    assert!(p.a.slot(ids.0).unwrap().fast_open_owner.is_none());
    assert_eq!(p.a.readable_bytes(ids.0), Ok(0));
}

#[test]
fn simultaneous_response_only_timeout_cannot_train_client_cooldown() {
    let mut p = Peers::new(false, false, true, false);
    let ids = p.open(100, true, true);
    let sb = packet(&mut p.b, 100, true);
    deliver(&mut p.a, 100, &sb);
    let ra = packet(&mut p.a, 100, true);
    assert_eq!(
        wire::parse(ra.0, &ra.1).unwrap().options.fast_open,
        Some(p.ca)
    );
    let deadline = p.a.next_deadline().unwrap();
    p.a.on_timeout(deadline, 128).unwrap();
    assert!(
        p.a.can_defer_fast_open_with_server_cookie(deadline, p.aa.ip(), p.ba, Some(p.cb))
            .unwrap()
    );
    let retry = packet(&mut p.a, deadline, true);
    assert!(
        wire::parse(retry.0, &retry.1)
            .unwrap()
            .options
            .fast_open
            .is_none()
    );
    deliver(&mut p.b, deadline, &ra);
    p.complete(ids, deadline, vec![], vec![]);
}
