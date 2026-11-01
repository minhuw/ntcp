// UDP echo evidence through the same TunHost constructor, input_frame
// dispatcher, Host submission transaction and output loop as run().
use super::*;
use ntcp_host::{IcmpDiscard, IcmpOutcome, UdpOptions};

const OPTIONS: UdpOptions = UdpOptions {
    dscp: 0,
    hop_limit: 64,
};

fn config(local: IpAddr) -> EndpointConfig {
    runtime_config(&Backend::default(), local, true, true, false).unwrap()
}

fn ip_header(v6: bool) -> usize {
    if v6 { IPV6_HEADER } else { IP_HEADER }
}

// One datagram through the Host transaction; returns the submitted frame.
fn udp_frame(
    host: &mut TunHost,
    endpoint: &Endpoint,
    time: u64,
    flow: UdpFlowId,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = [0; MTU];
    let mut sent = Vec::new();
    let result = host
        .host
        .udp_send(endpoint, time, flow, None, payload, &mut packet, |_, frame| {
            sent = frame.to_vec();
            BackendOutcome::Submitted
        })
        .unwrap();
    assert_eq!(result, UdpSent::Submitted(sent.len()));
    if sent[0] >> 4 == 4 {
        assert_eq!(u16::from_be_bytes([sent[6], sent[7]]), 0x4000, "DF, unfragmented");
    }
    sent
}

fn drain(echo: &mut UdpEcho, host: &mut TunHost, endpoint: &Endpoint, backend: &mut Backend) {
    for _ in 0..8 {
        if !echo.drive(host, endpoint, 0, backend).unwrap() {
            return;
        }
    }
    panic!("echo did not settle");
}

#[test]
fn udp_echo_round_trip_both_families() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let (mut b, mut bhost) = endpoint(remote.ip(), true);
        let service = SocketAddr::new(local.ip(), 7);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config(local.ip()), &refuse_settings()).unwrap();
        // Admission shares the Endpoint's address policy and Host authority.
        assert_eq!(
            ahost.host.udp_open(&a, service, None, OPTIONS),
            Err(ntcp_host::Error::Endpoint(EndpointError::AddressInUse))
        );
        assert_eq!(
            ahost.host.udp_open(&a, local, Some(addresses(!v6).1), OPTIONS),
            Err(ntcp_host::Error::Endpoint(EndpointError::InvalidAddress))
        );
        assert!(
            ahost
                .host
                .udp_open(&a, SocketAddr::new(remote.ip(), 7), None, OPTIONS)
                .is_err(),
            "a source this Host does not own"
        );
        assert!(
            ahost
                .host
                .udp_open(&a, local, Some(remote), UdpOptions { hop_limit: 0, ..OPTIONS })
                .is_err()
        );
        let client = bhost
            .host
            .udp_open(&b, SocketAddr::new(remote.ip(), 5000), Some(service), OPTIONS)
            .unwrap();
        let mut backend = Backend::default();
        let largest = MTU - ip_header(v6) - 8;
        for (time, size) in [(1, 0), (2, 1), (3, 512), (4, largest)] {
            let payload: Vec<u8> = (0..size).map(|n| (n * 7 + size) as u8).collect();
            let request = udp_frame(&mut bhost, &b, time, client, &payload);
            input_frame(&mut ahost, &mut a, time, &request, local.ip(), false, 0).unwrap();
            assert!(echo.drive(&mut ahost, &a, time, &mut backend).unwrap());
            assert_eq!(backend.frames.len(), 1);
            let reply = backend.frames.pop().unwrap();
            assert_eq!(reply.len(), ip_header(v6) + 8 + size);
            // The peer Host verifies the reply's checksum before queueing it.
            input_frame(&mut bhost, &mut b, time, &reply, remote.ip(), false, 0).unwrap();
            let mut bytes = [0; MTU];
            assert_eq!(
                bhost.host.udp_receive(client, &mut bytes).unwrap(),
                Some((service, size))
            );
            assert_eq!(&bytes[..size], payload);
        }
        println!("v6={v6}: UDP echo round trips up to {largest} octets");
    }
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=The Host dispatcher notifies the specific correlated sender while processing the report: TCP consumes PmtuFeedback drop advice and a Host UDP flow receives UdpEvent::PacketTooBig, whether or not the estimate changes. Path-level change notification is separate: a shared decrease marks the path's clients dirty, and Host::service_changes then brings every other user to the new budget (TCP budget application, the UDP flow change slot) on the next service pass. Dual-family TUN tests consume the UDP event immediately and observe the TCP flow adopt the shared decrease after the next service pass.
//# It is important to understand that the notification of the packetization
//# layer instances using the path about the change in the PMTU is distinct from
//# the notification of a specific instance that a packet has been dropped. The
//# latter should be done as soon as practical (i.e., asynchronously from the
//# point of view of the packetization layer instance), while the former may be
//# delayed until a packetization layer instance wants to create a packet.
#[test]
fn udp_quoted_router_ptb_reaches_echo_and_shrinks_tcp_on_the_same_path() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let service = SocketAddr::new(p.local.ip(), p.local.port());
        let mut echo = UdpEcho::open(&mut p.ahost, &p.a, service, &config(p.local.ip()), &refuse_settings())
            .unwrap();
        let client = p.bhost.host.udp_open(&p.b, p.remote, Some(service), OPTIONS).unwrap();
        let header = ip_header(v6);
        let mut packet = [0; MTU];
        assert_eq!(
            p.ahost.host.udp_send(&p.a, p.time, echo.flow, Some(p.remote),
                &[0; MTU], &mut packet, |_, _| panic!("no backend call")),
            Err(UdpSendError::TooBig { max_payload: MTU - header - 8 })
        );
        let mut backend = Backend::default();
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &[0x42; 1400]);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        let reply = backend.frames.pop().unwrap();
        let mtu = if v6 { 1280 } else { 1006 };
        assert!(reply.len() > mtu);
        let path = p.ahost.host.binding(p.aid).unwrap().snapshot.path();
        assert_eq!(p.ahost.host.paths().path_snapshot(path).unwrap().learned_mtu(), None);
        assert_eq!(p.a.managed_path(p.aid).unwrap().ordinary_ip_budget, MTU as u32);
        let report = ptb(&reply, mtu as u32);
        assert_ne!(ntcp_icmp::decode_icmp_quote(&report).unwrap().outer.source, p.remote.ip(),
            "an intermediate router, not the peer");
        input_frame(&mut p.ahost, &mut p.a, p.time, &report, p.local.ip(), false, 0).unwrap();
        assert_eq!(p.ahost.host.paths().path_snapshot(path).unwrap().learned_mtu(),
            Some(mtu as u32), "UDP correlation published the shared decrease");
        assert_eq!(p.ahost.host.udp_event(echo.flow).unwrap(), Some(UdpEvent::PacketTooBig {
            remote: p.remote, mtu: Some(mtu as u32), dropped_len: reply.len() as u32,
        }));
        assert_eq!(p.ahost.host.udp_event(echo.flow).unwrap(), None, "consumed once");
        // A repeated report is still advice; the service consumes it itself.
        input_frame(&mut p.ahost, &mut p.a, p.time, &report, p.local.ip(), false, 0).unwrap();
        assert!(echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap());
        assert_eq!(p.ahost.host.udp_event(echo.flow).unwrap(), None);
        // Later replies are held to the shared estimate: typed refusal, never split.
        let max_payload = mtu - header - 8;
        assert_eq!(
            p.ahost.host.udp_send(&p.a, p.time, echo.flow, Some(p.remote),
                &[0; 1400], &mut packet, |_, _| panic!("no backend call")),
            Err(UdpSendError::TooBig { max_payload })
        );
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &[0x43; 1400]);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        assert!(backend.frames.is_empty(), "oversized reply dropped, not fragmented");
        assert!(echo.held.is_none());
        let payload = vec![0x44; max_payload];
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &payload);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        let reply = backend.frames.pop().unwrap();
        assert_eq!(reply.len(), mtu);
        input_frame(&mut p.bhost, &mut p.b, p.time, &reply, p.remote.ip(), false, 0).unwrap();
        let mut bytes = [0; MTU];
        assert_eq!(p.bhost.host.udp_receive(client, &mut bytes).unwrap(), Some((service, max_payload)));
        // The TCP connection on the same path adopts it at its next egress.
        let stream: Vec<u8> = (0..12000).map(|n| (n % 241) as u8).collect();
        p.a.write(p.aid, &stream).unwrap();
        let (drops, frames) = p.progress(mtu, &stream);
        assert_eq!(drops, 0, "no TCP packet exceeded the UDP-learned path MTU");
        assert!(frames.iter().all(|f| f.len() <= mtu));
        assert!(frames.iter().any(|f| f.len() == mtu));
        assert_eq!(p.a.managed_path(p.aid).unwrap().ordinary_ip_budget, mtu as u32);
        println!("v6={v6}: UDP-quoted PTB {mtu}; {} TCP frames all <= {mtu}", frames.len());
    }
}

// A shared decrease caused by the TCP flow's segment reaches the echo only
// through its change notification: a reply held by a blocked TUN is
// reconsidered and refused with the changed limit, a later oversize request
// is refused by the path query before any encoding or backend call, and a
// fitting reply still leaves byte-for-byte.
#[test]
fn udp_echo_sizes_replies_by_path_limits_and_reconsiders_held_reply_on_change() {
    for v6 in [false, true] {
        let mut p = Pair::new(v6, true);
        let service = SocketAddr::new(p.local.ip(), p.local.port());
        let mut echo = UdpEcho::open(&mut p.ahost, &p.a, service, &config(p.local.ip()), &refuse_settings())
            .unwrap();
        let client = p.bhost.host.udp_open(&p.b, p.remote, Some(service), OPTIONS).unwrap();
        let (header, mtu) = if v6 { (IPV6_HEADER, 1280) } else { (IP_HEADER, 1006) };
        let max_payload = mtu - header - 8;
        let mut backend = Backend::default();
        // A fitting echo pins the echo's path to the peer.
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &[0x41; 1400]);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        assert_eq!(backend.frames.pop().unwrap().len(), header + 8 + 1400);
        // The next reply is held: the TUN would block.
        backend.blocked = true;
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &[0x42; 1400]);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        let attempts = backend.attempts;
        assert_eq!(echo.held, Some((p.remote, 1400)));
        assert!(echo.blocked && echo.notes.is_empty());
        // A router PTB quoting only a TCP segment lowers the shared path.
        p.a.write(p.aid, &[0x5a; 3000]).unwrap();
        let sent = emit(&mut p.ahost, &mut p.a, p.time, p.local.ip());
        assert!(sent[0].len() > mtu);
        let path = p.ahost.host.binding(p.aid).unwrap().snapshot.path();
        input_frame(&mut p.ahost, &mut p.a, p.time, &ptb(&sent[0], mtu as u32), p.local.ip(), false, 0)
            .unwrap();
        assert_eq!(p.ahost.host.paths().path_snapshot(path).unwrap().learned_mtu(), Some(mtu as u32));
        assert_eq!(p.ahost.host.udp_event(echo.flow).unwrap(), None, "no advice for the echo");
        let report = p.ahost.host.service_changes(&mut p.a, p.time).unwrap();
        assert!(report.applied >= 2 && report.failed == 0, "{report:?}");
        backend.blocked = false;
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        assert_eq!(backend.attempts, attempts, "the held reply is never submitted");
        assert!(backend.frames.is_empty() && echo.held.is_none() && !echo.blocked);
        assert_eq!(echo.notes, [
            format!("UDP echo path to {} changed: MMS_S {}, payload limit {max_payload}",
                p.remote.ip(), mtu - header),
            format!("UDP echo of 1400 octets to {} refused: exceeds the changed path payload \
                limit of {max_payload}", p.remote),
        ]);
        assert_eq!(p.ahost.host.udp_path_change(echo.flow).unwrap(), None, "consumed once");
        // An oversize request is refused by the path query before encoding.
        echo.notes.clear();
        echo.packet.fill(0xa5);
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &[0x43; 1400]);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        assert!(echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap());
        assert_eq!(backend.attempts, attempts, "no backend call");
        assert!(echo.packet.iter().all(|&b| b == 0xa5), "nothing encoded");
        assert!(echo.held.is_none());
        assert_eq!(echo.notes, [format!("UDP echo of 1400 octets to {} refused: exceeds the path \
            payload limit of {max_payload}; replies are never fragmented", p.remote)]);
        // A reply of exactly the limit is echoed byte-for-byte.
        echo.notes.clear();
        let payload: Vec<u8> = (0..max_payload).map(|n| (n * 13 + 5) as u8).collect();
        let request = udp_frame(&mut p.bhost, &p.b, p.time, client, &payload);
        input_frame(&mut p.ahost, &mut p.a, p.time, &request, p.local.ip(), false, 0).unwrap();
        echo.drive(&mut p.ahost, &p.a, p.time, &mut backend).unwrap();
        let reply = backend.frames.pop().unwrap();
        assert!(backend.frames.is_empty() && echo.notes.is_empty());
        assert_eq!(reply.len(), mtu);
        input_frame(&mut p.bhost, &mut p.b, p.time, &reply, p.remote.ip(), false, 0).unwrap();
        let mut bytes = [0; MTU];
        assert_eq!(p.bhost.host.udp_receive(client, &mut bytes).unwrap(), Some((service, max_payload)));
        assert_eq!(&bytes[..max_payload], payload);
        println!("v6={v6}: held 1400 refused on change to {max_payload}; oversize refused \
            before encoding; {max_payload}-octet echo exact");
    }
}

#[test]
fn identical_udp_quotes_across_flow_generation_reuse_are_ambiguous() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let first = ahost.host.udp_open(&a, local, Some(remote), OPTIONS).unwrap();
        let old = udp_frame(&mut ahost, &a, 1, first, &[0x11; 1400]);
        ahost.host.udp_close(first).unwrap();
        let second = ahost.host.udp_open(&a, local, Some(remote), OPTIONS).unwrap();
        assert_ne!(first, second, "the single slot is reused by a new generation");
        assert_eq!(ahost.host.udp_event(first), Err(ntcp_host::Error::Obsolete));
        let same = udp_frame(&mut ahost, &a, 2, second, &[0x11; 1400]);
        assert_eq!(same, old, "byte-identical datagram from the new generation");
        let distinct = udp_frame(&mut ahost, &a, 3, second, &[0x22; 1400]);
        let mtu = if v6 { 1280 } else { 1006 };
        // Positive control: a distinct datagram identifies this generation.
        input_frame(&mut ahost, &mut a, 4, &ptb(&distinct, mtu), local.ip(), false, 0).unwrap();
        assert!(matches!(ahost.host.udp_event(second).unwrap(),
            Some(UdpEvent::PacketTooBig { dropped_len: 1448 | 1428, .. })));
        // The identical quote matches both generations: no owner advice.
        input_frame(&mut ahost, &mut a, 5, &ptb(&old, mtu), local.ip(), false, 0).unwrap();
        assert_eq!(ahost.host.udp_event(second).unwrap(), None);
        let outcome = ahost.host.input_icmp(&mut a, ahost.ingress, 6, &ptb(&old, mtu)).unwrap();
        assert!(matches!(outcome,
            IcmpDispatch::Completed(IcmpOutcome::Advice { owner: None, .. })
                | IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Ambiguous))),
            "{outcome:?}");
        assert_eq!(ahost.host.udp_event(second).unwrap(), None);
        println!("v6={v6}: identical quote across generations -> {outcome:?}");
    }
}

#[test]
fn forged_udp_quotes_are_rejected() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let flow = ahost.host.udp_open(&a, local, Some(remote), OPTIONS).unwrap();
        let sent = udp_frame(&mut ahost, &a, 1, flow, &[0x5a; 1400]);
        let h = header(&sent);
        let mtu = if v6 { 1280 } else { 1006 };
        let length = if v6 { 5 } else { 3 };
        for (name, offset) in [
            ("UDP checksum", h + 7),
            ("UDP source port", h + 1),
            ("UDP destination port", h + 3),
            ("UDP length", h + 5),
            ("IP total length", length),
            ("quoted destination", if v6 { 39 } else { 19 }),
        ] {
            let mut quote = sent.clone();
            quote[offset] ^= 1;
            if !v6 {
                seal_ip(&mut quote);
            }
            input_frame(&mut ahost, &mut a, 2, &ptb(&quote, mtu), local.ip(), false, 0).unwrap();
            assert_eq!(ahost.host.udp_event(flow).unwrap(), None, "{name}");
        }
        let mut packet = [0; MTU];
        let unchanged = ahost.host.udp_send(&a, 3, flow, None, &[0; 1400], &mut packet,
            |_, _| BackendOutcome::Submitted);
        assert!(matches!(unchanged, Ok(UdpSent::Submitted(_))), "budget unchanged");
        input_frame(&mut ahost, &mut a, 4, &ptb(&sent, mtu), local.ip(), false, 0).unwrap();
        assert!(ahost.host.udp_event(flow).unwrap().is_some());
        assert!(matches!(
            ahost.host.udp_send(&a, 5, flow, None, &[0; 1400], &mut packet,
                |_, _| panic!("no backend call")),
            Err(UdpSendError::TooBig { .. })
        ));
    }
}

#[test]
fn udp_receive_queue_backpressure_and_checksum_validation() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let (mut b, mut bhost) = endpoint(remote.ip(), true);
        let service = SocketAddr::new(local.ip(), 7);
        let mut echo = UdpEcho::open(&mut ahost, &a, service, &config(local.ip()), &refuse_settings()).unwrap();
        let client = bhost
            .host
            .udp_open(&b, SocketAddr::new(remote.ip(), 5000), Some(service), OPTIONS)
            .unwrap();
        let mut corrupt = udp_frame(&mut bhost, &b, 1, client, b"corrupted");
        *corrupt.last_mut().unwrap() ^= 1;
        input_frame(&mut ahost, &mut a, 1, &corrupt, local.ip(), false, 0).unwrap();
        for n in 0..BUDGET + 4 {
            let request = udp_frame(&mut bhost, &b, 2, client, &vec![n as u8; 64 + n]);
            input_frame(&mut ahost, &mut a, 2, &request, local.ip(), false, 0).unwrap();
        }
        // A blocked TUN holds exactly one reply and reads no further.
        let mut backend = Backend { blocked: true, ..Default::default() };
        echo.drive(&mut ahost, &a, 3, &mut backend).unwrap();
        assert!(echo.blocked);
        assert_eq!(echo.held.map(|(peer, len)| (peer, len)), Some((client_addr(remote), 64)));
        assert!(backend.frames.is_empty());
        let attempts = backend.attempts;
        echo.drive(&mut ahost, &a, 3, &mut backend).unwrap();
        assert_eq!(backend.attempts, attempts + 1, "the same reply is retried");
        backend.blocked = false;
        drain(&mut echo, &mut ahost, &a, &mut backend);
        assert!(!echo.blocked);
        assert_eq!(backend.frames.len(), BUDGET, "queue bound; corrupt and excess dropped");
        let mut bytes = [0; MTU];
        for (n, reply) in backend.frames.drain(..).enumerate() {
            input_frame(&mut bhost, &mut b, 4, &reply, remote.ip(), false, 0).unwrap();
            let (from, len) = bhost.host.udp_receive(client, &mut bytes).unwrap().unwrap();
            assert_eq!((from, &bytes[..len]), (service, &vec![n as u8; 64 + n][..]));
        }
        // Drained storage admits new requests again.
        let request = udp_frame(&mut bhost, &b, 5, client, b"after drain");
        input_frame(&mut ahost, &mut a, 5, &request, local.ip(), false, 0).unwrap();
        drain(&mut echo, &mut ahost, &a, &mut backend);
        assert_eq!(backend.frames.len(), 1);
        println!("v6={v6}: {} queued of {} offered; corrupt checksum dropped", BUDGET, BUDGET + 4);
    }
}

fn client_addr(remote: SocketAddr) -> SocketAddr {
    SocketAddr::new(remote.ip(), 5000)
}

// A Destination Unreachable of the same frame as `ptb`, no next-hop MTU.
fn unreachable(frame: &[u8]) -> Vec<u8> {
    let mut packet = ptb(frame, 0);
    let h = header(&packet);
    if packet[0] >> 4 == 6 {
        packet[h..h + 2].copy_from_slice(&[1, 3]);
    } else {
        packet[h + 1] = 1;
    }
    seal_feedback(&mut packet);
    packet
}

// Steady-state traffic overflows the per-owner history many times over;
// evicted datagrams keep exact signatures, so ICMP quoting any distinct
// datagram still reaches the flow, while a byte-identical resend of an
// evicted datagram stays ambiguous.
#[test]
fn udp_feedback_stays_attributable_after_history_overflow() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let cfg = config(local.ip());
        let history = cfg.connection.send_capacity.div_ceil(usize::from(cfg.connection.mss)) + 1;
        let flow = ahost.host.udp_open(&a, local, Some(remote), OPTIONS).unwrap();
        let sent: Vec<Vec<u8>> = (0..3 * history)
            .map(|n| {
                let mut payload = [0x33; 1400];
                payload[..2].copy_from_slice(&(n as u16).to_be_bytes());
                udp_frame(&mut ahost, &a, 1 + n as u64, flow, &payload)
            })
            .collect();
        let time = 10 + sent.len() as u64;
        let other = &sent[sent.len() - 2];
        input_frame(&mut ahost, &mut a, time, &unreachable(other), local.ip(), false, 0).unwrap();
        assert!(matches!(ahost.host.udp_event(flow).unwrap(),
            Some(UdpEvent::NetworkError { remote: r, .. }) if r == remote));
        // An evicted datagram is remembered only as ambiguous history.
        input_frame(&mut ahost, &mut a, time, &unreachable(&sent[0]), local.ip(), false, 0).unwrap();
        assert_eq!(ahost.host.udp_event(flow).unwrap(), None);
        // Resending it byte-identically keeps the old quote ambiguous ...
        let mut payload = [0x33; 1400];
        payload[..2].copy_from_slice(&0u16.to_be_bytes());
        let copy = udp_frame(&mut ahost, &a, time + 1, flow, &payload);
        assert_eq!(copy, sent[0]);
        input_frame(&mut ahost, &mut a, time + 2, &unreachable(&copy), local.ip(), false, 0).unwrap();
        assert_eq!(ahost.host.udp_event(flow).unwrap(), None);
        // ... while the other live datagrams remain attributable.
        input_frame(&mut ahost, &mut a, time + 2, &unreachable(&sent[sent.len() - 3]),
            local.ip(), false, 0).unwrap();
        assert!(ahost.host.udp_event(flow).unwrap().is_some());
        let mtu = if v6 { 1280 } else { 1006 };
        let live = &sent[sent.len() - 1];
        input_frame(&mut ahost, &mut a, time + 3, &ptb(live, mtu), local.ip(), false, 0).unwrap();
        assert_eq!(ahost.host.udp_event(flow).unwrap(), Some(UdpEvent::PacketTooBig {
            remote, mtu: Some(mtu), dropped_len: live.len() as u32,
        }));
        println!("v6={v6}: {} datagrams over a {history}-entry history; distinct quotes \
            attributed, identical quote ambiguous", sent.len());
    }
}

// A quote that matches only lossy history is no evidence of a submission.
// Once a flow's datagrams of different lengths and checksums overflow the
// exact signatures into one widened summary, an off-path sender knowing the
// four-tuple forges a never-sent length and checksum within its range: the
// Host must discard it and publish nothing.
#[test]
fn quote_matching_only_a_widened_udp_summary_publishes_nothing() {
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let (mut a, mut ahost) = endpoint(local.ip(), true);
        let flow = ahost.host.udp_open(&a, local, Some(remote), OPTIONS).unwrap();
        udp_frame(&mut ahost, &a, 1, flow, &[0x61; 1300]);
        let sent = udp_frame(&mut ahost, &a, 2, flow, &[0x62; 1400]);
        let h = header(&sent);
        // The 1400-byte datagram's header, rewritten to a 1350-byte payload
        // and checksum 0x1234 that were never sent.
        let mut forged = sent.clone();
        if v6 {
            forged[4..6].copy_from_slice(&(8 + 1350u16).to_be_bytes());
        } else {
            forged[2..4].copy_from_slice(&((h + 8 + 1350) as u16).to_be_bytes());
            seal_ip(&mut forged);
        }
        forged[h + 4..h + 6].copy_from_slice(&(8 + 1350u16).to_be_bytes());
        forged[h + 6..h + 8].copy_from_slice(&0x1234u16.to_be_bytes());
        let mtu = if v6 { 1280 } else { 1006 };
        let dispatch = |ahost: &mut TunHost, a: &mut Endpoint, time| {
            ahost.host.input_icmp(a, ahost.ingress, time, &ptb(&forged, mtu)).unwrap()
        };
        let before = dispatch(&mut ahost, &mut a, 3);
        assert_eq!(before,
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated)));
        let mut time = 4;
        for n in 0..8002u32 {
            let len = if n % 2 == 0 { 1300 } else { 1400 };
            let mut payload = vec![0x63; len];
            payload[..4].copy_from_slice(&n.to_be_bytes());
            udp_frame(&mut ahost, &a, time, flow, &payload);
            time += 1;
        }
        let after = dispatch(&mut ahost, &mut a, time);
        assert_eq!(after,
            IcmpDispatch::Completed(IcmpOutcome::Discarded(IcmpDiscard::Uncorrelated)),
            "lossy history never creates a match");
        assert_eq!(ahost.host.udp_event(flow).unwrap(), None);
        let mut packet = [0; MTU];
        let unchanged = ahost.host.udp_send(&a, time + 1, flow, None, &[0; 1400], &mut packet,
            |_, _| BackendOutcome::Submitted);
        assert!(matches!(unchanged, Ok(UdpSent::Submitted(_))), "budget unchanged: {unchanged:?}");
        println!("v6={v6}: forged in-range quote before overflow -> {before:?}; after 8002 \
            datagrams -> {after:?}; next 1400-byte send {unchanged:?}");
    }
}
