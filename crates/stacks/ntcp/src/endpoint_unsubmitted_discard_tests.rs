// SPDX-License-Identifier: MIT
// Endpoint::discard_unsubmitted: a held attempt whose next hop never
// resolved is withdrawn without a departure for every segment kind but
// fresh data, which is accounted as sent and lost (the refused_as_lost
// tests of endpoint_loss_counter_tests).
extern crate std;
use super::*;

fn endpoint() -> Endpoint {
    Endpoint::new(
        EndpointConfig {
            max_connections: 4,
            max_listeners: 2,
            connection: ConnectionConfig {
                mss: 1000,
                nagle: false,
                ..ConnectionConfig::default()
            },
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap()
}

const LOCAL: &str = "192.0.2.1:40000";
const REMOTE: &str = "192.0.2.2:8080";

fn segment(p: Transmit, bytes: &[u8]) -> (u32, u8, usize) {
    let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
    (s.header.sequence, s.header.flags, s.payload.len())
}

fn soft_error(a: &mut Endpoint, id: ConnectionId) -> bool {
    let mut seen = false;
    while let Some(event) = a.next_event() {
        if let Event::Connection(owner, events) = event
            && owner == id
            && events.network_error == Some(crate::NetworkError::SoftUnreachable)
        {
            seen = true;
        }
    }
    seen
}

// An established pair at time 1 whose client `a` reserves its output.
fn established() -> (Endpoint, Endpoint, ConnectionId, ConnectionId) {
    let mut a = endpoint();
    let mut b = endpoint();
    let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
    let client = a
        .connect(0, LOCAL.parse().unwrap(), REMOTE.parse().unwrap())
        .unwrap();
    let mut bytes = [0; 2048];
    for i in 0..3 {
        let (src, dst) = if i == 1 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let p = src.poll_transmit(1, &mut bytes, 16).unwrap().packet.unwrap();
        dst.input(1, p.ip, &bytes[..p.len]).unwrap();
    }
    let server = b.accept(listener).unwrap();
    a.enable_output_reservations().unwrap();
    (a, b, client, server)
}

#[test]
fn discarded_syn_has_no_departure_and_retries_at_the_rto() {
    let mut a = endpoint();
    let mut b = endpoint();
    a.enable_output_reservations().unwrap();
    b.listen(REMOTE.parse().unwrap(), 4).unwrap();
    let id = a
        .connect(0, LOCAL.parse().unwrap(), REMOTE.parse().unwrap())
        .unwrap();
    let mut bytes = [0; 2048];
    let (out, token) = a.poll_reserved_transmit(0, &mut bytes, 16).unwrap();
    let (iss, flags, _) = segment(out.packet.unwrap(), &bytes);
    assert_ne!(flags & SYN, 0);
    let token = token.unwrap();
    let rto = a.transport_info(id).unwrap().rto_us;
    // Resolution failed three seconds later (three solicitations).
    let failed = 3_000_000;
    assert!(
        a.discard_unsubmitted(
            failed,
            token,
            Some(crate::NetworkError::SoftUnreachable),
            crate::DropReason::NeighFailed
        )
        .unwrap()
    );
    assert!(
        !a.discard_unsubmitted(failed, token, None, crate::DropReason::NeighFailed)
            .unwrap()
    );
    assert!(!a.accept_transmit(failed, token).unwrap());
    assert!(!a.is_output_reserved(id));
    assert!(soft_error(&mut a, id));
    let info = a.transport_info(id).unwrap();
    assert_eq!(info.state, State::SynSent);
    assert_eq!((info.retransmitted, info.rto_backoff, info.rto_us), (0, 0, rto));
    assert_eq!(a.close_reason(id).unwrap(), None);
    // No new attempt before one RTO after the failure.
    assert!(a.next_deadline().is_some_and(|at| at >= failed + rto));
    a.on_timeout(failed + rto - 1, 16).unwrap();
    let (out, token) = a.poll_reserved_transmit(failed + rto - 1, &mut bytes, 16).unwrap();
    assert!(out.packet.is_none() && token.is_none());
    let retry = failed + rto;
    a.on_timeout(retry, 16).unwrap();
    let (out, token) = a.poll_reserved_transmit(retry, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    // The same SYN, not a retransmission: no backoff step was taken.
    assert_eq!(segment(p, &bytes).0, iss);
    assert!(a.accept_transmit(retry, token.unwrap()).unwrap());
    let info = a.transport_info(id).unwrap();
    assert_eq!((info.retransmitted, info.rto_backoff, info.rto_us), (0, 0, rto));
    // The RTT sample measures the submitted attempt, not the discarded one.
    b.input(retry + 1, p.ip, &bytes[..p.len]).unwrap();
    let reply = b.poll_transmit(retry + 1, &mut bytes, 16).unwrap().packet.unwrap();
    a.input(retry + 5_000, reply.ip, &bytes[..reply.len]).unwrap();
    let info = a.transport_info(id).unwrap();
    assert_eq!(info.state, State::Established);
    assert_eq!(info.rtt_us, Some(5_000));
}

#[test]
fn repeatedly_discarded_syn_ends_at_its_deadline_with_the_error() {
    let mut a = endpoint();
    a.enable_output_reservations().unwrap();
    let id = a
        .connect(0, LOCAL.parse().unwrap(), REMOTE.parse().unwrap())
        .unwrap();
    let mut bytes = [0; 2048];
    let mut now = 0;
    let mut attempts = 0u64;
    let mut error = false;
    while a.close_reason(id).unwrap().is_none() {
        let (out, token) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
        if let Some(token) = token {
            assert_ne!(segment(out.packet.unwrap(), &bytes).1 & SYN, 0);
            attempts += 1;
            let rto = a.transport_info(id).unwrap().rto_us;
            // Each attempt's resolution takes three RetransTimers.
            now += 3_000_000;
            assert!(
                a.discard_unsubmitted(
                    now,
                    token,
                    Some(crate::NetworkError::SoftUnreachable),
                    crate::DropReason::NeighFailed
                )
                .unwrap()
            );
            error |= soft_error(&mut a, id);
            assert!(a.next_deadline().is_some_and(|at| at >= now + rto));
        } else {
            now = a.next_deadline().unwrap();
            a.on_timeout(now, 16).unwrap();
        }
        assert!(attempts < 1_000);
    }
    assert!(error);
    assert_eq!(a.close_reason(id).unwrap(), Some(crate::CloseReason::TimedOut));
    // R2 for a SYN, from its first selection: unchanged by the attempts,
    // each one RTO after the previous failure.
    let deadline = a.config.connection.user_timeout_us.max(180_000_000);
    assert!((deadline..deadline + 4_000_000).contains(&now));
    assert_eq!(attempts, deadline.div_ceil(4_000_000));
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
}

#[test]
fn a_discarded_fin_restores_its_selection() {
    let (mut a, _, id, _) = established();
    let mut bytes = [0; 2048];
    // A new FIN: discarding it returns the close to ESTABLISHED.
    let t = 10;
    let rto = a.transport_info(id).unwrap().rto_us;
    a.shutdown(id).unwrap();
    let (out, token) = a.poll_reserved_transmit(t, &mut bytes, 16).unwrap();
    let (fin, flags, _) = segment(out.packet.unwrap(), &bytes);
    assert_ne!(flags & wire::FIN, 0);
    assert_eq!(a.state(id).unwrap(), State::FinWait1);
    assert!(
        a.discard_unsubmitted(t, token.unwrap(), None, crate::DropReason::NeighFailed)
            .unwrap()
    );
    assert_eq!(a.state(id).unwrap(), State::Established);
    assert_eq!(a.transport_info(id).unwrap().unacked, 0);
    let retry = a.next_deadline().unwrap();
    assert!(retry >= t + rto);
    let (out, _) = a.poll_reserved_transmit(retry - 1, &mut bytes, 16).unwrap();
    assert!(out.packet.is_none());
    a.on_timeout(retry, 16).unwrap();
    let (out, token) = a.poll_reserved_transmit(retry, &mut bytes, 16).unwrap();
    let (again, flags, _) = segment(out.packet.unwrap(), &bytes);
    assert_eq!((again, flags & wire::FIN), (fin, wire::FIN));
    assert!(a.accept_transmit(retry, token.unwrap()).unwrap());
    assert_eq!(a.state(id).unwrap(), State::FinWait1);
    assert_eq!(a.transport_info(id).unwrap().retransmitted, 0);
}

#[test]
fn discarded_pure_ack_and_reset_are_dropped() {
    let (mut a, mut b, id, peer) = established();
    let mut bytes = [0; 2048];
    b.write(peer, &[3; 100]).unwrap();
    let p = b.poll_transmit(2, &mut bytes, 16).unwrap().packet.unwrap();
    a.input(2, p.ip, &bytes[..p.len]).unwrap();
    a.read(id, &mut [0; 100]).unwrap();
    let mut token = None;
    let mut t = 2;
    while token.is_none() {
        a.on_timeout(t, 16).unwrap();
        let (out, attempt) = a.poll_reserved_transmit(t, &mut bytes, 16).unwrap();
        if let Some(p) = out.packet {
            let (_, flags, len) = segment(p, &bytes);
            assert_eq!((flags & (SYN | wire::FIN | RST), len), (0, 0));
        }
        token = attempt;
        t = a.next_deadline().unwrap_or(t + 1).max(t + 1);
    }
    assert!(
        a.discard_unsubmitted(t, token.unwrap(), None, crate::DropReason::NeighFailed)
            .unwrap()
    );
    assert!(!a.is_output_reserved(id));
    // Dropped like an ACK lost on the wire: nothing is retried.
    let (out, _) = a.poll_reserved_transmit(t, &mut bytes, 16).unwrap();
    assert!(out.packet.is_none());
    a.abort(id).unwrap();
    let (out, token) = a.poll_reserved_transmit(t, &mut bytes, 16).unwrap();
    assert_ne!(segment(out.packet.unwrap(), &bytes).1 & RST, 0);
    assert!(
        a.discard_unsubmitted(t, token.unwrap(), None, crate::DropReason::NeighFailed)
            .unwrap()
    );
    assert!(!a.is_output_reserved(id));
    let (out, _) = a.poll_reserved_transmit(t, &mut bytes, 16).unwrap();
    assert!(out.packet.is_none());
}

// A passive open's SYN-ACK whose next hop never resolved: withdrawn
// without a departure, the child stays in SYN-RECEIVED, and the same
// SYN-ACK is sent again no earlier than one RTO after the failure, not as
// a retransmission; the handshake then completes.
#[test]
fn discarded_syn_ack_has_no_departure_and_retries_at_the_rto() {
    let mut a = endpoint();
    let mut b = endpoint();
    b.enable_output_reservations().unwrap();
    let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
    a.connect(0, LOCAL.parse().unwrap(), REMOTE.parse().unwrap())
        .unwrap();
    let mut bytes = [0; 2048];
    let syn = a.poll_transmit(0, &mut bytes, 16).unwrap().packet.unwrap();
    b.input(1, syn.ip, &bytes[..syn.len]).unwrap();
    let (out, token) = b.poll_reserved_transmit(1, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    let (iss, flags, _) = segment(p, &bytes);
    assert_eq!(flags & (SYN | wire::ACK), SYN | wire::ACK);
    let child = p.connection.expect("a SYN-RECEIVED child");
    let rto = b.transport_info(child).unwrap().rto_us;
    let failed = 3_000_001;
    assert!(
        b.discard_unsubmitted(
            failed,
            token.unwrap(),
            Some(crate::NetworkError::SoftUnreachable),
            crate::DropReason::NeighFailed
        )
        .unwrap()
    );
    assert!(!b.is_output_reserved(child));
    let info = b.transport_info(child).unwrap();
    assert_eq!(info.state, State::SynReceived);
    assert_eq!(
        (info.retransmitted, info.rto_backoff, info.rto_us),
        (0, 0, rto)
    );
    assert!(b.next_deadline().is_some_and(|at| at >= failed + rto));
    b.on_timeout(failed + rto - 1, 16).unwrap();
    let (out, token) = b
        .poll_reserved_transmit(failed + rto - 1, &mut bytes, 16)
        .unwrap();
    assert!(out.packet.is_none() && token.is_none());
    let retry = failed + rto;
    b.on_timeout(retry, 16).unwrap();
    let (out, token) = b.poll_reserved_transmit(retry, &mut bytes, 16).unwrap();
    let p = out.packet.unwrap();
    assert_eq!(segment(p, &bytes).0, iss);
    assert!(b.accept_transmit(retry, token.unwrap()).unwrap());
    assert_eq!(b.transport_info(child).unwrap().retransmitted, 0);
    a.input(retry + 1, p.ip, &bytes[..p.len]).unwrap();
    let ack = a
        .poll_transmit(retry + 1, &mut bytes, 16)
        .unwrap()
        .packet
        .unwrap();
    b.input(retry + 2, ack.ip, &bytes[..ack.len]).unwrap();
    assert_eq!(b.accept(listener).unwrap(), child);
    assert_eq!(b.state(child).unwrap(), State::Established);
}

// A retransmission whose next hop never resolved is no retransmission:
// withdrawing it leaves the retransmission count and backoff as the
// timeout left them, nothing is aborted, and the same range is sent again
// no earlier than one RTO after the failure.
#[test]
fn discarded_retransmission_counts_no_retransmission() {
    let (mut a, mut b, id, peer) = established();
    let mut bytes = [0; 2048];
    a.write(id, &[5; 600]).unwrap();
    let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
    let (start, _, len) = segment(out.packet.unwrap(), &bytes);
    assert_eq!(len, 600);
    assert!(a.accept_transmit(2, token.unwrap()).unwrap());
    // The segment is lost; its RTO expires.
    let expiry = a.next_deadline().unwrap();
    a.on_timeout(expiry, 16).unwrap();
    let timed_out = a.transport_info(id).unwrap();
    let (out, token) = a.poll_reserved_transmit(expiry, &mut bytes, 16).unwrap();
    assert_eq!(segment(out.packet.unwrap(), &bytes).0, start);
    let failed = expiry + 3_000_000;
    assert!(
        a.discard_unsubmitted(
            failed,
            token.unwrap(),
            Some(crate::NetworkError::SoftUnreachable),
            crate::DropReason::NeighFailed
        )
        .unwrap()
    );
    assert!(!a.is_output_reserved(id));
    assert!(soft_error(&mut a, id));
    let info = a.transport_info(id).unwrap();
    assert_eq!(
        (info.retransmitted, info.rto_backoff),
        (timed_out.retransmitted, timed_out.rto_backoff)
    );
    assert_eq!(a.close_reason(id).unwrap(), None);
    let rto = info.rto_us;
    let mut now = failed;
    let (p, token) = loop {
        a.on_timeout(now, 16).unwrap();
        let (out, token) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
        if let Some(p) = out.packet {
            break (p, token.unwrap());
        }
        now = a.next_deadline().unwrap().max(now + 1);
        assert!(now < failed + 10 * rto);
    };
    assert!(now >= failed + rto, "{now}");
    assert_eq!(segment(p, &bytes).0, start);
    assert!(a.accept_transmit(now, token).unwrap());
    b.input(now, p.ip, &bytes[..p.len]).unwrap();
    assert_eq!(b.readable_bytes(peer).unwrap(), 600);
}

// A backend that refuses output synchronously (TxOutcome::Rejected, Linux's
// NET_XMIT_DROP from a full qdisc) has the fresh segment it refused counted
// unsent: back in the unsent queue, retried on the resource-probe clock,
// with no departure and no retransmission. A backend that cannot refuse has
// nothing kept for it, and its reservation stays for the embedding to
// retry.
#[test]
fn a_synchronous_refusal_of_fresh_data_is_not_counted_sent() {
    for refusals in [true, false] {
        let (mut a, _, id, _) = established();
        a.set_local_transmit_refusals(refusals);
        assert_eq!(a.local_transmit_refusals(), refusals);
        let mut bytes = [0; 2048];
        a.write(id, &[7; 300]).unwrap();
        let (out, token) = a.poll_reserved_transmit(2, &mut bytes, 16).unwrap();
        let (start, _, len) = segment(out.packet.unwrap(), &bytes);
        assert_eq!(len, 300);
        let token = token.unwrap();
        assert_eq!(a.reject_local_output(3, token).unwrap(), refusals);
        let info = a.transport_info(id).unwrap();
        if !refusals {
            assert!(a.is_output_reserved(id));
            assert_eq!(a.drop_counts().total(), 0);
            continue;
        }
        assert!(!a.is_output_reserved(id));
        assert_eq!(a.drop_counts()[crate::DropReason::BackendRefused], 1);
        assert_eq!((info.unacked, info.notsent_bytes), (0, 300));
        assert_eq!((info.retransmitted, info.rto_backoff), (0, 0));
        let (mut retry, mut sent) = (3, None);
        for _ in 0..8 {
            retry = a.next_deadline().unwrap();
            a.on_timeout(retry, 16).unwrap();
            let (out, token) = a.poll_reserved_transmit(retry, &mut bytes, 16).unwrap();
            if let Some(p) = out.packet {
                sent = Some((p, token.unwrap()));
                break;
            }
        }
        let (p, token) = sent.unwrap();
        assert_eq!(a.transport_info(id).unwrap().resource_probes, 1);
        assert_eq!(segment(p, &bytes), (start, wire::ACK | wire::PSH, 300));
        assert!(a.accept_transmit(retry, token).unwrap());
        assert_eq!(a.transport_info(id).unwrap().total_retrans, 0);
    }
}
