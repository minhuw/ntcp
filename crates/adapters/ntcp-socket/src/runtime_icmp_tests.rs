// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Child module of runtime_memory_tests: actual packet admission and shared egress.
use super::fast_open_tests::{tfo_capture, tfo_deliver};
use super::*;

fn icmp_error_frame(packet: &[u8], kind: u8, code: u8) -> Vec<u8> {
    let mut bytes = ptb_frame(packet);
    bytes[20] = kind;
    bytes[21] = code;
    bytes[24..28].fill(0);
    ptb_checksums(&mut bytes);
    bytes
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//= reason=Real IPv4 packet admission and scheduler dispatch notify the selected socket via SO_ERROR; soft reports retain Established state, cwnd and successful writes. Other connections remain unchanged.
//# Since these Unreachable messages indicate soft error conditions, a
//# TCP implementation MUST NOT abort the connection (MUST-56), and it
//# SHOULD make the information available to the application (SHLD-25).
fn packet_icmp_error_codes_notify_without_soft_abort_and_isolate_connections() {
    for (kind, code, error, errno) in [
        (3, 0, ntcp::NetworkError::SoftUnreachable, EHOSTUNREACH),
        (3, 1, ntcp::NetworkError::SoftUnreachable, EHOSTUNREACH),
        (3, 5, ntcp::NetworkError::SoftUnreachable, EHOSTUNREACH),
        (3, 13, ntcp::NetworkError::SoftUnreachable, EHOSTUNREACH),
        (11, 0, ntcp::NetworkError::TimeExceeded, ETIMEDOUT),
        (12, 0, ntcp::NetworkError::ParameterProblem, EPROTO),
        (3, 2, ntcp::NetworkError::HardUnreachable, EHOSTUNREACH),
        (3, 3, ntcp::NetworkError::HardUnreachable, EHOSTUNREACH),
    ] {
        let (mut a, _, clients, _) = ptb_pair(8);
        let id = cid(&a, clients[0]);
        let other = cid(&a, clients[1]);
        a.execute(clients[0], Op::Write(vec![7; 1460])).unwrap();
        let packet = tfo_capture(&mut a);
        let before = a.endpoint.transport_info(id).unwrap();
        let feedback = icmp_error_frame(&packet, kind, code);
        assert_eq!(
            ntcp_icmp::decode_icmp(&feedback)
                .unwrap()
                .ipv4_network_error(),
            Some(error)
        );
        tfo_deliver(&mut a, feedback.clone());
        assert_ne!(
            a.execute(clients[0], Op::Ready).unwrap().value & EPOLLERR,
            0
        );
        assert_eq!(
            a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            errno
        );
        assert_eq!(
            a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            a.execute(clients[1], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        assert_eq!(a.endpoint.state(other).unwrap(), State::Established);
        assert_eq!(path_mtu(&a, clients[1]), 1500);
        if error == ntcp::NetworkError::HardUnreachable {
            assert_eq!(a.endpoint.state(id).unwrap(), State::Closed);
            let info = a.execute(clients[0], Op::Transport(1)).unwrap().bytes;
            assert_eq!(info[0], 7);
        } else {
            assert_eq!(a.endpoint.state(id).unwrap(), State::Established);
            let after = a.endpoint.transport_info(id).unwrap();
            assert_eq!(after.cwnd, before.cwnd);
            assert_eq!(path_mtu(&a, clients[0]), 1500);
            assert_eq!(
                a.execute(clients[0], Op::Ready).unwrap().value & EPOLLERR,
                0
            );
            // A repeated report is a new notification while the connection
            // stays writable; SO_ERROR is not the send_state fatal channel.
            tfo_deliver(&mut a, feedback);
            assert_eq!(
                a.execute(clients[0], Op::Write(vec![8; 1460]))
                    .unwrap()
                    .value,
                1460
            );
            assert_eq!(segment(&tfo_capture(&mut a)).payload, [8; 1460]);
            assert_eq!(
                a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                errno
            );
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
//= type=test
//= reason=Validated SourceQuench leaves the full core transport snapshot and application error state unchanged. Wrong address/ports/live sequence are ignored and corrupt checksums fail admission.
//# TCP implementations MUST silently discard any received ICMP Source
//# Quench messages (MUST-55).
fn packet_icmp_source_quench_and_bad_correlation_do_not_change_transport() {
    let (mut a, _, clients, _) = ptb_pair(8);
    let id = cid(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![7; 1460])).unwrap();
    let packet = tfo_capture(&mut a);
    let snapshot = a.endpoint.transport_info(id).unwrap();
    let quench = icmp_error_frame(&packet, 4, 0);
    tfo_deliver(&mut a, quench);
    assert_eq!(a.endpoint.transport_info(id).unwrap(), snapshot);
    assert_eq!(
        a.execute(clients[0], Op::Ready).unwrap().value & EPOLLERR,
        0
    );
    assert_eq!(
        a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        0
    );
    let valid = icmp_error_frame(&packet, 3, 3);
    for index in [16, 44, 48, 50, 52] {
        let mut wrong = valid.clone();
        wrong[index] ^= 0x40;
        if index == 16 {
            wrong[40] = wrong[16];
        }
        wrong[38..40].fill(0);
        let checksum = ntcp_ip::checksum(&wrong[28..48]);
        wrong[38..40].copy_from_slice(&checksum.to_be_bytes());
        ptb_checksums(&mut wrong);
        ntcp_icmp::decode_icmp(&wrong).unwrap();
        tfo_deliver(&mut a, wrong);
        assert_eq!(
            a.endpoint.state(id).unwrap(),
            State::Established,
            "index {index}"
        );
        assert_eq!(
            a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
    }
    // All these errors share the existing checksum/quote admission checks.
    for (kind, code) in [(3, 1), (3, 3), (4, 0), (11, 0), (12, 0)] {
        let valid = icmp_error_frame(&packet, kind, code);
        for offset in [10, 22, 38] {
            let mut corrupt = valid.clone();
            corrupt[offset] ^= 1;
            if offset == 38 {
                ptb_checksums(&mut corrupt);
            }
            assert_eq!(a.execute(0, Op::Inject(corrupt)).unwrap_err(), EINVAL);
            assert!(a.packets.as_ref().unwrap().input.is_empty());
        }
    }
}

#[test]
fn packet_icmp_non_pmtu_waits_for_reserved_owner_without_blocking_other_flow() {
    for (kind, code, hard) in [(3, 1, false), (3, 3, true), (11, 0, false)] {
        let (mut a, mut b, clients, servers) = ptb_pair(1);
        let held = cid(&a, clients[0]);
        a.execute(clients[0], Op::Write(vec![7; 4380])).unwrap();
        a.service_egress().unwrap();
        assert!(a.endpoint.is_output_reserved(held));
        let packet = a.execute(0, Op::Capture(65535)).unwrap().bytes;
        a.execute(0, Op::Inject(icmp_error_frame(&packet, kind, code)))
            .unwrap();
        receive(&mut a);
        assert!(a.egress.as_ref().unwrap().retained_rx(held));
        assert_eq!(a.endpoint.state(held).unwrap(), State::Established);
        assert_eq!(a.sockets[&clients[0]].soft_error, 0);
        assert_eq!(a.sockets[&clients[0]].error, 0);
        b.execute(servers[1], Op::Write(b"other flow".to_vec()))
            .unwrap();
        let other = tfo_capture(&mut b);
        tfo_deliver(&mut a, other);
        assert_eq!(
            a.execute(clients[1], Op::Read(64)).unwrap().bytes,
            b"other flow"
        );
        for _ in 0..2 {
            a.test_now = Some(a.now() + 1000);
            assert_eq!(segment(&tfo_capture(&mut a)).payload, [7; 1460]);
        }
        assert!(!a.endpoint.is_output_reserved(held));
        receive(&mut a);
        assert!(!a.egress.as_ref().unwrap().retained_rx(held));
        assert_eq!(
            a.endpoint.state(held).unwrap(),
            if hard {
                State::Closed
            } else {
                State::Established
            }
        );
        assert_ne!(
            a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            a.execute(clients[1], Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
    }
}

#[test]
fn packet_icmp_source_quench_is_not_retained_behind_a_reserved_owner() {
    let (mut a, _, clients, _) = ptb_pair(1);
    let held = cid(&a, clients[0]);
    a.execute(clients[0], Op::Write(vec![7; 4380])).unwrap();
    let packet = tfo_capture(&mut a);
    assert!(a.endpoint.is_output_reserved(held));
    a.execute(0, Op::Inject(icmp_error_frame(&packet, 4, 0)))
        .unwrap();
    receive(&mut a);
    assert!(!a.egress.as_ref().unwrap().retained_rx(held));
    assert_eq!(a.endpoint.state(held).unwrap(), State::Established);
    assert_eq!(a.sockets[&clients[0]].soft_error, 0);
    assert_eq!(a.sockets[&clients[0]].error, 0);
    assert_eq!(path_mtu(&a, clients[0]), 1500);
}

#[test]
fn packet_icmp_notifications_are_consumable_edges_and_fatal_error_takes_precedence() {
    let (mut a, _, clients, _) = ptb_pair(8);
    a.execute(clients[0], Op::Write(vec![7; 1460])).unwrap();
    let packet = tfo_capture(&mut a);
    tfo_deliver(&mut a, icmp_error_frame(&packet, 3, 1));
    let first = a.execute(clients[0], Op::Ready).unwrap();
    tfo_deliver(&mut a, icmp_error_frame(&packet, 11, 0));
    let second = a.execute(clients[0], Op::Ready).unwrap();
    assert_ne!(
        first.readiness_generations[2],
        second.readiness_generations[2]
    );
    tfo_deliver(&mut a, icmp_error_frame(&packet, 4, 0));
    assert_eq!(
        a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        ETIMEDOUT
    );
    assert_eq!(
        a.execute(clients[0], Op::Ready).unwrap().value & EPOLLERR,
        0
    );
    // Receive and transmit operations do not consume a nonterminal report.
    tfo_deliver(&mut a, icmp_error_frame(&packet, 11, 0));
    assert_eq!(a.execute(clients[0], Op::Read(1)).unwrap_err(), EAGAIN);
    assert_eq!(
        a.execute(clients[0], Op::Write(vec![9; 1460]))
            .unwrap()
            .value,
        1460
    );
    tfo_capture(&mut a);
    tfo_deliver(&mut a, icmp_error_frame(&packet, 3, 3));
    assert_eq!(
        a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        EHOSTUNREACH
    );
    assert_eq!(
        a.execute(clients[0], Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        0
    );
}

#[test]
fn packet_icmp_passive_reports_do_not_fail_accept_or_close_listener() {
    for code in [1, 3] {
        let mut a = owner(1, Profile::Pipeline, 8);
        let mut b = owner(2, Profile::Pipeline, 8);
        let listener = new(&mut b, SOCK_NONBLOCK);
        b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
            .unwrap();
        b.execute(listener, Op::Listen(1)).unwrap();
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                .unwrap_err(),
            EINPROGRESS
        );
        let syn = tfo_capture(&mut a);
        tfo_deliver(&mut b, syn);
        let synack = tfo_capture(&mut b);
        tfo_deliver(&mut b, icmp_error_frame(&synack, 3, code));
        assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLERR, 0);
        assert_eq!(
            b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
            EAGAIN
        );
        assert_eq!(
            b.execute(listener, Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            EHOSTUNREACH
        );
        assert_eq!(b.execute(listener, Op::Transport(1)).unwrap().bytes[0], 10);
        tfo_deliver(&mut a, synack);
        let ack = tfo_capture(&mut a);
        tfo_deliver(&mut b, ack);
        if code == 1 {
            let accepted = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            assert_eq!(
                b.endpoint.state(cid(&b, accepted)).unwrap(),
                State::Established
            );
            a.execute(client, Op::Write(b"ok".to_vec())).unwrap();
            let data = tfo_capture(&mut a);
            tfo_deliver(&mut b, data);
            assert_eq!(b.execute(accepted, Op::Read(2)).unwrap().bytes, b"ok");
        } else {
            assert_eq!(segment(&tfo_capture(&mut b)).header.flags, ntcp::wire::RST);
            assert_eq!(
                b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
        }
        assert_eq!(
            b.execute(listener, Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
    }
}

#[test]
fn packet_icmp_retained_generation_cannot_migrate_to_a_reused_tuple() {
    let (mut a, _, clients, _) = ptb_pair(1);
    let old = cid(&a, clients[0]);
    let tuple = a.endpoint.tuple(old).unwrap();
    a.execute(clients[0], Op::Write(vec![7; 4380])).unwrap();
    let packet = tfo_capture(&mut a);
    assert!(a.endpoint.is_output_reserved(old));
    let mut error = icmp_error_frame(&packet, 3, 3);
    // Two1ms backend retries advance the four-microsecond ISN clock500
    // ticks. Together with the intervening second open, the reused tuple's
    // next ISN coincides with this live byte. A missing generation guard
    // would therefore hard-abort it, rather than merely fail sequence checks.
    let colliding = segment(&packet).header.sequence.wrapping_add(500);
    error[52..56].copy_from_slice(&colliding.to_be_bytes());
    ptb_checksums(&mut error);
    a.execute(0, Op::Inject(error)).unwrap();
    receive(&mut a);
    assert!(a.egress.as_ref().unwrap().retained_rx(old));
    for _ in 0..2 {
        a.test_now = Some(a.now() + 1000);
        tfo_capture(&mut a);
    }
    assert!(!a.endpoint.is_output_reserved(old));
    // Model a core lifetime ending before deferred RX dispatch. Normal owner
    // commands are themselves held behind RX; the direct core fixture is
    // intentional so this tests the independent generation guard as well.
    let sequence = segment(&packet).header.sequence;
    assert!(
        a.endpoint
            .network_error(
                a.now(),
                tuple,
                sequence,
                ntcp::NetworkError::HardUnreachable
            )
            .unwrap()
    );
    a.endpoint.release(old).unwrap();
    a.sockets.remove(&clients[0]);
    let replacement = new(&mut a, SOCK_NONBLOCK);
    a.execute(replacement, Op::Bind(tuple.local)).unwrap();
    assert_eq!(
        a.execute(replacement, Op::Connect(tuple.remote))
            .unwrap_err(),
        EINPROGRESS
    );
    let id = cid(&a, replacement);
    assert_ne!(id, old);
    let syn = tfo_capture(&mut a);
    assert_eq!(segment(&syn).header.sequence, colliding);
    assert_eq!(a.endpoint.connection_id(tuple), Some(id));
    receive(&mut a);
    assert!(!a.egress.as_ref().unwrap().retained_rx(old));
    assert_eq!(a.endpoint.state(id).unwrap(), State::SynSent);
    assert_eq!(
        a.execute(replacement, Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        0
    );
}
