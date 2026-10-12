use super::*;
use core::num::NonZeroU8;

#[test]
fn handshake_limit_reserved_selection_rejection_and_acceptance() {
    let (mut a, _, _, client) = endpoints();
    a.enable_output_reservations().unwrap();
    a.set_handshake_retransmission_limit(client, NonZeroU8::new(1))
        .unwrap();
    let mut bytes = [0; 2048];
    for retry in 0..=1 {
        let now = if retry == 0 {
            0
        } else {
            a.next_deadline().unwrap()
        };
        if retry != 0 {
            a.on_timeout(now, 64).unwrap();
        }
        assert!(matches!(
            a.poll_reserved_transmit(now, &mut [0; 19], 16),
            Err(EndpointError::Connection(Error::OutputTooSmall))
        ));
        let (_, attempt) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
        let attempt = attempt.unwrap();
        assert_eq!(
            a.set_handshake_retransmission_limit(client, None),
            Err(EndpointError::OutputReserved)
        );
        assert_eq!(
            a.handshake_retransmission_limit(client),
            Ok(NonZeroU8::new(1))
        );
        assert!(a.reject_unsubmitted(attempt).unwrap());
        assert!(!a.accept_transmit(now, attempt).unwrap());
        // Repeated polls/rejections retain the same packet, not new retries.
        for _ in 0..3 {
            let (_, attempt) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
            assert!(a.reject_unsubmitted(attempt.unwrap()).unwrap());
        }
        let (_, attempt) = a.poll_reserved_transmit(now, &mut bytes, 16).unwrap();
        let accepted_at = now + 10_000;
        a.on_timeout(accepted_at, 64).unwrap();
        assert_eq!(a.state(client), Ok(State::SynSent));
        assert!(a.accept_transmit(accepted_at, attempt.unwrap()).unwrap());
        assert!(!a.accept_transmit(accepted_at, attempt.unwrap()).unwrap());
        assert_eq!(a.state(client), Ok(State::SynSent));
    }
    let end = a.next_deadline().unwrap();
    a.on_timeout(end - 1, 64).unwrap();
    assert_eq!(a.state(client), Ok(State::SynSent));
    a.on_timeout(end, 64).unwrap();
    assert_eq!(a.close_reason(client), Ok(Some(CloseReason::TimedOut)));
    assert!(
        a.poll_reserved_transmit(end, &mut bytes, 16)
            .unwrap()
            .0
            .packet
            .is_none()
    );
    a.release(client).unwrap();
    assert_eq!(
        a.set_handshake_retransmission_limit(client, None),
        Err(EndpointError::InvalidHandle)
    );
}

#[test]
fn handshake_limit_listener_snapshot_and_pending_cleanup() {
    let (mut a, mut b, listener, _) = endpoints();
    assert_eq!(
        b.listener_handshake_retransmission_limit(listener),
        Ok(None)
    );
    b.set_listener_handshake_retransmission_limit(listener, NonZeroU8::new(1))
        .unwrap();
    // Snapshot at SYN input, not at accept or SYNACK output.
    deliver(&mut b, 0, packets(&mut a, 0));
    b.set_listener_handshake_retransmission_limit(listener, NonZeroU8::new(2))
        .unwrap();
    pump(&mut a, &mut b, 0);
    let child = b.accept(listener).unwrap();
    assert_eq!(
        b.handshake_retransmission_limit(child),
        Ok(NonZeroU8::new(1))
    );
    let baseline = b.buffer_bytes();
    let (local, remote) = addresses();
    a.connect(
        10,
        core::net::SocketAddr::new(local.ip(), local.port() + 1),
        remote,
    )
    .unwrap();
    deliver(&mut b, 10, packets(&mut a, 10));
    b.set_listener_handshake_retransmission_limit(listener, None)
        .unwrap();
    assert_eq!(packets(&mut b, 10).len(), 1);
    for _ in 0..2 {
        let end = b.next_deadline().unwrap();
        b.on_timeout(end, 64).unwrap();
        assert_eq!(packets(&mut b, end).len(), 1);
        assert!(b.buffer_bytes() > baseline);
    }
    let end = b.next_deadline().unwrap();
    b.on_timeout(end, 64).unwrap();
    assert!(packets(&mut b, end).is_empty());
    assert_eq!(b.buffer_bytes(), baseline);
    assert_eq!(
        b.accept(listener),
        Err(EndpointError::Connection(Error::WouldBlock))
    );
    assert_eq!(b.state(child), Ok(State::Established));
}

#[test]
fn handshake_limit_time_wait_reuse_snapshots_listener() {
    let mut cfg = config();
    cfg.connection.timestamps = true;
    cfg.reuse_time_wait = true;
    let (local, remote) = addresses();
    let mut a = Endpoint::new(cfg.clone(), [1; 32], 0, test_policy).unwrap();
    let mut b = Endpoint::new(cfg, [2; 32], 0, test_policy).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let first = a.connect(0, local, remote).unwrap();
    pump(&mut a, &mut b, 1_000);
    let old = b.accept(listener).unwrap();
    b.shutdown(old).unwrap();
    pump(&mut a, &mut b, 2_000);
    a.shutdown(first).unwrap();
    pump(&mut a, &mut b, 3_000);
    assert_eq!(b.state(old), Ok(State::TimeWait));
    a.release(first).unwrap();
    b.release(old).unwrap();
    b.set_listener_handshake_retransmission_limit(listener, NonZeroU8::new(1))
        .unwrap();
    a.connect(10_000, local, remote).unwrap();
    deliver(&mut b, 11_000, packets(&mut a, 11_000));
    b.set_listener_handshake_retransmission_limit(listener, None)
        .unwrap();
    pump(&mut a, &mut b, 11_000);
    let new = b.accept(listener).unwrap();
    assert_ne!(old, new);
    assert_eq!(b.handshake_retransmission_limit(new), Ok(NonZeroU8::new(1)));
}
