use super::*;

#[test]
fn handshake_limit_direct_active_passive_simultaneous_and_default() {
    for role in 0..3 {
        for limited in [false, true] {
            let mut a = if role == 0 {
                Connection::active(tuple(), config(1024, 64), 100, 0).unwrap()
            } else {
                opening_for_close(config(1024, 64), 100, role == 2).0
            };
            a.set_handshake_retransmission_limit(limited.then(|| NonZeroU8::new(1).unwrap()));
            let now = a.now;
            assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(a.committed_syn_retransmissions, 0);
            packet(&mut a, now);
            // Simultaneous open already sent its original SYN; SYNACK is a retry
            // of that same sequence number and must not get a fresh budget.
            assert_eq!(a.committed_syn_retransmissions, u8::from(role == 2));
            if role != 2 {
                let now = a.rto_deadline.unwrap();
                a.timeout(now).unwrap();
                assert_eq!(a.committed_syn_retransmissions, 0);
                assert_eq!(a.transmit(now, &mut [0; 19]), Err(Error::OutputTooSmall));
                assert_eq!(a.committed_syn_retransmissions, 0);
                packet(&mut a, now);
            }
            assert_eq!(a.committed_syn_retransmissions, 1);
            let end = a.rto_deadline.unwrap();
            a.timeout(end - 1).unwrap();
            assert!(a.handshake_pending());
            a.timeout(end).unwrap();
            if limited {
                assert_eq!(a.reason, Some(CloseReason::TimedOut));
                assert_eq!(a.transmit(end, &mut [0; 2048]), Ok(None));
            } else {
                assert!(a.handshake_pending());
                packet(&mut a, end);
                assert_eq!(a.committed_syn_retransmissions, 2);
            }
        }
    }
}

#[test]
fn handshake_limit_tfo_fallback_and_changing_limit_preserve_committed_count() {
    for reserved in [false, true] {
        let mut a = Connection::active(tuple(), config(8192, 536), 100, 0).unwrap();
        let mut cache = crate::fast_open::FastOpen::new().unwrap();
        cache.learn(
            0,
            tuple().local.ip(),
            tuple().remote.ip(),
            wire::FastOpenCookie::new(&[7; 8]).unwrap(),
            536,
        );
        let cached = cache.get(0, 100, tuple().local.ip(), tuple().remote.ip());
        a.prepare_fast_open(cached, b"hello").unwrap();
        let mut bytes = [0; 2048];
        for retry in 0..=1 {
            let now = if retry == 0 {
                0
            } else {
                a.rto_deadline.unwrap()
            };
            if retry != 0 {
                a.timeout(now).unwrap();
            }
            let size = a
                .transmit_selected(now, &mut bytes, reserved)
                .unwrap()
                .unwrap();
            let syn = wire::parse(ip(tuple()), &bytes[..size]).unwrap();
            assert_ne!(syn.header.flags & SYN, 0);
            assert_eq!(syn.payload.is_empty(), retry != 0);
            if reserved {
                assert_eq!(a.committed_syn_retransmissions, 0);
                let mut d = a.last_departure.unwrap();
                a.accept_reserved_output(now + 100, &mut d, 0, syn.payload.len(), true)
                    .unwrap();
            }
            assert_eq!(a.committed_syn_retransmissions, retry);
        }
        a.set_handshake_retransmission_limit(NonZeroU8::new(2));
        a.set_handshake_retransmission_limit(None);
        a.set_handshake_retransmission_limit(NonZeroU8::new(1));
        a.timeout(a.rto_deadline.unwrap()).unwrap();
        assert_eq!(a.reason, Some(CloseReason::TimedOut));
    }
}

#[test]
fn handshake_limit_has_no_established_data_effect_and_application_deadline_wins() {
    let (mut a, _) = pair(config(8192, 536), 0);
    a.set_handshake_retransmission_limit(NonZeroU8::new(1));
    a.committed_syn_retransmissions = 1;
    a.write(b"unacknowledged").unwrap();
    packet(&mut a, 100);
    for _ in 0..2 {
        let now = a.rto_deadline.unwrap();
        a.timeout(now).unwrap();
        assert_eq!(a.state(), State::Established);
        packet(&mut a, now);
    }
    let mut a = Connection::active(tuple(), config(1024, 64), 100, 0).unwrap();
    a.set_handshake_retransmission_limit(NonZeroU8::new(1));
    a.set_application_timeout(Some(100)).unwrap();
    packet(&mut a, 0);
    a.timeout(100).unwrap();
    assert_eq!(a.reason, Some(CloseReason::TimedOut));
    assert_eq!(a.committed_syn_retransmissions, 0);
}

#[test]
fn handshake_limit_reserved_passive_and_simultaneous_count_only_departures() {
    for simultaneous in [false, true] {
        let (mut a, _) = opening_for_close(config(1024, 64), 100, simultaneous);
        a.set_handshake_retransmission_limit(NonZeroU8::new(1));
        let mut bytes = [0; 2048];
        let mut now = a.now;
        for expected in u8::from(simultaneous)..=1 {
            if expected != u8::from(simultaneous) {
                now = a.rto_deadline.unwrap();
                a.timeout(now).unwrap();
            }
            a.transmit_selected(now, &mut bytes, true).unwrap().unwrap();
            assert_eq!(a.committed_syn_retransmissions, 0);
            a.reject_reserved_output();
            assert_eq!(a.committed_syn_retransmissions, 0);
            let mut departure = a.last_departure.unwrap();
            a.accept_reserved_output(now + 100, &mut departure, 0, 0, true)
                .unwrap();
            assert_eq!(a.committed_syn_retransmissions, expected);
        }
        a.timeout(a.rto_deadline.unwrap()).unwrap();
        assert_eq!(a.reason, Some(CloseReason::TimedOut));
    }
}

#[test]
fn handshake_limit_clearing_retains_default_r2_floor() {
    let mut a = Connection::active(tuple(), config(1024, 64), 100, 0).unwrap();
    a.set_user_timeout(1_000).unwrap();
    a.set_handshake_retransmission_limit(NonZeroU8::new(1));
    packet(&mut a, 0);
    let now = a.rto_deadline.unwrap();
    a.timeout(now).unwrap();
    packet(&mut a, now);
    a.set_handshake_retransmission_limit(None);
    let now = a.rto_deadline.unwrap();
    a.timeout(now).unwrap();
    packet(&mut a, now);
    assert_eq!(a.committed_syn_retransmissions, 2);
    assert_eq!(a.user_deadline(), Some(180_000_000));
    a.timeout(179_999_999).unwrap();
    assert!(a.handshake_pending());
    a.timeout(180_000_000).unwrap();
    assert_eq!(a.reason, Some(CloseReason::TimedOut));
}
