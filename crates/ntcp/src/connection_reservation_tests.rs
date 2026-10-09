use super::*;

#[test]
fn reserved_nonhead_sack_retry_keeps_exhausted_prr_credit_and_recovery_state() {
    use crate::output_reservation::OutputReservation;
    for iss in [0, u32::MAX - 4999] {
        let mut a = strict_flight(iss);
        strict_ack(&mut a, 200_000, 0, &[(7000, 10_000)]);
        packet(&mut a, 200_000);
        strict_ack(&mut a, 200_001, 1000, &[(7000, 10_000)]);
        let mut bytes = [0; 2048];
        let mut last = 0;
        for _ in 0..20 {
            let Some(n) = a.transmit(200_001, &mut bytes).unwrap() else {
                break;
            };
            last = n;
            if a.prr.unwrap().credit() == 0 {
                break;
            }
        }
        assert_eq!(a.prr.unwrap().credit(), 0);
        let segment = wire::parse(ip(tuple()), &bytes[..last]).unwrap();
        let sequence = segment.header.sequence;
        let payload = segment.payload.to_vec();
        assert_ne!(Seq(sequence), a.snd_una);
        assert!(!payload.is_empty());
        let mut reservation = OutputReservation::new();
        reservation.bytes.resize(2048, 0);
        let token = reservation.token(None).unwrap();
        reservation.capture(
            crate::Transmit {
                connection: None,
                tx_timestamp: None,
                ipv4_options: Default::default(),
                ecn: 0,
                ip: ip(tuple()),
                len: last,
                hop_limit: 64,
                dscp: 0,
            },
            &bytes,
            token,
        );
        a.lower_mss(64).unwrap();
        let counters = a.prr.unwrap().counters();
        let recovery = a.sack_recovery.map(|r| (r.high_rxt, r.rescue_rxt, r.pipe));
        let boundaries = (a.snd_nxt, a.snd_una, a.send_base, a.send.len());
        assert_eq!(a.transmit(200_001, &mut [0; 2048]).unwrap(), None);
        let mut total = 0;
        crate::allocation_tests::fail_after(0, || {
            loop {
                let p = reservation.fragment(84, &mut bytes).unwrap();
                let s = wire::parse(p.ip, &bytes[..p.len]).unwrap();
                assert_eq!(s.header.sequence, sequence.wrapping_add(total as u32));
                assert_eq!(s.payload, &payload[total..total + s.payload.len()]);
                total += s.payload.len();
                let r = reservation.current.as_mut().unwrap();
                if r.finished {
                    break;
                }
                r.offset += r.emitted_bytes;
                r.sacks += r.emitted_sacks;
            }
        });
        assert_eq!(total, payload.len());
        assert_eq!(a.prr.unwrap().credit(), 0);
        assert_eq!(a.prr.unwrap().counters(), counters);
        assert_eq!(
            a.sack_recovery.map(|r| (r.high_rxt, r.rescue_rxt, r.pipe)),
            recovery
        );
        assert_eq!(
            (a.snd_nxt, a.snd_una, a.send_base, a.send.len()),
            boundaries
        );
    }
}

#[test]
fn reserved_rejection_withdraws_only_latest_recorded_pmtu_attempt() {
    let (mut a, _) = pair(
        ConnectionConfig {
            pmtud: Some(crate::PmtudConfig::new(1500)),
            nagle: false,
            ..config(1024, 128)
        },
        100,
    );
    a.write(b"local rejection").unwrap();
    packet(&mut a, 40);
    let range = a.last_pmtu_output.unwrap();
    let info = a.path_mtu_info();
    let counters = (a.snd_nxt, a.congestion.cwnd(), a.congestion.ssthresh());
    a.reject_reserved_output();
    assert!(a.last_pmtu_output.is_none());
    assert!(!a.pmtud.as_mut().unwrap().reject_latest(range.0, range.1));
    assert_eq!(a.path_mtu_info(), info);
    assert_eq!(
        (a.snd_nxt, a.congestion.cwnd(), a.congestion.ssthresh()),
        counters
    );

    a.write(b"another output").unwrap();
    packet(&mut a, 41);
    let range = a.last_pmtu_output.unwrap();
    a.ack_pending = true;
    packet(&mut a, 42);
    assert!(a.last_pmtu_output.is_none());
    a.reject_reserved_output();
    // A rejected pure ACK cannot erase an older sequence-bearing attempt.
    assert!(a.pmtud.as_mut().unwrap().reject_latest(range.0, range.1));
}
