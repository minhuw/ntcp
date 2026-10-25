use super::*;

fn sampled(margin_us: u64, units: u64, iss: u32) -> (Connection, Connection) {
    let cfg = ConnectionConfig {
        sack: true,
        rack: true,
        prr: true,
        tlp: true,
        tlp_timer_margin_us: margin_us,
        peer_max_ack_delay_us: 0,
        initial_window: InitialWindow::Iw10,
        rto_min_us: 200_000,
        timebase: CallerTimebase {
            units_per_second: units,
            ..Default::default()
        },
        ..config(16_384, 1000)
    };
    let timebase = cfg.timebase;
    let mut a = Connection::active(tuple(), cfg.clone(), iss, 0).unwrap();
    let syn = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple()), &syn).unwrap();
    let mut b = Connection::passive(reverse(tuple()), cfg, 900, 0, &syn).unwrap();
    let synack = packet(&mut b, 0);
    a.input(
        timebase.ticks_from_us(100),
        &wire::parse(ip(b.tuple()), &synack).unwrap(),
    )
    .unwrap();
    deliver(&mut a, &mut b, timebase.ticks_from_us(100));
    assert_eq!(a.rtt.srtt(), Some(timebase.ticks_from_us(100)));
    (a, b)
}

fn flight(a: &mut Connection, b: &mut Connection, drop_tail: bool) {
    let t = a.config.timebase;
    a.write(&[42; 4000]).unwrap();
    for index in 0..4 {
        let data = packet(a, t.ticks_from_us(200));
        if !drop_tail || index != 3 {
            b.input(
                t.ticks_from_us(300),
                &wire::parse(ip(a.tuple()), &data).unwrap(),
            )
            .unwrap();
        }
    }
    assert_eq!(a.flight(), 4000);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//= reason=Real wire handshake/data/feedback at microsecond and nanosecond caller units, including sequence wrap: zero selects the baseline, default2ms and5ms suppress a probe before ordinary feedback. A lost tail with dropped earlier ACKs is repaired exactly once at the configured deadline; an arbitrarily large margin still cannot postpone the original RTO.
//# If Now() + PTO > TCP_RTO_expiration():
//# PTO = TCP_RTO_expiration() - Now()
fn pto_margin_ack_loss_and_rto_cap_wire() {
    assert_eq!(ConnectionConfig::default().tlp_timer_margin_us, 2000);
    for units in [1_000_000, 1_000_000_000] {
        for iss in [0, u32::MAX - 1999] {
            for (margin, expected_us) in [(0, 400), (2000, 2400), (5000, 5400)] {
                let (mut a, mut b) = sampled(margin, units, iss);
                let t = a.config.timebase;
                flight(&mut a, &mut b, false);
                assert_eq!(a.tlp_deadline, Some(t.ticks_from_us(expected_us)));
                let original_rto = a.rto_deadline;
                let cwnd = a.congestion.cwnd();
                a.timeout(t.ticks_from_us(499)).unwrap();
                let mut bytes = [0; 2048];
                let output = a.transmit(t.ticks_from_us(499), &mut bytes).unwrap();
                if margin == 0 {
                    let data = wire::parse(ip(a.tuple()), &bytes[..output.unwrap()]).unwrap();
                    assert_eq!(data.header.sequence, iss.wrapping_add(3001));
                    assert_eq!(data.payload.len(), 1000);
                    assert!(a.tlp_end.is_some());
                } else {
                    assert!(output.is_none());
                    assert_eq!(a.rto_deadline, original_rto);
                    assert_eq!(a.tlp_end, None);
                }
                assert_eq!(a.congestion.cwnd(), cwnd);
                assert!(a.prr.is_none());
                b.immediate_ack();
                deliver(&mut b, &mut a, t.ticks_from_us(500));
                assert_eq!(a.transport_info().unacked, 0);
                assert_eq!(a.loss_timer, None);
                a.timeout(t.ticks_from_us(6000)).unwrap();
                assert_eq!(a.transmit(t.ticks_from_us(6000), &mut bytes), Ok(None));

                // Lose the tail and drop the receiver's earlier ACK: the
                // sender still sees a four-packet flight at the probe deadline.
                let (mut a, mut b) = sampled(margin, units, iss);
                flight(&mut a, &mut b, true);
                b.immediate_ack();
                packet(&mut b, t.ticks_from_us(300)); // dropped feedback
                let expiry = t.ticks_from_us(expected_us);
                a.timeout(expiry - 1).unwrap();
                assert_eq!(a.transmit(expiry - 1, &mut bytes), Ok(None));
                a.timeout(expiry).unwrap();
                let cwnd = a.congestion.cwnd();
                let repair = packet(&mut a, expiry);
                let data = wire::parse(ip(a.tuple()), &repair).unwrap();
                assert_eq!(data.header.sequence, iss.wrapping_add(3001));
                assert_eq!(data.payload.len(), 1000);
                assert_eq!(a.congestion.cwnd(), cwnd);
                assert!(!a.congestion.in_recovery() && a.prr.is_none());
                assert_eq!(a.loss_timer, a.rto_deadline.map(|d| (LossTimer::Rto, d)));
                a.timeout(expiry + 1).unwrap();
                assert_eq!(a.transmit(expiry + 1, &mut bytes), Ok(None));
                b.input(expiry, &data).unwrap();
                b.immediate_ack();
                deliver(&mut b, &mut a, expiry + t.ticks_from_us(100));
                assert_eq!(a.transport_info().unacked, 0);
                assert_eq!(a.loss_timer, None);
            }
            for margin in [200_000, u64::MAX] {
                let (mut a, mut b) = sampled(margin, units, iss);
                let t = a.config.timebase;
                flight(&mut a, &mut b, true);
                let rto = a.rto_deadline.unwrap();
                assert_eq!(a.tlp_deadline, Some(rto));
                a.timeout(rto - 1).unwrap();
                assert!(!a.tlp_pending && !a.retx_pending);
                assert_eq!(a.rto_deadline, Some(rto));
                assert_eq!(a.transmit(rto - 1, &mut [0; 2048]), Ok(None));
                a.timeout(rto).unwrap();
                let probe = packet(&mut a, rto);
                assert_eq!(
                    wire::parse(ip(a.tuple()), &probe).unwrap().payload.len(),
                    1000
                );
                // The existing capped-PTO tie behavior rearms RTO after its one
                // probe. Margin did not move the original fallback into the future.
                assert_eq!(a.rto_deadline, Some(rto.saturating_add(a.rto())));
                assert_eq!(t.us_from_ticks(rto), 200_200);
            }
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc8985#section-7.2
//= type=test
//= reason=With0/2ms/MAX multi-packet margin, a sampled single packet still uses exactly2*SRTT+configured10ms peer delay. Short packets preserve the separate ACK floor; removing SRTT preserves the one-second fallback and original RTO cap in both caller units.
//# Third, when the FlightSize is one segment, the sender MAY inflate the
//# PTO by TLP.max_ack_delay to accommodate a potentially delayed
//# acknowledgment and reduce the risk of spurious retransmissions.
fn pto_margin_preserves_single_short_and_unsampled_budgets() {
    for units in [1_000_000, 1_000_000_000] {
        for margin in [0, 2000, u64::MAX] {
            let (mut a, _) = sampled(margin, units, 0);
            let t = a.config.timebase;
            a.config.peer_max_ack_delay_us = 10_000;
            a.write(&[42; 1000]).unwrap();
            packet(&mut a, t.ticks_from_us(200));
            assert_eq!(a.tlp_deadline, Some(t.ticks_from_us(10_400)));
            a.rtt = RttEstimator::with_timebase(1_000_000, t);
            a.schedule_tlp();
            assert_eq!(a.tlp_deadline, a.rto_deadline);
            a.rto_deadline = Some(t.ticks_from_us(2_000_000));
            a.schedule_tlp();
            assert_eq!(a.tlp_deadline, Some(t.ticks_from_us(1_000_200)));
        }
        for margin in [0, 2000] {
            let (mut a, _) = sampled(margin, units, 0);
            let t = a.config.timebase;
            a.config.peer_max_ack_delay_us = 10_000;
            a.set_nagle(false);
            a.write(&[42; 500]).unwrap();
            packet(&mut a, t.ticks_from_us(200));
            a.write(&[43; 500]).unwrap();
            packet(&mut a, t.ticks_from_us(201));
            assert_eq!(a.tlp_deadline, Some(t.ticks_from_us(10_301)));
        }
    }
}
