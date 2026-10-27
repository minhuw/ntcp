// SPDX-License-Identifier: MIT
use super::*;
use crate::connection::test_support::drain_wire;

fn drain(a: &mut Connection, now: u64) -> usize {
    drain_wire(a, now, 2048, 1024).iter().map(|p| p.1).sum()
}

fn advance_to(a: &mut Connection, now: u64) {
    for _ in 0..1024 {
        let Some(deadline) = a.next_deadline().filter(|d| *d <= now) else {
            drain(a, now);
            return;
        };
        assert!(deadline >= a.now);
        a.timeout(deadline).unwrap();
        drain(a, deadline);
        assert!(a.next_deadline().is_none_or(|d| d > deadline));
    }
    panic!("timer servicing did not quiesce");
}

// A queued stream and real bounded ACKs naturally complete initial HyStart++.
// No congestion state, flight or delivery counters are assigned by the test.
fn established_ca(iss: u32) -> (Connection, u64) {
    let mut cfg = profile();
    cfg.send_capacity = 500_000;
    cfg.coalesce_read_window_updates = true;
    cfg.output_group_flush = true;
    cfg.tlp = false;
    let metadata = ip(reverse(tuple()));
    let mut bytes = [0; 64];
    let n = wire::encode(
        metadata,
        Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: 0,
            acknowledgment: 0,
            flags: SYN,
            window: 32792,
            urgent_pointer: 0,
        },
        &[2, 4, 3, 232, 4, 2, 1, 1, 1, 3, 3, 10],
        &[],
        &mut bytes,
    )
    .unwrap();
    let syn = wire::parse(metadata, &bytes[..n]).unwrap();
    let mut a = Connection::passive(tuple(), cfg, iss, 0, &syn).unwrap();
    drain(&mut a, 0);
    let base = Seq(iss).wrapping_add(1);
    inject(&mut a, 100_000, Seq(1), base, ACK, 514, &[]);
    assert_eq!(a.write(&vec![7; 400_000]).unwrap(), 400_000);
    drain(&mut a, 100_000);
    let mut now = 100_000;
    for step in 1..=200 {
        now += 100_000;
        advance_to(&mut a, now - 1);
        let ack = base.wrapping_add(step * 2000);
        assert!(!ack.after(a.snd_nxt));
        inject(&mut a, now, Seq(1), ack, ACK, 514, &[]);
        assert!(!a.congestion.in_recovery() && a.prr.is_none());
        drain(&mut a, now);
    }
    assert_eq!(a.flight(), 0);
    assert_eq!(a.send.len(), 0);
    assert!(a.congestion.startup_state().is_none());
    assert!(a.congestion.cwnd() > a.congestion.ssthresh());
    assert!(a.congestion.ssthresh() > a.restart_window());
    (a, now)
}

//= https://www.rfc-editor.org/rfc/rfc9438#section-4.10
//= type=test
//= reason=Real400k stream finishes HyStart without synthetic cwnd. After idle beyond RTO a10k restart window below retained threshold grows to11k on a2k ACK, in scalar/reserved output and wrap. Failed encode and cancelled reservation cannot commit the transition.
//# When _cwnd_ is no more than _ssthresh_, CUBIC MUST employ a slow
//# start algorithm.
//= https://www.rfc-editor.org/rfc/rfc9406#section-4.3
//= type=test
//= reason=Completed initial startup stays completed across idle: growth uses standard one-MSS-per-ACK SS and no new HyStart engine. Non-idle control retains ordinary CA growth.
//# An implementation SHOULD use HyStart++ only for the initial slow
//# start (when the ssthresh is at its initial value of arbitrarily high
//# per [RFC5681]) and fall back to using standard slow start for the
//# remainder of the connection lifetime.
#[test]
fn actual_idle_restart_returns_to_standard_ss_after_scalar_and_reserved_output() {
    for iss in [0, u32::MAX - 5000] {
        for reserved in [false, true] {
            let (mut a, now) = established_ca(iss);
            let at = now + 2 * a.rto();
            let threshold = a.congestion.ssthresh();
            let window = a.restart_window();
            let base = a.snd_nxt;
            advance_to(&mut a, at - 1);
            assert_eq!(a.write(&vec![8; 160_000]).unwrap(), 160_000);
            let before = format!("{:?}", a.congestion);
            assert_eq!(a.transmit(at, &mut [0; 19]), Err(Error::OutputTooSmall));
            assert_eq!(format!("{:?}", a.congestion), before);
            let mut total = 0;
            if reserved {
                let mut bytes = [0; 2048];
                let n = a.transmit_selected(at, &mut bytes, true).unwrap().unwrap();
                let packet = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
                assert_eq!(Seq(packet.header.sequence), base);
                assert_eq!(packet.payload, &[8; 1000]);
                total += packet.payload.len();
                let mut departure = a.last_departure.unwrap();
                a.accept_reserved_output(at, &mut departure, 0, packet.payload.len(), true)
                    .unwrap();
            }
            total += drain(&mut a, at);
            assert_eq!(total, window as usize);
            assert_eq!(a.congestion.cwnd(), window);
            assert_eq!(a.congestion.ssthresh(), threshold);
            let ack = base.wrapping_add(2000);
            assert!(!ack.after(a.snd_nxt));
            inject(&mut a, at + 100_000, Seq(1), ack, ACK, 514, &[]);
            assert_eq!(a.congestion.cwnd(), window + 1000);
            assert_eq!(a.congestion.ssthresh(), threshold);
            assert!(a.congestion.startup_state().is_none());
            assert!(a.prr.is_none() && !a.congestion.in_recovery());
        }
    }
}

#[test]
fn cancelled_idle_restart_restores_phase_with_the_unsubmitted_window() {
    let (mut a, now) = established_ca(0);
    let at = now + 2 * a.rto();
    advance_to(&mut a, at - 1);
    a.write(&[8; 20_000]).unwrap();
    let before = format!("{:?}", a.congestion);
    let edges = (a.snd_nxt, a.snd_una, a.last_sent);
    a.transmit_selected(at, &mut [0; 2048], true)
        .unwrap()
        .unwrap();
    assert_eq!(a.congestion.cwnd(), a.restart_window());
    assert!(a.cancel_reserved_resource(at).unwrap());
    assert_eq!(format!("{:?}", a.congestion), before);
    assert_eq!((a.snd_nxt, a.snd_una, a.last_sent), edges);
}

#[test]
fn no_idle_restart_preserves_cubic_growth_after_the_same_bulk_flow() {
    let (mut a, now) = established_ca(0);
    let remaining = a.rto().checked_sub(now - a.last_sent).unwrap();
    let at = now + remaining / 2;
    let before = a.congestion.cwnd();
    let base = a.snd_nxt;
    advance_to(&mut a, at - 1);
    a.write(&vec![8; 160_000]).unwrap();
    assert!(drain(&mut a, at) > a.restart_window() as usize);
    assert_eq!(a.congestion.cwnd(), before);
    let ack = base.wrapping_add(2000);
    assert!(!ack.after(a.snd_nxt));
    inject(&mut a, at + 100_000, Seq(1), ack, ACK, 514, &[]);
    assert!(a.congestion.cwnd() > before && a.congestion.cwnd() < before + 1000);
}
