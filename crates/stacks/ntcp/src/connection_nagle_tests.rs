// Nagle as Linux's tcp_nagle_check, with Minshall's variant
// (tcp_minshall_check): a short segment waits only while an earlier short
// segment is unacknowledged. snd_sml is the end of the last new-data
// segment sent short (tcp_minshall_update).
extern crate std;

use super::*;
use crate::connection::test_support::drain_wire;
use std::vec::Vec;

// Sent payload as (offset from `base`, length); pure ACKs left out.
fn outputs(a: &mut Connection, now: Instant, base: Seq) -> Vec<(u32, usize)> {
    drain_wire(a, now, 1500, 64)
        .into_iter()
        .filter(|&(_, len, _)| len != 0)
        .map(|(sequence, len, _)| (Seq(sequence).distance_from(base), len))
        .collect()
}

fn ack(a: &mut Connection, now: Instant, through: Seq) {
    let window = (a.snd_wnd >> a.peer_scale) as u16;
    let next = a.receive.next();
    inject(a, now, next, through, ACK, window, &[]);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
//= type=test
//# A TCP implementation SHOULD implement the Nagle algorithm to coalesce
//# short segments (SHLD-7).
fn a_short_segment_waits_only_for_an_earlier_short_one() {
    for iss in [0, u32::MAX - 120] {
        let (mut a, _) = pair(config(4096, 100), iss);
        assert!(a.config.nagle);
        let base = a.snd_nxt;
        let initial = a.snd_sml;
        // Full segments leave Minshall's test as it was: a short write
        // behind them leaves at once.
        a.write(&[1; 200]).unwrap();
        assert_eq!(outputs(&mut a, 40, base), [(0, 100), (100, 100)]);
        assert_eq!(a.snd_sml, initial);
        a.write(&[2; 30]).unwrap();
        assert_eq!(outputs(&mut a, 41, base), [(200, 30)]);
        assert_eq!(a.snd_sml, base.wrapping_add(230));
        // A write's short tail follows its full segments at once.
        ack(&mut a, 50, base.wrapping_add(230));
        a.write(&[3; 250]).unwrap();
        assert_eq!(
            outputs(&mut a, 51, base),
            [(230, 100), (330, 100), (430, 50)]
        );
        assert_eq!(a.snd_sml, base.wrapping_add(480));
        // The next short segment waits for the ACK of that one, not of the
        // full segments before it.
        a.write(&[4; 30]).unwrap();
        assert_eq!(outputs(&mut a, 52, base), []);
        ack(&mut a, 60, base.wrapping_add(430));
        assert_eq!(outputs(&mut a, 60, base), []);
        ack(&mut a, 70, base.wrapping_add(480));
        assert_eq!(outputs(&mut a, 70, base), [(480, 30)]);
        assert_eq!(a.snd_sml, base.wrapping_add(510));
    }
}

// TCP_CORK holds a short segment whatever Minshall's test says, and
// NODELAY sends one an unacknowledged short segment would hold, as Linux's
// tcp_nagle_check (TCP_NAGLE_CORK, TCP_NAGLE_OFF).
#[test]
fn cork_and_nodelay_override_minshall() {
    let (mut a, _) = pair(config(4096, 100), 7);
    let base = a.snd_nxt;
    a.set_cork(true);
    a.write(&[1; 250]).unwrap();
    assert_eq!(outputs(&mut a, 40, base), [(0, 100), (100, 100)]);
    a.set_cork(false);
    assert_eq!(outputs(&mut a, 41, base), [(200, 50)]);
    a.write(&[2; 30]).unwrap();
    assert_eq!(outputs(&mut a, 42, base), []);
    a.set_nagle(false);
    assert_eq!(outputs(&mut a, 43, base), [(250, 30)]);
    // snd_sml is kept with Nagle off, as Linux updates it whatever nonagle.
    assert_eq!(a.snd_sml, base.wrapping_add(280));
    a.set_nagle(true);
    a.write(&[3; 30]).unwrap();
    assert_eq!(outputs(&mut a, 44, base), []);
}

// A MSG_MORE tail is released by the ACK after which Nagle no longer holds
// it: Linux's ACK-driven output (tcp_data_snd_check) applies the socket's
// own Nagle, here with only full segments unacknowledged.
#[test]
fn an_ack_releases_a_more_tail_once_no_short_segment_is_unacknowledged() {
    let (mut a, _) = pair(config(4096, 100), 7);
    let base = a.snd_nxt;
    a.write_with_options(&[1; 250], true, false).unwrap();
    assert_eq!(outputs(&mut a, 40, base), [(0, 100), (100, 100)]);
    ack(&mut a, 50, base.wrapping_add(100));
    assert_ne!(a.flight(), 0);
    assert_eq!(outputs(&mut a, 50, base), [(200, 50)]);
}

// Retransmissions do not move snd_sml (Linux updates it in tcp_write_xmit
// only), and a timeout keeps it: the short segment it names still holds
// the next one until its ACK.
#[test]
fn retransmissions_and_timeouts_keep_snd_sml() {
    let (mut a, _) = pair(config(4096, 100), u32::MAX - 60);
    let base = a.snd_nxt;
    a.write(&[1; 250]).unwrap();
    assert_eq!(outputs(&mut a, 40, base).len(), 3);
    let sml = base.wrapping_add(250);
    assert_eq!(a.snd_sml, sml);
    // A partial ACK inside the first segment makes its retry short.
    ack(&mut a, 50, base.wrapping_add(30));
    let rto = a.rto_deadline.unwrap();
    a.timeout(rto).unwrap();
    assert_eq!(outputs(&mut a, rto, base), [(30, 70)]);
    assert_eq!(a.snd_sml, sml);
    a.write(&[2; 30]).unwrap();
    ack(&mut a, rto + 10, base.wrapping_add(200));
    let sent = outputs(&mut a, rto + 10, base);
    assert!(sent.iter().all(|&(offset, _)| offset < 250), "{sent:?}");
    assert_eq!(a.snd_sml, sml);
    ack(&mut a, rto + 20, sml);
    assert_eq!(outputs(&mut a, rto + 20, base), [(250, 30)]);
}
