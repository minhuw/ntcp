extern crate std;

use super::*;

fn sender(iss: u32, scale: u64, nagle: bool) -> Connection {
    let cfg = ConnectionConfig {
        timestamps: true,
        sack: true,
        rack: true,
        prr: true,
        prr_algorithm: PrrAlgorithm::Rfc9937,
        prr_pacing: false,
        pacing: None,
        tlp: true,
        initial_window: InitialWindow::Iw10,
        rto_min_us: 200_000,
        peer_max_ack_delay_us: 499_999,
        delayed_ack_us: 200_000,
        adaptive_ack: true,
        congestion_algorithm: CongestionAlgorithm::Cubic,
        nagle,
        timebase: CallerTimebase {
            units_per_second: 1_000_000 * scale,
            ..CallerTimebase::default()
        },
        ..config(65_536, 1460)
    };
    let mut a = Connection::active(tuple(), cfg, iss, 0).unwrap();
    packet(&mut a, 0);
    let metadata = ip(reverse(tuple()));
    let mut bytes = [0; 28];
    let size = wire::encode(
        metadata,
        Header {
            source_port: tuple().remote.port(),
            destination_port: tuple().local.port(),
            sequence: 900,
            acknowledgment: iss.wrapping_add(1),
            flags: SYN | ACK,
            window: 0,
            urgent_pointer: 0,
        },
        &[2, 4, 3, 232, 1, 1, 4, 2],
        &[],
        &mut bytes,
    )
    .unwrap();
    a.input(
        10_000 * scale,
        &wire::parse(metadata, &bytes[..size]).unwrap(),
    )
    .unwrap();
    packet(&mut a, 10_000 * scale);
    assert!(!a.timestamps && !a.scaling);
    assert_eq!(a.mss, 1000);
    assert_eq!(a.congestion.cwnd(), 10_000);
    a.write(&[0x55; 1000]).unwrap();
    assert_eq!(a.loss_timer, Some((LossTimer::Zwp, 210_000 * scale)));
    a
}

fn snapshot(a: &Connection, label: &str, wire_len: usize) -> alloc::string::String {
    std::format!(
        "{{\"label\":\"{label}\",\"wire_payload_bytes\":{wire_len},\"una\":{},\"nxt\":{},\"flight\":{},\"notsent\":{},\"cwnd\":{},\"probe_pending\":{},\"retx_pending\":{},\"loss_timer\":\"{:?}\",\"rwnd_limited_us\":{},\"prr_active\":{}}}",
        a.snd_una.0,
        a.snd_nxt.0,
        a.flight(),
        a.transport_info().notsent_bytes,
        a.congestion.cwnd(),
        a.probe_pending,
        a.retx_pending,
        a.loss_timer,
        a.transport_info().rwnd_limited_us,
        a.prr.is_some(),
    )
}

#[test]
fn modern_persist_reopen_committed_vs_pending_probe() {
    let mut traces = Vec::new();
    // 0: window before deadline handling; 1: timeout without wire output;
    // 2: probe committed before window update. Only committed output advances NXT.
    for order in 0..3 {
        for iss in [0, u32::MAX] {
            for scale in [1, 1000] {
                for nagle in [false, true] {
                    let mut a = sender(iss, scale, nagle);
                    let base = Seq(iss.wrapping_add(1));
                    let now = 210_000 * scale;
                    let mut states = vec![snapshot(&a, "queued", 0)];
                    if order != 0 {
                        a.timeout(now).unwrap();
                        assert!(a.probe_pending);
                        assert_eq!(a.snd_nxt, base);
                        states.push(snapshot(&a, "timeout_before_output", 0));
                    }
                    if order == 2 {
                        let bytes = packet(&mut a, now);
                        let segment = wire::parse(ip(tuple()), &bytes).unwrap();
                        assert_eq!(segment.header.sequence, base.0);
                        assert_eq!(segment.payload, &[0x55]);
                        assert_eq!(a.snd_nxt, base.wrapping_add(1));
                        assert_eq!(a.flight(), 1);
                        assert_eq!(a.persist_interval, 400_000 * scale);
                        states.push(snapshot(&a, "probe_committed", 1));
                    }
                    inject(&mut a, now, Seq(901), base, ACK, 2000, &[]);
                    assert_eq!(a.snd_wnd, 2000);
                    assert!(!a.probe_pending);
                    assert_eq!(a.persist_deadline, None);
                    assert_eq!(a.transport_info().rwnd_limited_us, 200_000);
                    assert!(a.prr.is_none());
                    states.push(snapshot(&a, "window_opened", 0));
                    let bytes = packet(&mut a, now);
                    let data = wire::parse(ip(tuple()), &bytes).unwrap();
                    let expected = if order == 2 { 999 } else { 1000 };
                    let seq = base.wrapping_add(u32::from(order == 2));
                    assert_eq!(
                        (data.header.sequence, data.payload.len()),
                        (seq.0, expected)
                    );
                    assert_eq!(data.header.flags, ACK | PSH);
                    assert_eq!(a.snd_nxt, base.wrapping_add(1000));
                    assert_eq!(a.snd_una, base); // Reopening never fabricates delivery.
                    assert_eq!(a.persist_probe_end, None);
                    assert_eq!(a.consecutive_timeouts, 0);
                    states.push(snapshot(&a, "immediate_data", expected));
                    traces.push(std::format!(
                        "{{\"order\":{order},\"iss\":{iss},\"ticks_per_us\":{scale},\"nagle\":{nagle},\"states\":[{}]}}",
                        states.join(",")
                    ));
                }
            }
        }
    }
    if let Ok(directory) = std::env::var("NTCP_PERSIST_REOPEN_STUDY_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            std::format!("{directory}/core-traces.json"),
            std::format!("[{}]\n", traces.join(",")),
        )
        .unwrap();
    }
}

#[test]
fn modern_persist_probe_ack_releases_tail_without_disabling_nagle() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = Seq(iss.wrapping_add(1));
        a.timeout(210_000).unwrap();
        packet(&mut a, 210_000);
        // A reopened one-byte window still has no room beyond the probe.
        inject(&mut a, 210_000, Seq(901), base, ACK, 1, &[]);
        assert_eq!(a.transmit(210_000, &mut [0; 1500]), Ok(None));
        // A real ACK of the probe byte eliminates the Nagle flight condition.
        inject(
            &mut a,
            211_000,
            Seq(901),
            base.wrapping_add(1),
            ACK,
            2000,
            &[],
        );
        let bytes = packet(&mut a, 211_000);
        let data = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            (data.header.sequence, data.payload.len()),
            (base.wrapping_add(1).0, 999)
        );
        assert_eq!(a.consecutive_timeouts, 0);
        assert_eq!(a.persist_probe_end, None);
    }
}

#[test]
fn persist_reopen_failed_output_and_one_shot_window_updates() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = Seq(iss.wrapping_add(1));
        a.timeout(210_000).unwrap();
        assert_eq!(
            a.transmit(210_000, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.snd_nxt, base);
        assert_eq!(a.persist_probe_end, None);
        packet(&mut a, 210_000);
        assert_eq!(a.persist_probe_end, Some(base.wrapping_add(1)));
        // An ACK beyond what was sent cannot reopen the window or earn credit.
        inject(
            &mut a,
            210_001,
            Seq(901),
            base.wrapping_add(2),
            ACK,
            2000,
            &[],
        );
        assert_eq!(a.snd_wnd, 0);
        assert!(!a.persist_reopen_nagle_exception());
        inject(&mut a, 210_002, Seq(901), base, ACK, 2000, &[]);
        assert!(a.persist_reopen_nagle_exception());
        assert_eq!(
            a.transmit(210_002, &mut [0; 19]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.snd_nxt, base.wrapping_add(1));
        assert!(a.persist_reopen_nagle_exception());
        let bytes = packet(&mut a, 210_002);
        let tail = wire::parse(ip(tuple()), &bytes).unwrap();
        assert_eq!(
            (tail.header.sequence, tail.payload.len()),
            (base.wrapping_add(1).0, 999)
        );
        assert_eq!(a.persist_probe_end, None);
        assert_eq!(a.snd_una, base);
        a.write(&[0x66]).unwrap();
        inject(&mut a, 210_003, Seq(901), base, ACK, 2000, &[]);
        assert_eq!(a.transmit(210_003, &mut [0; 1500]), Ok(None));
        // Only actual delivery, not another window update, releases this write.
        inject(
            &mut a,
            210_004,
            Seq(901),
            base.wrapping_add(1000),
            ACK,
            2000,
            &[],
        );
        let bytes = packet(&mut a, 210_004);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload, &[0x66]);
    }
}

#[test]
fn persist_reopen_reservations_record_and_consume_only_on_departure() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = Seq(iss.wrapping_add(1));
        a.timeout(210_000).unwrap();
        let mut out = [0; 1500];
        a.transmit_selected(210_000, &mut out, true)
            .unwrap()
            .unwrap();
        let mut probe = a.last_departure.unwrap();
        assert!(probe.persist_probe);
        assert_eq!(a.persist_probe_end, None);
        a.accept_reserved_output(210_001, &mut probe, 0, 0, false)
            .unwrap();
        assert_eq!(a.persist_probe_end, None);
        a.accept_reserved_output(210_002, &mut probe, 0, 1, true)
            .unwrap();
        assert_eq!(a.persist_probe_end, Some(base.wrapping_add(1)));
        inject(&mut a, 210_003, Seq(901), base, ACK, 2000, &[]);
        let n = a
            .transmit_selected(210_003, &mut out, true)
            .unwrap()
            .unwrap();
        let segment = wire::parse(ip(tuple()), &out[..n]).unwrap();
        assert_eq!(
            (segment.header.sequence, segment.payload.len()),
            (base.wrapping_add(1).0, 999)
        );
        let mut tail = a.last_departure.unwrap();
        assert!(!tail.persist_probe);
        assert_eq!(a.persist_probe_end, Some(base.wrapping_add(1)));
        a.accept_reserved_output(210_004, &mut tail, 0, 0, false)
            .unwrap();
        assert_eq!(a.persist_probe_end, Some(base.wrapping_add(1)));
        // A backend MTU split consumes the exception on its first accepted data.
        a.accept_reserved_output(210_005, &mut tail, 0, 400, false)
            .unwrap();
        assert_eq!(a.persist_probe_end, None);
        a.accept_reserved_output(210_006, &mut tail, 400, 599, true)
            .unwrap();
        assert_eq!(a.snd_una, base);
        assert_eq!(a.snd_nxt, base.wrapping_add(1000));
    }
}

#[test]
// Ordinary data and old-data persist retries never gain the Nagle exception.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4
//= type=test
//# A TCP implementation SHOULD implement the Nagle algorithm to
//# coalesce short segments (SHLD-7).
fn persist_reopen_ordinary_short_flight_still_obeys_nagle() {
    for iss in [0, u32::MAX] {
        let cfg = ConnectionConfig {
            timestamps: false,
            rack: true,
            sack: true,
            prr: true,
            prr_algorithm: PrrAlgorithm::Rfc9937,
            rto_min_us: 200_000,
            ..config(65_536, 1000)
        };
        let (mut a, _) = pair(cfg, iss);
        let base = a.snd_una;
        let next = a.receive.next();
        a.write(&[0x55]).unwrap();
        packet(&mut a, 100);
        assert_eq!(a.flight(), 1);
        assert_eq!(a.persist_probe_end, None);
        a.write(&[0x55; 999]).unwrap();
        assert_eq!(a.transmit(100, &mut [0; 1500]), Ok(None));
        inject(&mut a, 110, next, base, ACK, 0, &[]);
        let deadline = a.next_deadline().unwrap();
        a.timeout(deadline).unwrap();
        let bytes = packet(&mut a, deadline);
        assert_eq!(wire::parse(ip(tuple()), &bytes).unwrap().payload.len(), 1);
        assert_eq!(a.persist_probe_end, None);
        inject(&mut a, deadline + 1, next, base, ACK, 2000, &[]);
        assert!(!a.persist_reopen_nagle_exception());
        assert_eq!(a.transmit(deadline + 1, &mut [0; 1500]), Ok(None));
    }
}

#[test]
fn persist_reopen_window_cork_and_timeout_guards() {
    for iss in [0, u32::MAX] {
        let mut a = sender(iss, 1, true);
        let base = Seq(iss.wrapping_add(1));
        a.timeout(210_000).unwrap();
        packet(&mut a, 210_000);
        inject(&mut a, 210_000, Seq(901), base, ACK, 1, &[]);
        assert!(a.persist_reopen_nagle_exception());
        // Exemption is only from Nagle, never from the receive window.
        assert_eq!(a.transmit(210_000, &mut [0; 1500]), Ok(None));
        a.set_cork(true);
        inject(&mut a, 210_001, Seq(901), base, ACK, 2000, &[]);
        assert_eq!(a.transmit(210_001, &mut [0; 1500]), Ok(None));
        a.set_cork(false);
        packet(&mut a, 210_001);
        assert_eq!(a.persist_probe_end, None);

        let mut a = sender(iss, 1, true);
        a.timeout(210_000).unwrap();
        packet(&mut a, 210_000);
        inject(&mut a, 210_000, Seq(901), base, ACK, 1, &[]);
        a.timeout(610_000).unwrap();
        assert_eq!(a.persist_probe_end, None);
        assert!(!a.persist_reopen_nagle_exception());
        assert_eq!(a.consecutive_timeouts, 1);
        let mut a = sender(iss, 1, true);
        a.timeout(210_000).unwrap();
        packet(&mut a, 210_000);
        a.terminal(CloseReason::Aborted);
        assert_eq!(a.persist_probe_end, None);
    }
}
