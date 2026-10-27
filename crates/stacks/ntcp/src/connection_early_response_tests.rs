use super::*;
use crate::connection::test_support::select_and_commit;
use crate::{ConnectionId, Endpoint, EndpointConfig, GsoLimits, ListenerId};

fn cfg(units: u64) -> ConnectionConfig {
    let mut c = ConnectionConfig {
        fast_open_early_response: true,
        initial_window: InitialWindow::Iw10,
        nagle: false,
        sack: true,
        rack: true,
        tlp: true,
        prr: true,
        prr_pacing: false,
        ..config(16_384, 1000)
    };
    c.timebase.units_per_second = units;
    c
}

fn opening(
    c: ConnectionConfig,
    iss: u32,
    auth: bool,
    request: &[u8],
) -> (Connection, Connection, Vec<u8>) {
    let mut peer = Connection::active(reverse(tuple()), c.clone(), 900, 0).unwrap();
    let mut cache = crate::fast_open::FastOpen::new().unwrap();
    cache.learn(
        0,
        peer.tuple.local.ip(),
        peer.tuple.remote.ip(),
        wire::FastOpenCookie::new(&[7; 8]).unwrap(),
        1000,
    );
    let cached = cache.get(0, 100, peer.tuple.local.ip(), peer.tuple.remote.ip());
    assert_eq!(
        peer.prepare_fast_open(cached, request).unwrap(),
        request.len()
    );
    let bytes = packet(&mut peer, 0);
    let syn = wire::parse(ip(peer.tuple()), &bytes).unwrap();
    let server = Connection::passive_with_receive(
        tuple(),
        c,
        iss,
        0,
        &syn,
        auth,
        &mut None,
        RxTimestamps::default(),
        RxPacketTimestamps::default(),
    )
    .unwrap();
    (peer, server, bytes)
}

fn emit_at_us(a: &mut Connection, us: u64, reserved: bool) -> Vec<u8> {
    let now = a.config.timebase.ticks_from_us(us);
    let mut out = vec![0; 65535];
    let n = select_and_commit(a, now, &mut out, reserved).expect("packet");
    out.truncate(n);
    out
}

fn acknowledge(a: &mut Connection, us: u64, count: u32, sacks: &[(u32, u32)]) {
    let now = a.config.timebase.ticks_from_us(us);
    let base = a.iss.wrapping_add(1);
    let mut options = wire::Options::default();
    if a.timestamps {
        options.timestamps = Some((
            a.timestamp_value(now),
            a.timestamp_value(a.config.timebase.ticks_from_us(20_000)),
        ));
    }
    for (entry, &(l, r)) in options.sack_blocks.iter_mut().zip(sacks) {
        *entry = Some((base.wrapping_add(l).0, base.wrapping_add(r).0));
    }
    a.input(
        now,
        &Segment {
            header: Header {
                source_port: a.tuple.remote.port(),
                destination_port: a.tuple.local.port(),
                sequence: a.receive.next().0,
                acknowledgment: base.wrapping_add(count).0,
                flags: ACK,
                window: 16_384,
                urgent_pointer: 0,
            },
            options,
            raw_options: &[],
            payload: &[],
        },
    )
    .unwrap();
}

#[test]
fn early_response_actual_gate_and_committed_synack() {
    assert!(!ConnectionConfig::default().fast_open_early_response);
    for enabled in [false, true] {
        for auth in [false, true] {
            for request in [b"".as_slice(), b"request"] {
                for reserved in [false, true] {
                    let mut c = cfg(1_000_000);
                    c.fast_open_early_response = enabled;
                    c.nagle = true; // The SYN alone must not delay the first short response.
                    let (_, mut a, _) = opening(c, u32::MAX - 2, auth, request);
                    a.write(b"reply").unwrap();
                    assert_eq!(a.transmit(10_000, &mut [0; 19]), Err(Error::OutputTooSmall));
                    assert!(!a.early_response_eligible());
                    if reserved {
                        a.transmit_selected(10_000, &mut [0; 2048], true)
                            .unwrap()
                            .unwrap();
                        assert!(!a.early_response_eligible());
                        a.reject_reserved_output();
                        assert!(!a.early_response_eligible());
                        assert_eq!(a.transmit(11_000, &mut [0; 2048]), Ok(None));
                        let mut d = a.last_departure.unwrap();
                        a.accept_reserved_output(20_000, &mut d, 0, 0, true)
                            .unwrap();
                    } else {
                        let bytes = emit_at_us(&mut a, 20_000, false);
                        let synack = wire::parse(ip(a.tuple()), &bytes).unwrap();
                        assert_eq!(synack.header.flags & (SYN | ACK), SYN | ACK);
                        assert!(synack.payload.is_empty());
                    }
                    let allowed = enabled && auth;
                    assert_eq!(a.early_response_eligible(), allowed);
                    let anchor = a.rto_deadline;
                    assert_eq!(anchor, Some(1_020_000));
                    let mut out = [0; 2048];
                    let result = a.transmit(30_000, &mut out).unwrap();
                    assert_eq!(result.is_some(), allowed);
                    if let Some(n) = result {
                        let data = wire::parse(ip(a.tuple()), &out[..n]).unwrap();
                        assert_eq!(data.header.flags & SYN, 0);
                        assert_eq!(data.payload, b"reply");
                        assert_eq!(data.header.sequence, a.iss.wrapping_add(1).0);
                    }
                    assert_eq!(a.rto_deadline, anchor);
                    assert!(a.handshake_pending());
                }
            }
        }
    }
}

#[test]
fn early_response_actual_cap_window_mss_and_bounded_early_gso() {
    for units in [1_000_000, 1_000_000_000] {
        for mss in [1000, 1460, 3000] {
            for window in [0, 700, 16_384] {
                let mut c = cfg(units);
                c.mss = mss;
                let (_, mut a, _) = opening(c, 100, true, b"request");
                // Vary receive credit without fabricating a completed handshake.
                a.snd_wnd = window;
                a.write(&vec![42; 12_000]).unwrap();
                emit_at_us(&mut a, 20_000, false);
                let anchor = a.rto_deadline;
                let cap = a
                    .initial_window()
                    .min(a.congestion.cwnd())
                    .min(window.saturating_sub(1))
                    .min(12_000);
                let mut payload = vec![0; 16_384];
                let mut sent = 0;
                for _ in 0..20 {
                    let now = a.config.timebase.ticks_from_us(600_000);
                    a.timeout(now).unwrap(); // Release SWS for a sub-MSS window tail.
                    let mut bytes = [0; 4096];
                    let Some(n) = a
                        .transmit_selected_with_gso(
                            now,
                            &mut bytes,
                            true,
                            Some(crate::output_reservation::GsoBuffer {
                                limits: GsoLimits {
                                    max_bytes: 16_384,
                                    max_segments: 16,
                                },
                                payload: &mut payload,
                            }),
                        )
                        .unwrap()
                    else {
                        break;
                    };
                    let data = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
                    assert_eq!(data.header.flags & (SYN | FIN), 0);
                    assert!(data.payload.len() <= a.mss);
                    let mut d = a.last_departure.unwrap();
                    let total = d.payload;
                    let size = d.segmentation.map_or(total, |s| s.segment_payload_len);
                    for offset in (0..total).step_by(size.max(1)) {
                        let n = size.min(total - offset);
                        a.accept_reserved_output(now, &mut d, offset, n, offset + n == total)
                            .unwrap();
                    }
                    sent += total as u32;
                    assert!(sent <= cap);
                    assert_eq!(a.rto_deadline, anchor);
                    assert!(a.tlp_deadline.is_none() && a.rack.deadline.is_none());
                }
                assert_eq!(sent, cap);
                assert_eq!(a.data_flight(), cap);
                a.write(b"more").unwrap();
                let extra = if cap
                    < a.initial_window()
                        .min(a.congestion.cwnd())
                        .min(window.saturating_sub(1))
                {
                    let bytes = emit_at_us(&mut a, 600_000, false);
                    assert_eq!(wire::parse(ip(a.tuple()), &bytes).unwrap().payload, b"more");
                    4
                } else {
                    assert_eq!(a.transmit(a.now, &mut [0; 4096]), Ok(None));
                    0
                };
                if window == 16_384 {
                    acknowledge(&mut a, 700_000, cap + extra, &[]);
                    assert!(a.handshake_complete());
                    a.write(b"after").unwrap();
                    let data = emit_at_us(&mut a, 710_000, false);
                    assert!(
                        !wire::parse(ip(a.tuple()), &data)
                            .unwrap()
                            .payload
                            .is_empty()
                    );
                }
            }
        }
    }
}

fn assert_early_response_window_boundary(window: u32) {
    for reserved in [false, true] {
        for iss in [100, u32::MAX - 100] {
            let (_, mut a, _) = opening(cfg(1_000_000), iss, true, b"request");
            // Isolate receive credit without completing the handshake.
            a.snd_wnd = window;
            a.write(&[42; 4000]).unwrap();
            emit_at_us(&mut a, 20_000, reserved);
            assert_eq!((a.flight(), a.data_flight()), (1, 0));
            let una = a.snd_una;
            let anchor = a.rto_deadline;
            let mut sent = 0;
            for now in [300_000, 600_000, 900_000] {
                a.timeout(now).unwrap(); // Release SWS for a sub-MSS window tail.
                let mut bytes = [0; 2048];
                let Some(n) = a.transmit_selected(now, &mut bytes, reserved).unwrap() else {
                    continue;
                };
                let data = wire::parse(ip(a.tuple()), &bytes[..n]).unwrap();
                assert_eq!(data.header.flags & (SYN | FIN), 0);
                assert!(!data.payload.is_empty());
                let start = Seq(data.header.sequence);
                let end = start.wrapping_add(data.payload.len() as u32);
                assert_eq!(start, a.iss.wrapping_add(1 + sent));
                assert!(
                    end.distance_from(una) <= window,
                    "early payload exceeds rwnd={window}: ISS={iss}, reserved={reserved}"
                );
                if reserved {
                    let mut d = a.last_departure.unwrap();
                    a.accept_reserved_output(now, &mut d, 0, data.payload.len(), true)
                        .unwrap();
                }
                let original = a.rack.original_retry_span(start, end).unwrap();
                assert_eq!(
                    (original.original_start, original.original_end),
                    (start, end)
                );
                assert!(original.originally_in_window);
                assert_eq!(original.successful_retries, 0);
                sent += data.payload.len() as u32;
            }
            assert_eq!(sent, window - 1);
            assert_eq!(a.data_flight(), sent);
            assert_eq!(a.flight(), window);
            assert_eq!(a.snd_nxt, una.wrapping_add(window));
            assert_eq!(
                a.transmit_selected(900_000, &mut [0; 2048], reserved),
                Ok(None)
            );
            assert_eq!(a.rto_deadline, anchor);
            assert!(a.handshake_pending());
        }
    }
}

#[test]
fn early_response_window_boundary_syn_exhausts_one_byte_window() {
    assert_early_response_window_boundary(1);
}

#[test]
fn early_response_window_boundary_small_windows_and_wrapped_iss() {
    for window in [700, 1700] {
        assert_early_response_window_boundary(window);
    }
}

#[test]
fn early_response_actual_syn_retry_anchor_and_ack_handoff() {
    for units in [1_000_000, 1_000_000_000] {
        for reserved in [false, true] {
            for iss in [100, u32::MAX - 1000] {
                for acked in [0, 500, 4000] {
                    let mut c = cfg(units);
                    c.timestamps = true;
                    c.mss = 1012;
                    c.rto_min_us = 1;
                    let (_, mut a, syn) = opening(c, iss, true, b"request");
                    a.write(&[42; 4000]).unwrap();
                    emit_at_us(&mut a, 20_000, reserved);
                    let anchor = a.rto_deadline.unwrap();
                    for us in [40_000, 50_000, 60_000, 70_000] {
                        emit_at_us(&mut a, us, reserved);
                    }
                    assert_eq!(a.data_flight(), 4000);
                    let head = a.rack.head_transmission(a.iss.wrapping_add(1));
                    let read_before = a.readable_bytes();
                    a.input(
                        a.config.timebase.ticks_from_us(80_000),
                        &wire::parse(ip(reverse(tuple())), &syn).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(a.readable_bytes(), read_before);
                    assert_eq!(a.rto_deadline, Some(anchor));
                    let retry = emit_at_us(&mut a, 90_000, reserved);
                    assert!(
                        wire::parse(ip(a.tuple()), &retry)
                            .unwrap()
                            .payload
                            .is_empty()
                    );
                    let deadline = a.rto_deadline.unwrap();
                    a.timeout(deadline).unwrap();
                    let us = a.config.timebase.us_from_ticks(deadline);
                    let retry = emit_at_us(&mut a, us, reserved);
                    let retry = wire::parse(ip(a.tuple()), &retry).unwrap();
                    assert!(retry.payload.is_empty() && retry.options.fast_open.is_none());
                    assert_eq!(a.rack.head_transmission(a.iss.wrapping_add(1)), head);
                    assert!(a.sack_post_rto.is_none());
                    assert!(a.sample.is_none());
                    assert_eq!(a.data_flight(), 4000);
                    a.write(b"x").unwrap();
                    assert_eq!(a.transmit(a.now, &mut [0; 2048]), Ok(None));
                    acknowledge(&mut a, 2_200_000, acked, &[(3000, 4000)]);
                    assert!(a.handshake_complete());
                    assert_eq!(a.acknowledged, u64::from(acked));
                    assert_eq!(a.send.len(), 4001 - acked as usize);
                    assert_eq!(a.rtt.srtt(), None);
                    assert!(a.rto() >= a.config.timebase.ticks_from_us(3_000_000));
                }
            }
        }
    }
}

#[test]
fn early_response_actual_partial_sack_prr_and_fin_wait() {
    for iss in [100, u32::MAX - 1000] {
        let mut c = cfg(1_000_000);
        c.rack = false;
        c.tlp = false;
        let (_, mut a, _) = opening(c, iss, true, b"request");
        emit_at_us(&mut a, 20_000, false);
        for (n, us) in [
            (500, 40_000),
            (500, 50_000),
            (1000, 60_000),
            (1000, 70_000),
            (1000, 80_000),
        ] {
            a.write(&vec![42; n]).unwrap();
            emit_at_us(&mut a, us, false);
        }
        a.shutdown().unwrap();
        assert_eq!(a.transmit(90_000, &mut [0; 2048]), Ok(None));
        assert_eq!(a.state, State::SynReceived);
        assert_eq!(a.fin_sequence, None);
        acknowledge(&mut a, 200_000, 500, &[(1000, 4000)]);
        assert_eq!(a.prr.unwrap().counters(), (4000, 3500, 0));
        assert_eq!(a.acknowledged, 500);
        acknowledge(&mut a, 210_000, 4000, &[]);
        let bytes = emit_at_us(&mut a, 220_000, false);
        let fin = wire::parse(ip(a.tuple()), &bytes).unwrap();
        assert!(fin.payload.is_empty());
        assert_eq!(fin.header.flags & FIN, FIN);
        assert_eq!(fin.header.sequence, iss.wrapping_add(4001));
        assert_eq!(a.transmit(220_000, &mut [0; 2048]), Ok(None));
        acknowledge(&mut a, 230_000, 4001, &[]);
        assert_eq!(a.state, State::FinWait2);
    }
}

#[test]
fn early_response_actual_pmtu_shrink_and_pacing_keep_syn_anchor() {
    for units in [1_000_000, 1_000_000_000] {
        let mut c = cfg(units);
        c.pmtud = Some(crate::PmtudConfig::new(1500));
        c.pacing = Some(crate::PacingConfig {
            max_burst_segments: 1,
            ..Default::default()
        });
        let (_, mut a, _) = opening(c, 100, true, b"request");
        a.write(&[42; 6000]).unwrap();
        emit_at_us(&mut a, 20_000, false);
        let anchor = a.rto_deadline;
        emit_at_us(&mut a, 40_000, false);
        assert_eq!(a.transmit(a.now, &mut [0; 2048]), Ok(None));
        let pace = a.general_pacing_deadline(a.now).unwrap();
        a.set_first_hop_mtu(a.now, 540).unwrap();
        assert_eq!(a.mss, 500);
        // A shrink below flight cannot create credit or discard on-wire bytes.
        a.snd_wnd = 500;
        a.timeout(pace).unwrap();
        // Existing PMTU shrink behavior queues a data-free SYN-ACK first.
        let us = a.config.timebase.us_from_ticks(pace);
        let retry = emit_at_us(&mut a, us, false);
        let retry = wire::parse(ip(a.tuple()), &retry).unwrap();
        assert_ne!(retry.header.flags & SYN, 0);
        assert!(retry.payload.is_empty());
        assert!(a.rto_deadline >= anchor);
        let anchor = a.rto_deadline;
        assert_eq!(a.transmit(pace, &mut [0; 2048]), Ok(None));
        assert_eq!(a.data_flight(), 1000);
        a.snd_wnd = 16_384;
        let us = a.config.timebase.us_from_ticks(pace);
        let bytes = emit_at_us(&mut a, us, false);
        assert_eq!(
            wire::parse(ip(a.tuple()), &bytes).unwrap().payload.len(),
            500
        );
        assert_eq!(a.rto_deadline, anchor);
        assert!(a.tlp_deadline.is_none() && a.rack.deadline.is_none());
    }
}

// Public Endpoint path: real cookie acquisition, authenticated admission, paired
// peer input and reservation ownership. No synthesized transport state.
fn public_pair(early: bool, units: u64) -> (Endpoint, Endpoint, ListenerId) {
    let make = |key, early| {
        let mut c = cfg(units);
        c.fast_open_early_response = early;
        Endpoint::new(
            EndpointConfig {
                max_connections: 16,
                max_listeners: 2,
                connection: c,
                ..Default::default()
            },
            [key; 32],
            0,
            |_| true,
        )
        .unwrap()
    };
    let mut a = make(1, false);
    let mut b = make(2, early);
    a.enable_fast_open().unwrap();
    b.enable_fast_open().unwrap();
    let listener = b.listen(tuple().local, 8).unwrap();
    b.set_listener_fast_open(listener, 2).unwrap();
    let (id, n) = a
        .connect_fast_open(0, tuple().remote, tuple().local, b"miss")
        .unwrap();
    assert_eq!(n, 0);
    let p = public_packet(&mut a, 0, false);
    b.input(0, p.0, &p.1).unwrap();
    let p = public_packet(&mut b, 1, false);
    a.input(1, p.0, &p.1).unwrap();
    let p = public_packet(&mut a, 2, false);
    b.input(2, p.0, &p.1).unwrap();
    let child = b.accept(listener).unwrap();
    a.abort(id).unwrap();
    let p = public_packet(&mut a, 3, false);
    b.input(3, p.0, &p.1).unwrap();
    a.release(id).unwrap();
    b.release(child).unwrap();
    (a, b, listener)
}

fn public_packet(a: &mut Endpoint, now: u64, reserved: bool) -> (IpMetadata, Vec<u8>) {
    let mut bytes = [0; 4096];
    let tx = if reserved {
        let (output, attempt) = a.poll_reserved_transmit(now, &mut bytes, 64).unwrap();
        let attempt = attempt.unwrap();
        assert_eq!(a.transmit_segmentation(attempt), None);
        assert!(a.accept_transmit(now, attempt).unwrap());
        output.packet.unwrap()
    } else {
        a.poll_transmit(now, &mut bytes, 64)
            .unwrap()
            .packet
            .unwrap()
    };
    (tx.ip, bytes[..tx.len].to_vec())
}

fn public_open(
    a: &mut Endpoint,
    b: &mut Endpoint,
    listener: ListenerId,
    now: u64,
) -> (ConnectionId, ConnectionId) {
    let local = core::net::SocketAddr::new(tuple().remote.ip(), 2001);
    let (client, n) = a
        .connect_fast_open(now, local, tuple().local, b"request")
        .unwrap();
    assert_eq!(n, 7);
    let p = public_packet(a, now, false);
    b.input(now, p.0, &p.1).unwrap();
    let child = b.accept(listener).unwrap();
    (client, child)
}

#[test]
fn early_response_public_paired_direct_reserved_before_final_ack() {
    for units in [1_000_000, 1_000_000_000] {
        for reserved in [false, true] {
            for early in [false, true] {
                let (mut a, mut b, listener) = public_pair(early, units);
                if reserved {
                    b.enable_output_reservations_with_gso(
                        2,
                        GsoLimits {
                            max_bytes: 8192,
                            max_segments: 8,
                        },
                    )
                    .unwrap();
                }
                let t = |us| us * (units / 1_000_000);
                let (client, child) = public_open(&mut a, &mut b, listener, t(100));
                assert_eq!(b.state(child).unwrap(), State::SynReceived);
                assert_eq!(b.read(child, &mut [0; 32]).unwrap(), 7);
                b.write(child, b"early reply").unwrap();
                let synack = public_packet(&mut b, t(200), reserved);
                assert!(wire::parse(synack.0, &synack.1).unwrap().payload.is_empty());
                a.input(t(200), synack.0, &synack.1).unwrap();
                // Client is established, but deliberately retain its final ACK locally.
                assert_eq!(a.state(client).unwrap(), State::Established);
                if early {
                    let data = public_packet(&mut b, t(300), reserved);
                    assert_eq!(
                        wire::parse(data.0, &data.1).unwrap().payload,
                        b"early reply"
                    );
                    a.input(t(300), data.0, &data.1).unwrap();
                    let mut got = [0; 32];
                    assert_eq!(a.read(client, &mut got).unwrap(), 11);
                    assert_eq!(&got[..11], b"early reply");
                    assert_eq!(b.state(child).unwrap(), State::SynReceived);
                } else {
                    assert!(
                        b.poll_transmit(t(300), &mut [0; 2048], 64)
                            .unwrap()
                            .packet
                            .is_none()
                    );
                }
                let ack = public_packet(&mut a, t(400), false);
                b.input(t(400), ack.0, &ack.1).unwrap();
                assert_eq!(b.state(child).unwrap(), State::Established);
                assert_eq!(b.acknowledged(child).unwrap(), if early { 11 } else { 0 });
                if !early {
                    let data = public_packet(&mut b, t(500), reserved);
                    assert_eq!(
                        wire::parse(data.0, &data.1).unwrap().payload,
                        b"early reply"
                    );
                }
            }
        }
    }
}

#[test]
fn early_response_public_rejected_synack_stale_attempt_and_terminal_drain() {
    let (mut a, mut b, listener) = public_pair(true, 1_000_000);
    b.enable_output_reservations().unwrap();
    let (_, child) = public_open(&mut a, &mut b, listener, 100);
    b.write(child, b"reply").unwrap();
    let mut bytes = [0; 2048];
    let (out, attempt) = b
        .poll_reserved_transmit_for(200, child, &mut bytes, 64)
        .unwrap();
    let old = attempt.unwrap();
    assert!(
        wire::parse(out.packet.unwrap().ip, &bytes[..out.packet.unwrap().len])
            .unwrap()
            .payload
            .is_empty()
    );
    assert!(
        b.poll_transmit(300, &mut bytes, 64)
            .unwrap()
            .packet
            .is_none()
    );
    assert!(b.reject_unsubmitted(old).unwrap());
    let (out, next) = b
        .poll_reserved_transmit_for(400, child, &mut bytes, 64)
        .unwrap();
    assert!(!b.accept_transmit(500, old).unwrap());
    assert_eq!(
        wire::parse(out.packet.unwrap().ip, &bytes[..out.packet.unwrap().len])
            .unwrap()
            .header
            .flags
            & SYN,
        SYN
    );
    assert!(b.accept_transmit(500, next.unwrap()).unwrap());
    assert!(b.ready_connections().any(|id| id == child));
    let data = public_packet(&mut b, 600, true);
    assert_eq!(wire::parse(data.0, &data.1).unwrap().payload, b"reply");
    b.set_application_timeout(child, Some(1000)).unwrap();
    b.on_timeout(2000, 64).unwrap();
    assert_eq!(b.close_reason(child).unwrap(), Some(CloseReason::TimedOut));
    let mut got = [0; 32];
    assert_eq!(b.read_terminal(child, &mut got).unwrap(), 7);
    assert_eq!(&got[..7], b"request");
    assert_eq!(b.read_terminal(child, &mut got).unwrap(), 0);
}

#[test]
fn early_response_public_auth_fallbacks_and_reset_debt_do_not_transmit() {
    for mode in 0..5 {
        let (mut a, mut b, listener) = public_pair(true, 1_000_000);
        b.set_listener_fast_open(listener, 1).unwrap();
        if mode >= 3 {
            let (client, child) = public_open(&mut a, &mut b, listener, 100);
            let synack = public_packet(&mut b, 200, false);
            b.write(child, b"first reply").unwrap();
            public_packet(&mut b, 210, false);
            if mode == 4 {
                // Peer reset after a genuine early response charges listener debt.
                a.input(220, synack.0, &synack.1).unwrap();
                a.abort(client).unwrap();
                let reset = public_packet(&mut a, 230, false);
                b.input(230, reset.0, &reset.1).unwrap();
                assert_eq!(b.close_reason(child).unwrap(), Some(CloseReason::Reset));
                assert_eq!(b.read_terminal(child, &mut [0; 32]).unwrap(), 7);
                b.release(child).unwrap();
            }
        }
        let local = core::net::SocketAddr::new(tuple().remote.ip(), 2002);
        let (_, n) = a
            .connect_fast_open(300, local, tuple().local, b"second")
            .unwrap();
        assert_eq!(n, 6);
        let syn = public_packet(&mut a, 300, false);
        let parsed = wire::parse(syn.0, &syn.1).unwrap();
        let mut options = parsed.raw_options.to_vec();
        if mode == 0 {
            // Invalid authentication with structurally valid cookie.
            let position = options.windows(2).position(|b| b == [34, 10]).unwrap();
            options[position + 2] ^= 1;
        }
        if mode == 1 {
            // A data-less ordinary SYN has no authenticated early capability.
            let position = options.windows(2).position(|b| b == [34, 10]).unwrap();
            options[position..position + 10].fill(1);
        }
        if mode == 2 {
            b.set_listener_fast_open(listener, 0).unwrap();
        }
        let mut bytes = [0; 2048];
        let len = wire::encode(
            syn.0,
            parsed.header,
            &options,
            if mode == 1 { &[] } else { parsed.payload },
            &mut bytes,
        )
        .unwrap();
        b.input(310, syn.0, &bytes[..len]).unwrap();
        assert!(b.accept(listener).is_err());
        let out = b
            .poll_transmit(320, &mut bytes, 64)
            .unwrap()
            .packet
            .unwrap();
        let fallback = wire::parse(out.ip, &bytes[..out.len]).unwrap();
        assert_eq!(fallback.header.flags & SYN, SYN);
        assert!(fallback.payload.is_empty());
        assert_eq!(
            fallback.header.acknowledgment,
            parsed.header.sequence.wrapping_add(1)
        );
        let child = out.connection.unwrap();
        b.write(child, b"must wait").unwrap();
        for _ in 0..4 {
            assert!(
                b.poll_transmit(330, &mut bytes, 64)
                    .unwrap()
                    .packet
                    .is_none()
            );
        }
    }
}

#[test]
fn early_response_public_reserved_data_rejection_preserves_anchor_and_accounting() {
    let (mut a, mut b, listener) = public_pair(true, 1_000_000);
    b.enable_output_reservations().unwrap();
    let (_, child) = public_open(&mut a, &mut b, listener, 100);
    b.write(child, &[42; 1000]).unwrap();
    public_packet(&mut b, 200, true);
    let mut bytes = [0; 2048];
    let (out, attempt) = b
        .poll_reserved_transmit_for(300, child, &mut bytes, 64)
        .unwrap();
    let first = attempt.unwrap();
    let original = bytes[..out.packet.unwrap().len].to_vec();
    assert!(b.reject_unsubmitted(first).unwrap());
    assert!(!b.accept_transmit(400, first).unwrap());
    assert_eq!(b.transport_info(child).unwrap().delivered_segments, 0);
    let (out, attempt) = b
        .poll_reserved_transmit_for(500, child, &mut bytes, 64)
        .unwrap();
    assert_eq!(&bytes[..out.packet.unwrap().len], &original);
    assert!(b.accept_transmit(600, attempt.unwrap()).unwrap());
    // Early data acceptance must not postpone the SYN-ACK's 200us + 1s RTO.
    b.on_timeout(1_000_200, 64).unwrap();
    let retry = public_packet(&mut b, 1_000_200, true);
    let retry = wire::parse(retry.0, &retry.1).unwrap();
    assert_eq!(retry.header.flags & SYN, SYN);
    assert!(retry.payload.is_empty());
    assert_eq!(b.state(child).unwrap(), State::SynReceived);
}

#[test]
fn early_response_cork_and_timestamp_readiness_after_reserved_synack() {
    for units in [1_000_000, 1_000_000_000] {
        let (_, mut a, _) = opening(cfg(units), 100, true, b"request");
        a.write_with_options(b"queued", true, false).unwrap();
        assert!(a.cork_deadline.is_none());
        emit_at_us(&mut a, 20_000, true);
        assert_eq!(
            a.cork_deadline,
            Some(a.config.timebase.ticks_from_us(220_000))
        );
        assert_eq!(a.transmit(a.now, &mut [0; 2048]), Ok(None));
        let end = a.cork_deadline.unwrap();
        a.timeout(end).unwrap();
        let data = emit_at_us(&mut a, 220_000, true);
        assert_eq!(
            wire::parse(ip(a.tuple()), &data).unwrap().payload,
            b"queued"
        );

        let mut c = cfg(units);
        c.timestamps = true;
        let (_, mut a, _) = opening(c, 100, true, b"r");
        a.config.timestamp_bytes_per_tick = 1; // Server-only budget; client's SYN has data.
        a.write(b"abc").unwrap();
        emit_at_us(&mut a, 20_000, true);
        assert_eq!(
            a.transmit(a.now, &mut [0; 2048]),
            Err(Error::TimestampBudgetExceeded)
        );
        assert_eq!(
            a.next_deadline(),
            Some(a.config.timebase.ticks_from_us(21_000))
        );
        a.timeout(a.next_deadline().unwrap()).unwrap();
        let data = emit_at_us(&mut a, 21_000, true);
        assert_eq!(wire::parse(ip(a.tuple()), &data).unwrap().payload, b"a");
    }
}

#[test]
fn early_response_close_drains_queue_after_handshake_and_keeps_empty_early_fin() {
    for close in [false, true] {
        for initial_window in [InitialWindow::Rfc5681, InitialWindow::Iw10] {
            let mut c = cfg(1_000_000);
            c.initial_window = initial_window;
            let (_, mut a, _) = opening(c, u32::MAX - 1000, true, b"request");
            assert_eq!(a.read(&mut [0; 32]).unwrap(), 7);
            a.write(&[42; 4500]).unwrap();
            if close {
                a.close().unwrap();
            } else {
                a.shutdown().unwrap();
            }
            emit_at_us(&mut a, 20_000, false);
            for us in [40_000, 50_000, 60_000, 70_000] {
                let bytes = emit_at_us(&mut a, us, false);
                let data = wire::parse(ip(a.tuple()), &bytes).unwrap();
                assert_eq!(data.payload.len(), 1000);
                assert_eq!(data.header.flags & FIN, 0);
            }
            let early_tail = if initial_window == InitialWindow::Iw10 {
                let bytes = emit_at_us(&mut a, 80_000, false);
                let tail = wire::parse(ip(a.tuple()), &bytes).unwrap();
                assert_eq!(tail.payload.len(), 500);
                assert_eq!(tail.header.flags & FIN, 0);
                500
            } else {
                assert_eq!(a.transmit(80_000, &mut [0; 2048]), Ok(None));
                0
            };
            assert_eq!(a.fin_sequence, None);
            assert_eq!(a.send.len(), 4500);
            acknowledge(&mut a, 200_000, 4000 + early_tail, &[]);
            let bytes = emit_at_us(&mut a, 210_000, false);
            let tail = wire::parse(ip(a.tuple()), &bytes).unwrap();
            assert_eq!(tail.payload.len(), (500 - early_tail) as usize);
            assert_eq!(tail.header.flags & FIN, FIN);
            assert_eq!(
                tail.header.sequence,
                a.iss.wrapping_add(4001 + early_tail).0
            );
            a.shutdown().unwrap();
            if close {
                a.close().unwrap();
            }
            assert_eq!(a.transmit(220_000, &mut [0; 2048]), Ok(None));
            acknowledge(&mut a, 230_000, 4501, &[]);
            assert_eq!(a.state, State::FinWait2);
            assert_eq!(a.acknowledged, 4500);
        }
    }
    let (_, mut a, _) = opening(cfg(1_000_000), 100, true, b"request");
    assert_eq!(a.read(&mut [0; 32]).unwrap(), 7);
    a.close().unwrap();
    emit_at_us(&mut a, 20_000, false);
    let bytes = emit_at_us(&mut a, 30_000, false);
    let fin = wire::parse(ip(a.tuple()), &bytes).unwrap();
    assert_eq!(fin.header.flags & FIN, FIN);
    assert!(fin.payload.is_empty());
    assert!(a.handshake_pending());
    assert_eq!(a.fin_sequence, Some(a.iss.wrapping_add(1)));
    acknowledge(&mut a, 40_000, 1, &[]);
    assert_eq!(a.state, State::FinWait2);
}

#[test]
fn passive_tfo_split_ack_history_uses_single_wire_advance() {
    for iss in [100, u32::MAX] {
        for count in [0, 500, 1000] {
            let (_, mut a, _) = opening(cfg(1_000_000), iss, true, b"request");
            emit_at_us(&mut a, 0, false); // SYN-ACK
            a.write(&[1; 1000]).unwrap();
            emit_at_us(&mut a, 20_000, false); // Early response before final handshake ACK.
            assert_eq!(a.congestion.ack_history(), None);
            acknowledge(&mut a, 100_000, count, &[]);
            assert_eq!(a.state(), State::Established);
            assert_eq!(
                a.congestion.ack_history(),
                Some((Seq(iss), Seq(iss).wrapping_add(1 + count)))
            );
            // An unchanged window/duplicate cannot replace the recorded advance.
            acknowledge(&mut a, 100_001, count, &[]);
            assert_eq!(
                a.congestion.ack_history(),
                Some((Seq(iss), Seq(iss).wrapping_add(1 + count)))
            );
        }
    }
}

#[test]
fn inventory_tfo_server_early_policy_and_pre_handshake_payload_cap() {
    extern crate std;
    for enabled in [false, true] {
        for reserved in [false, true] {
            for (response_bytes, timestamps) in [(100, false), (10000, true)] {
                let mut c = cfg(1_000_000);
                c.fast_open_early_response = enabled;
                c.mss = 1460;
                c.timestamps = timestamps;
                c.congestion_algorithm = CongestionAlgorithm::Cubic;
                c.nagle = true;
                let request = vec![42; if timestamps { 1000 } else { 10 }];
                let syn = Segment {
                    header: Header {
                        source_port: tuple().remote.port(),
                        destination_port: tuple().local.port(),
                        sequence: 100,
                        acknowledgment: 0,
                        flags: SYN,
                        window: if timestamps { 65535 } else { 32792 },
                        urgent_pointer: 0,
                    },
                    options: wire::Options {
                        mss: Some(if timestamps { 1012 } else { 1460 }),
                        sack_permitted: true,
                        timestamps: timestamps.then_some((1000, 0)),
                        ..Default::default()
                    },
                    raw_options: &[],
                    payload: &request,
                };
                // Isolate the core policy after cookie authentication, which
                // the original live scripts reach before their failing write.
                let mut a = Connection::passive_with_receive(
                    tuple(),
                    c,
                    900,
                    0,
                    &syn,
                    true,
                    &mut None,
                    RxTimestamps::default(),
                    RxPacketTimestamps::default(),
                )
                .unwrap();
                emit_at_us(&mut a, 1000, reserved);
                assert!(!a.handshake_complete());
                assert_eq!(a.read(&mut vec![0; 1000]).unwrap(), request.len());
                assert_eq!(a.write(&vec![7; response_bytes]).unwrap(), response_bytes);
                let mut lengths = Vec::new();
                let mut grouped = false;
                for _ in 0..16 {
                    let mut bytes = vec![0; 65535];
                    let mut payload = vec![0; 65535];
                    let Some(n) = a
                        .transmit_selected_with_gso(
                            10000,
                            &mut bytes,
                            reserved,
                            Some(crate::output_reservation::GsoBuffer {
                                limits: GsoLimits {
                                    max_bytes: 65536,
                                    max_segments: 16,
                                },
                                payload: &mut payload,
                            }),
                        )
                        .unwrap()
                    else {
                        break;
                    };
                    let wire = wire::parse(ip(tuple()), &bytes[..n]).unwrap();
                    assert_eq!(wire.header.flags & SYN, 0);
                    if reserved {
                        let mut d = a.last_departure.unwrap();
                        let total = d.payload;
                        grouped |= d.segmentation.is_some();
                        let size = d.segmentation.map_or(total, |s| s.segment_payload_len);
                        for offset in (0..total).step_by(size.max(1)) {
                            let n = size.min(total - offset);
                            lengths.push(n);
                            a.accept_reserved_output(10000, &mut d, offset, n, offset + n == total)
                                .unwrap();
                        }
                    } else {
                        assert!(wire.payload.len() <= a.mss);
                        lengths.push(wire.payload.len());
                    }
                }
                let sent: usize = lengths.iter().sum();
                assert_eq!(sent, if enabled { response_bytes } else { 0 });
                let before_ack_cwnd = a.congestion.cwnd();
                let mss = a.mss;
                let state = a.state();
                assert_eq!(state, State::SynReceived);
                let options = wire::Options {
                    timestamps: timestamps.then_some((1001, a.timestamp_value(1000))),
                    ..Default::default()
                };
                a.input(
                    20_000,
                    &Segment {
                        header: Header {
                            source_port: tuple().remote.port(),
                            destination_port: tuple().local.port(),
                            sequence: a.receive.next().0,
                            acknowledgment: a.iss.wrapping_add(1 + sent as u32).0,
                            flags: ACK,
                            window: 16384,
                            urgent_pointer: 0,
                        },
                        options,
                        raw_options: &[],
                        payload: &[],
                    },
                )
                .unwrap();
                assert!(a.handshake_complete());
                a.write(b"after").unwrap();
                let bytes = emit_at_us(&mut a, 21_000, reserved);
                assert!(!wire::parse(ip(tuple()), &bytes).unwrap().payload.is_empty());
                std::eprintln!(
                    "TFO_INVENTORY {{\"probe\":\"server_early_policy\",\"enabled\":{enabled},\"reserved\":{reserved},\"write_bytes\":{response_bytes},\"timestamps\":{timestamps},\"mss\":{mss},\"cwnd_bytes\":{before_ack_cwnd},\"pre_handshake_sent\":{sent},\"lengths\":{lengths:?},\"gso\":{grouped},\"handshake_completed_on_control_ack\":true}}"
                );
            }
        }
    }
}
