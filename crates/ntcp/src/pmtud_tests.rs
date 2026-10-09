use super::*;
use crate::{OutgoingIpv4Options, PmtudConfig};

fn cfg(mtu: u32) -> ConnectionConfig {
    ConnectionConfig {
        pmtud: Some(PmtudConfig::new(mtu)),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: true,
        sack: true,
        ..config(65_536, 1460)
    }
}

fn family_pair(mut cfg: ConnectionConfig, ipv4: bool, iss: u32) -> (Connection, Connection) {
    let tuple = if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    };
    let mut a = Connection::active(tuple, cfg.clone(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let syn = wire::parse(ip(tuple), &bytes).unwrap();
    assert_eq!(syn.options.mss, Some(1460));
    cfg.pmtud = None;
    let mut b = Connection::passive(reverse(tuple), cfg, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    (a, b)
}

fn wire_packet(a: &mut Connection, now: u64, options: OutgoingIpv4Options) -> Vec<u8> {
    let tcp = packet(a, now);
    let mut out = vec![0; 65_575];
    let header = match (a.tuple.local.ip(), a.tuple.remote.ip()) {
        (core::net::IpAddr::V4(src), core::net::IpAddr::V4(dst)) => {
            let (_, n) = options.encode(src, dst, 0, &mut out[20..60]).unwrap();
            let header = 20 + n;
            out[0] = 0x40 | (header / 4) as u8;
            out[2..4].copy_from_slice(&((header + tcp.len()) as u16).to_be_bytes());
            out[6] = 0x40; // DF
            out[8] = 64;
            out[9] = 6;
            out[12..16].copy_from_slice(&src.octets());
            out[16..20].copy_from_slice(&dst.octets());
            let checksum = ntcp_ip::checksum(&out[..header]);
            out[10..12].copy_from_slice(&checksum.to_be_bytes());
            header
        }
        (core::net::IpAddr::V6(src), core::net::IpAddr::V6(dst)) => {
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
            out[6] = 6;
            out[7] = 64;
            out[8..24].copy_from_slice(&src.octets());
            out[24..40].copy_from_slice(&dst.octets());
            40
        }
        _ => unreachable!(),
    };
    out[header..header + tcp.len()].copy_from_slice(&tcp);
    out.truncate(header + tcp.len());
    let parsed = ntcp_ip::parse(&out, true).unwrap();
    wire::parse(ip(a.tuple), parsed.payload).unwrap();
    out
}

fn ack(a: &mut Connection, now: u64, end: Seq) {
    let tuple = reverse(a.tuple);
    let mut out = [0; 64];
    let options = if a.timestamps {
        let mut o = [1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0];
        o[4..8].copy_from_slice(&(now as u32).to_be_bytes());
        o[8..12].copy_from_slice(&a.timestamp_value(a.last_sent).to_be_bytes());
        o.to_vec()
    } else {
        vec![]
    };
    let n = wire::encode(
        ip(tuple),
        Header {
            source_port: tuple.local.port(),
            destination_port: tuple.remote.port(),
            sequence: a.receive.next().0,
            acknowledgment: end.0,
            flags: ACK,
            window: (65_535u32 >> a.peer_scale) as u16,
            urgent_pointer: 0,
        },
        &options,
        &[],
        &mut out,
    )
    .unwrap();
    a.input(now, &wire::parse(ip(tuple), &out[..n]).unwrap())
        .unwrap();
}

#[test]
// Tests parse complete IPv4/IPv6 packets, including timestamp options and retries.
//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//# A host MUST never reduce its estimate of the Path MTU below 68
//# octets.
//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//# If a node receives a Packet Too Big message reporting a next-hop MTU
//# that is less than the IPv6 minimum link MTU, it must discard it.
fn pmtud_wire_family_floors_options_wrap_and_receive_offer() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 100] {
            let (mut a, _) = family_pair(cfg(1500), ipv4, iss);
            let advertised = a.config.mss;
            let original_cwnd = a.congestion.cwnd();
            let original_mss = a.mss;
            a.write(&[7; 1460]).unwrap(); // insufficient trailing data: not a probe
            let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
            let ip = ntcp_ip::parse(&frame, false).unwrap();
            let segment = wire::parse(
                IpMetadata {
                    source: ip.ip.source,
                    destination: ip.ip.destination,
                },
                ip.payload,
            )
            .unwrap();
            let seq = segment.header.sequence;
            let header = if ipv4 { 20 } else { 40 };
            if !ipv4 {
                assert!(
                    !a.pmtu_feedback(41, seq, frame.len() as u32, header, 1279)
                        .unwrap()
                );
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);
            }
            let floor = if ipv4 { 68 } else { 1280 };
            assert!(
                a.pmtu_feedback(42, seq, frame.len() as u32, header, floor)
                    .unwrap()
            );
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, floor);
            assert_eq!(a.config.mss, advertised);
            assert_eq!(
                a.congestion.cwnd(),
                (u64::from(original_cwnd) * a.mss as u64 / original_mss as u64) as u32
            );
            let retry = wire_packet(&mut a, 43, OutgoingIpv4Options::default());
            assert!(retry.len() <= floor as usize);
            let ip = ntcp_ip::parse(&retry, false).unwrap();
            let retry = wire::parse(
                IpMetadata {
                    source: ip.ip.source,
                    destination: ip.ip.destination,
                },
                ip.payload,
            )
            .unwrap();
            assert_eq!(retry.header.sequence, seq);
            assert!(retry.options.timestamps.is_some());
            assert_eq!(retry.payload, &segment.payload[..retry.payload.len()]);
        }
    }
    assert!(Connection::active(tuple(), cfg(67), 0, 0).is_err());
    let mut a = Connection::active(tuple(), cfg(68), 0, 0).unwrap();
    let syn = wire_packet(&mut a, 0, OutgoingIpv4Options::default());
    assert!(syn.len() <= 68);
    let parsed = ntcp_ip::parse(&syn, false).unwrap();
    assert_eq!(
        wire::parse(
            IpMetadata {
                source: parsed.ip.source,
                destination: parsed.ip.destination
            },
            parsed.payload
        )
        .unwrap()
        .options
        .mss,
        Some(1460)
    );
}

#[test]
fn pmtud_quote_security_zero_plateaus_and_progress_deferred_candidate() {
    for iss in [0, u32::MAX - 100] {
        let (mut a, _) = family_pair(cfg(1500), true, iss);
        a.write(&[1; 1448]).unwrap();
        let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        let seq = a.snd_una;
        for (q, n, h, mtu) in [
            (seq.0 + 1, 1500, 20, 1000),
            (seq.0, 1499, 20, 1000),
            (seq.0, 1500, 24, 1000),
            (seq.0, 1500, 20, 1500),
            (seq.0, 1500, 20, 2000),
        ] {
            assert!(!a.pmtu_feedback(41, q, n, h, mtu).unwrap());
        }
        assert_eq!(frame.len(), 1500);
        // Legacy reported total >= current estimate is corrected by IHL bytes.
        assert!(a.pmtu_feedback(42, seq.0, 1500, 20, 0).unwrap());
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1006);
        let end = a.snd_nxt;
        ack(&mut a, 43, end);
        assert!(!a.pmtu_feedback(44, seq.0, 1500, 20, 68).unwrap());

        let (mut a, _) = family_pair(cfg(1500), true, iss);
        a.write(&[2; 1448]).unwrap();
        packet(&mut a, 40);
        let end = a.snd_nxt;
        ack(&mut a, 50, end); // prove 1500-byte delivery
        a.write(&[3; 1448]).unwrap();
        packet(&mut a, 60);
        let seq = a.snd_una;
        assert!(a.pmtu_feedback(61, seq.0, 1500, 20, 68).unwrap());
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500); // deferred
        ack(&mut a, 62, seq.wrapping_add(1)); // even partial progress clears
        let expiry = a.loss_timer.unwrap().1;
        a.timeout(expiry).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);

        let (mut a, _) = family_pair(cfg(1500), true, iss);
        a.write(&[2; 1448]).unwrap();
        packet(&mut a, 40);
        let end = a.snd_nxt;
        ack(&mut a, 50, end);
        a.write(&[3; 1448]).unwrap();
        packet(&mut a, 60);
        let seq = a.snd_una;
        assert!(a.pmtu_feedback(61, seq.0, 1500, 20, 68).unwrap());
        let expiry = a.loss_timer.unwrap().1;
        a.timeout(expiry).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 68);
        assert!(wire_packet(&mut a, expiry, OutgoingIpv4Options::default()).len() <= 68);
    }
}

#[test]
fn pmtud_ipv4_header_options_exact_quote_and_retransmit_budget() {
    let (mut a, _) = family_pair(cfg(1500), true, 0);
    let options = OutgoingIpv4Options {
        source_route: Some(crate::SourceRoute::new(&[], false).unwrap()),
        record_route_slots: Some(2),
        timestamp: None,
    };
    let (_, n) = options
        .encode(
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            0,
            &mut [0; 40],
        )
        .unwrap();
    assert!(n > 0);
    a.set_ip_header_len(20 + n as u16);
    a.write(&[1; 1448]).unwrap();
    let frame = wire_packet(&mut a, 40, options);
    assert_eq!(frame.len(), 1500);
    let seq = a.snd_una.0;
    assert!(!a.pmtu_feedback(41, seq, 1500, 20, 508).unwrap());
    assert!(a.pmtu_feedback(42, seq, 1500, 20 + n as u16, 508).unwrap());
    assert!(wire_packet(&mut a, 43, options).len() <= 508);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.5
//= type=test
//# To do so, it creates a probe packet such that its
//# size, including the outermost IP headers, is equal to the probe size.
fn pmtud_real_probe_ack_restore_failed_encode_and_periodic_retry() {
    for ipv4 in [true, false] {
        let (mut a, _) = family_pair(cfg(1500), ipv4, u32::MAX - 4000);
        let reduced = if ipv4 { 1006 } else { 1280 };
        a.write(&vec![1; a.mss]).unwrap();
        let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        let seq = a.snd_una.0;
        assert!(
            a.pmtu_feedback(
                41,
                seq,
                frame.len() as u32,
                if ipv4 { 20 } else { 40 },
                reduced
            )
            .unwrap()
        );
        let end = a.snd_nxt;
        ack(&mut a, 50, end);
        // The PTB holdoff survives progress, and local link updates don't raise eff.
        a.set_first_hop_mtu(51, 2000).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, reduced);
        let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
        assert!(deadline >= 600_000_041);
        a.timeout(deadline).unwrap();
        a.write(&[5; 20_000]).unwrap();
        let before = a.path_mtu_info();
        let flight = a.flight();
        assert_eq!(
            a.transmit(deadline, &mut [0; 20]),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(a.path_mtu_info(), before);
        assert_eq!(a.flight(), flight);
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        let frame = wire_packet(&mut a, deadline, OutgoingIpv4Options::default());
        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
        assert_eq!(frame.len(), probe.size as usize);
        assert!(probe.size > reduced);
        assert!(probe.size <= if ipv4 { 1500 } else { 1520 }); // scratch + peer cap
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, reduced);
        assert!(a.flight() <= a.congestion.cwnd().min(a.snd_wnd));
        ack(&mut a, deadline + 100, probe.end);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, probe.size);
        assert_eq!(a.path_mtu_info().unwrap().search_low, probe.size);
        assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        assert!(a.pmtud.as_ref().unwrap().deadline.is_none()); // active search, no 2m hold
        let next = wire_packet(&mut a, deadline + 101, OutgoingIpv4Options::default());
        assert!(next.len() > probe.size as usize);
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//# Upon additional
//# successive timeouts, search_low and eff_pmtu SHOULD be halved, with a
//# lower bound of 68 bytes for IPv4 and 1280 bytes for IPv6.
fn pmtud_full_stop_r1_halving_and_normal_congestion_response() {
    for ipv4 in [true, false] {
        let (mut a, _) = family_pair(cfg(1500), ipv4, 0);
        a.write(&[7; 1400]).unwrap();
        packet(&mut a, 40);
        for count in 1..=8 {
            let expiry = a.loss_timer.unwrap().1;
            a.timeout(expiry).unwrap();
            assert_eq!(a.consecutive_timeouts, count);
            let expected = if count < 3 {
                1500
            } else if !ipv4 {
                1280
            } else {
                (1024u32 >> (count - 3)).max(68)
            };
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, expected);
            let retry = wire_packet(&mut a, expiry, OutgoingIpv4Options::default());
            assert!(retry.len() <= expected as usize);
            assert_eq!(a.congestion.cwnd(), a.mss as u32);
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.4
//= type=test
//# In this case, the state variables eff_pmtu, search_low,
//# and search_high SHOULD NOT be updated, and the same-sized probe
//# SHOULD be attempted again as soon as the probing preconditions are
//# met (i.e., once the packetization layer has no outstanding
//# unrecovered losses).
fn pmtud_probe_isolated_and_multiple_loss_wait_for_trailing_ack() {
    for multiple in [false, true] {
        let (mut a, _) = family_pair(cfg(1500), true, 0);
        a.write(b"x").unwrap();
        packet(&mut a, 32);
        let end = a.snd_nxt;
        ack(&mut a, 33, end);
        a.write(&[9; 20_000]).unwrap();
        let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
        assert_eq!(frame.len(), probe.size as usize);
        let before = a.path_mtu_info().unwrap();
        while a.snd_nxt.distance_from(probe.start) < probe.trailing_end.distance_from(probe.start) {
            packet(&mut a, 41);
        }
        // Fast retransmit inferred through real duplicate ACKs, not a PMTU waiver.
        // First ACK updates the scaled window; three subsequent ACKs are duplicates.
        for _ in 0..4 {
            ack(&mut a, 42, probe.start);
        }
        let cwnd = a.congestion.cwnd();
        let retry = wire_packet(&mut a, 43, OutgoingIpv4Options::default());
        assert!(retry.len() <= before.search_low as usize);
        assert_eq!(a.path_mtu_info().unwrap().search_high, before.search_high);
        assert!(a.congestion.cwnd() <= cwnd);
        if multiple {
            // A partial recovery ACK exposes a second hole in the trailing window.
            ack(&mut a, 44, probe.end);
            let retry = wire_packet(&mut a, 44, OutgoingIpv4Options::default());
            let parsed = ntcp_ip::parse(&retry, false).unwrap();
            assert_eq!(
                wire::parse(ip(a.tuple), parsed.payload)
                    .unwrap()
                    .header
                    .sequence,
                probe.end.0
            );
        }
        ack(&mut a, 45, probe.trailing_end);
        let info = a.path_mtu_info().unwrap();
        if multiple {
            assert_eq!(info.search_high, before.search_high);
            assert_eq!(info.current_mtu, before.current_mtu);
        } else {
            assert_eq!(info.search_high, probe.size - 1);
            assert_eq!(info.current_mtu, before.search_low);
            let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
            assert!(deadline >= 45 + a.rto());
            a.timeout(deadline).unwrap();
            assert_eq!(a.path_mtu_info().unwrap().search_high, probe.size - 1);
        }
    }
}

#[test]
fn pmtud_probe_rwnd_queue_eor_timestamp_and_pacing_gates() {
    for gate in 0..5 {
        let mut cfg = cfg(1500);
        if gate == 4 {
            cfg.pacing = Some(crate::PacingConfig {
                max_bytes_per_second: Some(1000),
                max_burst_segments: 1,
                ..crate::PacingConfig::default()
            });
        }
        let (mut a, _) = family_pair(cfg, true, 0);
        a.write(&[1; 20_000]).unwrap();
        match gate {
            0 => a.snd_wnd = 1500,
            1 => {
                a.send = SendBuffer::new(65_536).unwrap();
                a.write(&[1; 1500]).unwrap();
            }
            2 => {
                a.config.timestamp_bytes_per_tick = 10;
            }
            3 => {
                a.rtt = RttEstimator::new(1_000_000);
            }
            _ => {}
        }
        packet(&mut a, 40);
        if gate < 4 {
            assert!(a.pmtud.as_ref().unwrap().probe.is_none());
        } else {
            let flight = a.flight();
            assert_eq!(a.transmit(40, &mut [0; 2000]), Ok(None));
            assert_eq!(a.flight(), flight);
            assert!(a.next_deadline().unwrap() > 40);
        }
    }
}

#[test]
fn pmtud_missing_peer_mss_and_small_allocation_remain_independent() {
    for ipv4 in [true, false] {
        let tuple = if ipv4 {
            tuple()
        } else {
            Tuple {
                local: "[2001:db8::1]:1000".parse().unwrap(),
                remote: "[2001:db8::2]:2000".parse().unwrap(),
            }
        };
        let mut a = Connection::active(tuple, cfg(9000), 0, 0).unwrap();
        packet(&mut a, 0);
        let mut bytes = [0; 64];
        let n = wire::encode(
            ip(reverse(tuple)),
            Header {
                source_port: tuple.remote.port(),
                destination_port: tuple.local.port(),
                sequence: 100,
                acknowledgment: 1,
                flags: SYN | ACK,
                window: 65_535,
                urgent_pointer: 0,
            },
            &[],
            &[],
            &mut bytes,
        )
        .unwrap();
        a.input(10, &wire::parse(ip(reverse(tuple)), &bytes[..n]).unwrap())
            .unwrap();
        assert_eq!(a.peer_mss, if ipv4 { 536 } else { 1220 });
        assert_eq!(a.mss, usize::from(a.peer_mss));
        assert_eq!(a.config.mss, 1460);
        a.write(&[0; 1000]).unwrap();
        let frame = wire_packet(&mut a, 20, OutgoingIpv4Options::default());
        assert!(frame.len() <= if ipv4 { 576 } else { 1280 });
    }
    let mut small = cfg(1500);
    small.mss = 64;
    let tuple = Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    };
    let a = Connection::active(tuple, small, 0, 0).unwrap();
    assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1280);
    assert_eq!(a.mss, 64);
}

#[test]
fn pmtud_eor_and_allocation_free_probe_feedback_retry() {
    let (mut a, _) = family_pair(cfg(1500), true, 0);
    a.write_with_options(&[3; 100], false, true).unwrap();
    a.write(&[4; 20_000]).unwrap();
    let first = packet(&mut a, 40);
    assert_eq!(wire::parse(ip(a.tuple), &first).unwrap().payload.len(), 100);
    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
    let mut out = [0; 2000];
    let n = crate::allocation_tests::fail_after(0, || a.transmit(41, &mut out))
        .unwrap()
        .unwrap();
    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
    assert_eq!(n + 20, probe.size as usize);
    let accepted = crate::allocation_tests::fail_after(0, || {
        a.pmtu_feedback(42, probe.start.0, probe.size, 20, 1006)
    })
    .unwrap();
    assert!(accepted);
    let n = crate::allocation_tests::fail_after(0, || a.transmit(43, &mut out))
        .unwrap()
        .unwrap();
    assert!(n + 20 <= 1006);
}

#[test]
fn pmtud_floor_clips_timestamp_and_sack_options_on_retry_and_ack() {
    let (mut a, mut b) = family_pair(cfg(1500), true, 0);
    a.write(&[1; 1448]).unwrap();
    packet(&mut a, 40);
    let seq = a.snd_una.0;
    assert!(a.pmtu_feedback(41, seq, 1500, 20, 68).unwrap());
    b.write(b"x").unwrap();
    let bytes = packet(&mut b, 42);
    let ip_b = ip(b.tuple);
    let segment = wire::parse(ip_b, &bytes).unwrap();
    let mut header = segment.header;
    header.sequence = header.sequence.wrapping_add(10);
    let mut bytes = [0; 128];
    let n = wire::encode(
        ip_b,
        header,
        segment.raw_options,
        segment.payload,
        &mut bytes,
    )
    .unwrap();
    a.input(43, &wire::parse(ip_b, &bytes[..n]).unwrap())
        .unwrap();
    let bytes = wire_packet(&mut a, 44, OutgoingIpv4Options::default());
    assert!(bytes.len() <= 68);
    let packet = ntcp_ip::parse(&bytes, false).unwrap();
    let segment = wire::parse(ip(a.tuple), packet.payload).unwrap();
    assert!(segment.options.timestamps.is_some());
    assert!(segment.options.sack_blocks[0].is_some());
    assert_eq!(segment.header.sequence, seq);
    assert!(segment.payload.len() <= 4);
}

#[test]
fn pmtud_cubic_prr_and_rate_cap_keep_original_allocation_and_pacing_debt() {
    for algorithm in [CongestionAlgorithm::Reno, CongestionAlgorithm::Cubic] {
        let mut cfg = cfg(1500);
        cfg.congestion_algorithm = algorithm;
        cfg.prr = true;
        cfg.pacing = Some(PacingConfig {
            max_bytes_per_second: Some(1000),
            max_burst_segments: 1,
            ..PacingConfig::default()
        });
        let (mut a, _) = family_pair(cfg, true, 0);
        a.write(&[1; 1448]).unwrap();
        packet(&mut a, 40);
        let old_cwnd = a.congestion.cwnd();
        let old_mss = a.mss;
        let old_allocation = a.scratch.capacity();
        let debt = a.pacer;
        let seq = a.snd_una.0;
        assert!(a.pmtu_feedback(41, seq, 1500, 20, 508).unwrap());
        assert_eq!(
            a.congestion.cwnd(),
            (u64::from(old_cwnd) * a.mss as u64 / old_mss as u64) as u32
        );
        assert_eq!(a.scratch.capacity(), old_allocation);
        assert_eq!(a.pacer, debt);
        assert_eq!(a.transport_info().mss, 456);
        assert_eq!(a.transmit(41, &mut [0; 2000]), Ok(None));
        let pacing = a.general_pacing_deadline(41).unwrap();
        assert!(pacing >= 1_448_040);
        // Service normal pacing without manufacturing a future EDT send.
        a.timeout(pacing).unwrap();
        let frame = wire_packet(&mut a, pacing, OutgoingIpv4Options::default());
        assert!(frame.len() <= 508);
    }
}

#[test]
fn pmtud_lost_probe_retry_subtracts_sack_options_once() {
    let (mut a, mut b) = family_pair(cfg(1500), true, 0);
    a.write(&[1; 20_000]).unwrap();
    packet(&mut a, 40);
    let low = a.path_mtu_info().unwrap().search_low;
    assert!(a.pmtud.as_ref().unwrap().probe.is_some());
    b.write(b"x").unwrap();
    let bytes = packet(&mut b, 41);
    let ip_b = ip(b.tuple);
    let segment = wire::parse(ip_b, &bytes).unwrap();
    let mut header = segment.header;
    header.sequence = header.sequence.wrapping_add(10);
    let mut bytes = [0; 128];
    let n = wire::encode(
        ip_b,
        header,
        segment.raw_options,
        segment.payload,
        &mut bytes,
    )
    .unwrap();
    a.input(42, &wire::parse(ip_b, &bytes[..n]).unwrap())
        .unwrap();
    let expiry = a.loss_timer.unwrap().1;
    a.timeout(expiry).unwrap();
    let frame = wire_packet(&mut a, expiry, OutgoingIpv4Options::default());
    assert_eq!(frame.len(), low as usize);
    let parsed = ntcp_ip::parse(&frame, false).unwrap();
    assert!(
        wire::parse(ip(a.tuple), parsed.payload)
            .unwrap()
            .options
            .sack_blocks[0]
            .is_some()
    );
}

#[test]
fn pmtud_timebase_and_impossible_header_budget_are_bounded() {
    for scale in [1, 1000] {
        let mut cfg = cfg(1500);
        cfg.timebase.units_per_second *= scale;
        let (mut a, _) = family_pair(cfg, true, 0);
        a.write(&[1; 1448]).unwrap();
        packet(&mut a, 40);
        let seq = a.snd_una.0;
        assert!(a.pmtu_feedback(41, seq, 1500, 20, 1006).unwrap());
        assert_eq!(
            a.pmtud.as_ref().unwrap().deadline,
            Some(41 + 600_000_000 * scale)
        );
    }
    // IPv4 options plus mandatory TCP options cannot always fit MTU 68.
    // No IP fragmentation is implemented here: never emit an oversized SYN.
    let mut a = Connection::active(tuple(), cfg(68), 0, 0).unwrap();
    a.set_ip_header_len(60);
    assert_eq!(a.transmit(0, &mut [0; 200]), Err(Error::InvalidArgument));
    assert_eq!(a.snd_nxt, a.iss);
}
