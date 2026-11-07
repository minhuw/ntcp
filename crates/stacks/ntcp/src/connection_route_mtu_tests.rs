use super::*;
use crate::connection::test_support::select_and_commit;
use crate::{Endpoint, EndpointConfig, EndpointError, GsoLimits, PmtudConfig};

fn settings(ipv4: bool, route: Option<u32>) -> ConnectionConfig {
    let mut p = PmtudConfig::new(1500);
    p.route_mtu = route;
    p.initial_search_low = Some(if ipv4 { 552 } else { 1280 });
    ConnectionConfig {
        pmtud: Some(p),
        advertised_mss: Some(600),
        initial_window: InitialWindow::Iw10,
        nagle: false,
        timestamps: false,
        sack: true,
        delayed_ack_us: 0,
        ..config(65_536, 1460)
    }
}
fn address_pair(ipv4: bool) -> Tuple {
    if ipv4 {
        tuple()
    } else {
        Tuple {
            local: "[2001:db8::1]:1000".parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        }
    }
}

#[test]
fn route_mtu_creation_and_live_updates_validate_family_and_initial_bounds() {
    for ipv4 in [true, false] {
        let floor = settings(ipv4, None).packetization_mtu_floor(ipv4);
        let max = if ipv4 { 65535 } else { 65575 };
        for bad in [0, floor - 1, max + 1] {
            let mut c = settings(ipv4, None);
            c.pmtud.as_mut().unwrap().route_mtu = Some(bad);
            assert_eq!(c.validate(ipv4), Err(Error::InvalidArgument));
        }
        let route = if ipv4 { 640 } else { 1280 };
        let c = settings(ipv4, Some(route));
        let mut a = Connection::active(address_pair(ipv4), c.clone(), 10, 0).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().first_hop_mtu, 1500);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, route);
        let before = (
            a.path_mtu_info(),
            a.now,
            a.mss,
            a.rto_deadline,
            a.syn_pending,
        );
        for bad in [0, floor - 1, max + 1] {
            assert_eq!(
                a.set_route_mtu(1000, Some(bad)),
                Err(Error::InvalidArgument)
            );
            assert_eq!(
                (
                    a.path_mtu_info(),
                    a.now,
                    a.mss,
                    a.rto_deadline,
                    a.syn_pending
                ),
                before
            );
        }
        let mut bad = c.clone();
        bad.pmtud.as_mut().unwrap().initial_mtu = Some(route + 1);
        assert_eq!(bad.validate(ipv4), Err(Error::InvalidArgument));
        let mut bad = c;
        bad.pmtud.as_mut().unwrap().initial_search_high = Some(route + 1);
        assert_eq!(bad.validate(ipv4), Err(Error::InvalidArgument));
        a.set_route_mtu(1, None).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, route);
        assert_eq!(a.path_mtu_info().unwrap().search_high, 1500);
        assert_eq!(a.path_mtu_info().unwrap().route_mtu, None);
        assert_eq!(
            a.set_route_mtu(0, Some(route)),
            Err(Error::TimeWentBackwards)
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
//= type=test
//= reason=Same-path route-cap expansion only reopens upper search space; IPv4/IPv6 real queued-data probe and peer ACK prove that effective MTU and MSS do not rise on the administrative update. No route-provider/cache/new-path integration claim.
//# If the probe size is larger than the eff_pmtu, raise eff_pmtu
//# to the probe size.
fn route_cap_expansion_sends_real_probe_without_preack_mtu_or_window_growth() {
    for ipv4 in [true, false] {
        let route = if ipv4 { 640 } else { 1280 };
        let t = address_pair(ipv4);
        let mut a = Connection::active(t, settings(ipv4, Some(route)), 10, 0).unwrap();
        let syn = packet(&mut a, 0);
        let mut peer = settings(ipv4, None);
        peer.pmtud = None;
        peer.advertised_mss = None;
        let mut b = Connection::passive(
            reverse(t),
            peer,
            900,
            10,
            &wire::parse(ip(t), &syn).unwrap(),
        )
        .unwrap();
        deliver(&mut b, &mut a, 20);
        deliver(&mut a, &mut b, 30);
        let before = (a.mss, a.congestion.cwnd(), a.receive_mss(), a.rto_deadline);
        a.set_route_mtu(40, Some(1500)).unwrap();
        assert_eq!(
            (a.mss, a.congestion.cwnd(), a.receive_mss(), a.rto_deadline),
            before
        );
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, route);
        a.write(&vec![7; if ipv4 { 4000 } else { 20_000 }]).unwrap();
        let bytes = packet(&mut a, 50);
        let probe = wire::parse(ip(t), &bytes).unwrap();
        assert_eq!(probe.payload.len(), if ipv4 { 986 } else { 1330 });
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, route);
        b.input(51, &probe).unwrap();
        deliver(&mut b, &mut a, 52);
        assert_eq!(
            a.path_mtu_info().unwrap().current_mtu,
            if ipv4 { 1026 } else { 1390 }
        );
        assert_eq!(a.receive_mss(), 600);
        assert!(!a.retx_pending);
    }
}

#[test]
fn route_decrease_repacketizes_flight_without_synthetic_delivery() {
    let mut c = settings(true, None);
    c.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    c.advertised_mss = None;
    let (mut a, _) = pair(c, 10);
    a.write(&[7; 3000]).unwrap();
    let original = packet(&mut a, 40);
    let original = wire::parse(ip(a.tuple), &original).unwrap();
    let progress = (a.snd_una, a.snd_nxt, a.acknowledged, a.rto_deadline);
    a.set_route_mtu(50, Some(640)).unwrap();
    assert_eq!(
        (a.snd_una, a.snd_nxt, a.acknowledged, a.rto_deadline),
        progress
    );
    assert!(a.retx_pending);
    a.set_route_mtu(60, None).unwrap();
    assert!(a.retx_pending);
    let repair = packet(&mut a, 60);
    let repair = wire::parse(ip(a.tuple), &repair).unwrap();
    assert_eq!(repair.header.sequence, original.header.sequence);
    assert_eq!(repair.payload.len(), 600);
    assert_eq!(a.path_mtu_info().unwrap().current_mtu, 640);
    assert_eq!(a.receive_mss(), 1460);
}

#[test]
fn endpoint_route_update_is_connection_local_and_does_not_change_template() {
    for ipv4 in [true, false] {
        let route = if ipv4 { 640 } else { 1280 };
        let t = address_pair(ipv4);
        let mut e = Endpoint::new(
            EndpointConfig {
                connection: settings(ipv4, Some(route)),
                ..Default::default()
            },
            [1; 32],
            0,
            |_| true,
        )
        .unwrap();
        let one = e.connect(0, t.local, t.remote).unwrap();
        let mut local = t.local;
        local.set_port(local.port() + 1);
        let two = e.connect(0, local, t.remote).unwrap();
        let other = e.path_mtu_info(two).unwrap();
        let budget = e.buffer_bytes();
        let invalid = settings(ipv4, None).packetization_mtu_floor(ipv4) - 1;
        assert!(e.set_route_mtu(1000, one, Some(invalid)).is_err());
        crate::allocation_tests::fail_after(0, || e.set_route_mtu(1, one, None)).unwrap();
        assert_eq!(e.path_mtu_info(two).unwrap(), other);
        assert_eq!(e.buffer_bytes(), budget);
        assert_eq!(e.path_mtu_info(one).unwrap().unwrap().first_hop_mtu, 1500);
        local.set_port(local.port() + 1);
        let three = e.connect(2, local, t.remote).unwrap();
        assert_eq!(e.path_mtu_info(three).unwrap(), other);
        assert_eq!(e.path_mtu_info(one).unwrap().unwrap().route_mtu, None);
    }
}

#[test]
fn endpoint_route_update_rejects_reserved_scalar_without_clock_or_packet_mutation() {
    let mut e = Endpoint::new(
        EndpointConfig {
            connection: settings(true, Some(640)),
            ..Default::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let id = e.connect(0, tuple().local, tuple().remote).unwrap();
    e.enable_output_reservations().unwrap();
    let mut bytes = [0; 2048];
    let (out, attempt) = e.poll_reserved_transmit(0, &mut bytes, 64).unwrap();
    let attempt = attempt.unwrap();
    let n = out.packet.unwrap().len;
    let original = bytes[..n].to_vec();
    let before = (
        e.path_mtu_info(id).unwrap(),
        e.next_deadline(),
        e.buffer_bytes(),
    );
    assert_eq!(
        e.set_route_mtu(1000, id, None),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(
        (
            e.path_mtu_info(id).unwrap(),
            e.next_deadline(),
            e.buffer_bytes()
        ),
        before
    );
    assert_eq!(bytes[..n], original);
    assert!(e.accept_transmit(1, attempt).unwrap()); // Rejection did not advance clock to1000.
    e.set_route_mtu(2, id, None).unwrap();
    assert_eq!(e.path_mtu_info(id).unwrap().unwrap().current_mtu, 640);
}

#[test]
fn endpoint_route_update_rejects_held_gso_and_preserves_descriptor() {
    let mut c = settings(true, None);
    c.pmtud.as_mut().unwrap().initial_search_low = Some(1500);
    c.advertised_mss = None;
    let make = || {
        Endpoint::new(
            EndpointConfig {
                connection: c.clone(),
                ..Default::default()
            },
            [1; 32],
            0,
            |_| true,
        )
        .unwrap()
    };
    let mut a = make();
    let mut b = make();
    let t = tuple();
    let listener = b.listen(t.remote, 4).unwrap();
    let id = a.connect(0, t.local, t.remote).unwrap();
    let mut bytes = [0; 2048];
    for i in 0..3 {
        let (src, dst) = if i == 1 {
            (&mut b, &mut a)
        } else {
            (&mut a, &mut b)
        };
        let p = src
            .poll_transmit(1, &mut bytes, 64)
            .unwrap()
            .packet
            .unwrap();
        dst.input(1, p.ip, &bytes[..p.len]).unwrap();
    }
    let _ = b.accept(listener).unwrap();
    a.enable_output_reservations_with_gso(
        1,
        GsoLimits {
            max_bytes: 5000,
            max_segments: 4,
        },
    )
    .unwrap();
    a.write(id, &[7; 5000]).unwrap();
    let (_, token) = a.poll_reserved_transmit_for(2, id, &mut bytes, 64).unwrap();
    let token = token.unwrap();
    let segmentation = a.transmit_segmentation(token).unwrap();
    let before = (
        a.path_mtu_info(id).unwrap(),
        a.send_progress(id).unwrap(),
        a.next_deadline(),
    );
    assert_eq!(
        a.set_route_mtu(1000, id, Some(640)),
        Err(EndpointError::OutputReserved)
    );
    assert_eq!(a.transmit_segmentation(token), Some(segmentation));
    assert_eq!(
        (
            a.path_mtu_info(id).unwrap(),
            a.send_progress(id).unwrap(),
            a.next_deadline()
        ),
        before
    );
    assert!(a.accept_transmit(3, token).unwrap());
    while a.is_output_reserved(id) {
        let (_, token) = a.poll_reserved_transmit_for(3, id, &mut bytes, 64).unwrap();
        assert!(a.accept_transmit(3, token.unwrap()).unwrap());
    }
    a.set_route_mtu(4, id, Some(640)).unwrap();
    assert_eq!(a.path_mtu_info(id).unwrap().unwrap().current_mtu, 640);
}

#[test]
fn endpoint_route_update_rejects_stale_generation_and_disabled_discovery() {
    let mut e = Endpoint::new(
        EndpointConfig {
            connection: settings(true, Some(640)),
            ..Default::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let old = e.connect(0, tuple().local, tuple().remote).unwrap();
    e.abort(old).unwrap();
    e.release(old).unwrap();
    e.poll_transmit(0, &mut [0; 2048], 64).unwrap();
    let new = e.connect(1, tuple().local, tuple().remote).unwrap();
    assert_ne!(old, new);
    let before = e.path_mtu_info(new).unwrap();
    assert_eq!(
        e.set_route_mtu(1000, old, None),
        Err(EndpointError::InvalidHandle)
    );
    assert_eq!(e.path_mtu_info(new).unwrap(), before);
    e.set_route_mtu(2, new, None).unwrap();

    let mut c = settings(true, None);
    c.pmtud = None;
    let mut a = Connection::active(tuple(), c, 10, 0).unwrap();
    assert_eq!(a.set_route_mtu(1000, None), Err(Error::InvalidArgument));
    assert_eq!(a.now, 0);
    assert_eq!(a.path_mtu_info(), None);
}

fn packetization_pair(
    ipv4: bool,
    timestamps: bool,
    units: u64,
    iss: u32,
    current: u32,
) -> (Connection, Connection) {
    let mut c = settings(ipv4, Some(current));
    c.timestamps = timestamps;
    c.sack = false;
    c.recovery_algorithm = RecoveryAlgorithm::Reno;
    c.timebase.units_per_second = units;
    let t = address_pair(ipv4);
    let scale = units / 1_000_000;
    let mut a = Connection::active(t, c.clone(), iss, 0).unwrap();
    let syn = packet(&mut a, 0);
    c.pmtud = None;
    c.advertised_mss = None;
    let mut b = Connection::passive(
        reverse(t),
        c,
        900,
        10 * scale,
        &wire::parse(ip(t), &syn).unwrap(),
    )
    .unwrap();
    deliver(&mut b, &mut a, 20 * scale);
    deliver(&mut a, &mut b, 30 * scale);
    a.set_route_mtu(40 * scale, Some(1500)).unwrap();
    (a, b)
}

fn packetization_output(a: &mut Connection, now: u64, reserved: bool) -> Vec<u8> {
    let mut bytes = vec![0; 2048];
    let n = select_and_commit(a, now, &mut bytes, reserved).unwrap();
    bytes.truncate(n);
    bytes
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=IPv4/IPv6 real route expansion keeps ordinary packets at current MSS while a larger explicit probe is pending. Timestamp options, wrapping sequence numbers, caller clock units and accepted reservations preserve limits; a real receiver ACK alone raises the effective PMTU. A too-small output buffer consumes no sequence or probe state.
//# If eff_pmtu is larger than search_low, it is explicitly permitted to send
//# non-probe packets larger than search_low.
fn upward_probe_keeps_current_mss_for_fresh_data_until_real_ack() {
    for ipv4 in [true, false] {
        let current = if ipv4 { 640 } else { 1320 };
        let ip_header = if ipv4 { 20 } else { 40 };
        for timestamps in [false, true] {
            for units in [1_000_000, 1_000_000_000] {
                for reserved in [false, true] {
                    for iss in [10, u32::MAX - 1500] {
                        let scale = units / 1_000_000;
                        let (mut a, mut b) =
                            packetization_pair(ipv4, timestamps, units, iss, current);
                        let mss = a.mss;
                        a.write(&[7; 20_000]).unwrap();
                        let probe = packetization_output(&mut a, 50 * scale, reserved);
                        let p = a.pmtud.as_ref().unwrap().probe.unwrap();
                        assert!(p.size > current);
                        assert_eq!(probe.len() as u32 + ip_header, p.size);
                        let state = (a.snd_nxt, a.rto_deadline, a.path_mtu_info());
                        assert_eq!(
                            a.transmit_selected(51 * scale, &mut [0; 19], reserved),
                            Err(Error::OutputTooSmall)
                        );
                        assert_eq!((a.snd_nxt, a.rto_deadline, a.path_mtu_info()), state);
                        let tail = packetization_output(&mut a, 52 * scale, reserved);
                        let tail = wire::parse(ip(a.tuple), &tail).unwrap();
                        assert_eq!(tail.header.sequence, p.end.0);
                        assert_eq!(tail.payload.len(), mss);
                        assert_eq!(a.mss, mss);
                        assert_eq!(a.path_mtu_info().unwrap().current_mtu, current);
                        b.input(53 * scale, &wire::parse(ip(a.tuple), &probe).unwrap())
                            .unwrap();
                        deliver(&mut b, &mut a, 54 * scale);
                        assert_eq!(a.path_mtu_info().unwrap().current_mtu, p.size);
                        assert!(a.mss > mss);
                        assert!(!a.retx_pending);
                    }
                }
            }
        }
    }
}

#[test]
fn upward_probe_loss_keeps_repairs_at_lower_bound() {
    for ipv4 in [true, false] {
        let current = if ipv4 { 640 } else { 1320 };
        let ip_header = if ipv4 { 20 } else { 40 };
        for timestamps in [false, true] {
            for reserved in [false, true] {
                let (mut a, mut b) =
                    packetization_pair(ipv4, timestamps, 1_000_000, u32::MAX - 1500, current);
                a.write(&[7; 20_000]).unwrap();
                packetization_output(&mut a, 50, reserved); // Lose only the larger probe.
                let p = a.pmtud.as_ref().unwrap().probe.unwrap();
                let low = a.path_mtu_info().unwrap().search_low;
                let mss = a.mss;
                let trailing: Vec<_> = (0..4)
                    .map(|n| packetization_output(&mut a, 51 + n, reserved))
                    .collect();
                for (n, tail) in trailing.iter().enumerate() {
                    assert_eq!(wire::parse(ip(a.tuple), tail).unwrap().payload.len(), mss);
                    b.input(60 + n as u64, &wire::parse(ip(a.tuple), tail).unwrap())
                        .unwrap();
                    deliver(&mut b, &mut a, 60 + n as u64);
                }
                assert!(a.retx_pending);
                assert_eq!(a.consecutive_timeouts, 0);
                assert!(a.pmtud.as_ref().unwrap().probe.is_some());
                let next = a.snd_nxt;
                let repair = packetization_output(&mut a, 70, reserved);
                let segment = wire::parse(ip(a.tuple), &repair).unwrap();
                assert_eq!(segment.header.sequence, p.start.0);
                assert_eq!(repair.len() as u32 + ip_header, low);
                assert_eq!(a.snd_nxt, next);
                assert_eq!(a.mss, mss);
            }
        }
    }
}

#[test]
fn below_estimate_probe_keeps_small_surrounding_packets() {
    for ipv4 in [true, false] {
        for timestamps in [false, true] {
            let (mut a, _) = packetization_pair(ipv4, timestamps, 1_000_000, 10, 1500);
            a.write(&[7; 20_000]).unwrap();
            packetization_output(&mut a, 50, false);
            let p = a.pmtud.as_ref().unwrap().probe.unwrap();
            let before = a.path_mtu_info().unwrap();
            assert!(p.size < before.current_mtu);
            let tail = packetization_output(&mut a, 51, false);
            assert_eq!(
                tail.len() as u32 + if ipv4 { 20 } else { 40 },
                before.search_low
            );
            assert_eq!(a.path_mtu_info().unwrap(), before);
        }
    }
}

#[path = "connection_ipv6_packetization_tests.rs"]
mod conservative_ipv6;
