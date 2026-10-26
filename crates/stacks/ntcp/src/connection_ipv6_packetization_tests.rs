use super::*;

fn small_pair(timestamps: bool, iss: u32) -> (Connection, Connection) {
    let mut c = settings(false, Some(660));
    c.pmtud.as_mut().unwrap().first_hop_mtu = 1520;
    c.pmtud.as_mut().unwrap().initial_search_low = Some(572);
    c.send_ip_payload_limit = 1480;
    c.timestamps = timestamps;
    c.sack = false;
    c.recovery_algorithm = RecoveryAlgorithm::Reno;
    let t = address_pair(false);
    let mut a = Connection::active(t, c.clone(), iss, 0).unwrap();
    let syn = packet(&mut a, 0);
    assert_eq!(wire::parse(ip(t), &syn).unwrap().options.mss, Some(600));
    c.pmtud = None;
    c.advertised_mss = None;
    let mut b = Connection::passive(reverse(t), c, 900, 10, &wire::parse(ip(t), &syn).unwrap()).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    (a, b)
}

#[test]
fn explicit_ipv6_packet_bounds_reserve_options_but_preserve_link_minimum() {
    for timestamps in [false, true] {
        for sack in [false, true] {
            let mut c = settings(false, None);
            c.timestamps = timestamps;
            c.sack = sack;
            let floor = c.packetization_mtu_floor(false);
            for field in 0..4 {
                for value in [0, floor - 1] {
                    let mut bad = c.clone();
                    let p = bad.pmtud.as_mut().unwrap();
                    match field {
                        0 => p.route_mtu = Some(value),
                        1 => p.initial_mtu = Some(value),
                        2 => p.initial_search_low = Some(value),
                        _ => p.initial_search_high = Some(value),
                    }
                    assert_eq!(bad.validate(false), Err(Error::InvalidArgument));
                }
            }
            let p = c.pmtud.as_mut().unwrap();
            p.route_mtu = Some(floor);
            p.initial_mtu = Some(floor);
            p.initial_search_low = Some(floor);
            p.initial_search_high = Some(floor);
            assert_eq!(c.validate(false), Ok(()));
            c.pmtud.as_mut().unwrap().first_hop_mtu = 1279;
            assert_eq!(c.validate(false), Err(Error::InvalidArgument));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
//= type=test
//# There SHOULD be per-protocol and per-route configuration options to override initial values for eff_pmtu and other PLPMTUD state variables.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
//= type=test
//# If the probe size is larger than the eff_pmtu, raise eff_pmtu to the probe size.
fn ipv6_small_packetization_promotes_only_on_real_probe_ack() {
    for timestamps in [false, true] {
        for reserved in [false, true] {
            for iss in [10, u32::MAX - 500] {
                let (mut a, mut b) = small_pair(timestamps, iss);
                let before = (a.mss, a.congestion.cwnd(), a.receive_mss(), a.snd_una, a.snd_nxt);
                a.set_route_mtu(40, Some(1520)).unwrap();
                assert_eq!((a.mss, a.congestion.cwnd(), a.receive_mss(), a.snd_una, a.snd_nxt), before);
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 660);
                a.write(&[7; 20_000]).unwrap();
                let bytes = packetization_output(&mut a, 50, reserved);
                let segment = wire::parse(ip(a.tuple), &bytes).unwrap();
                assert_eq!(bytes.len() + 40, 1046);
                assert_eq!(segment.payload.len(), if timestamps { 974 } else { 986 });
                let snapshot = a.path_mtu_info();
                for invalid in [660, 1045, 1279] {
                    assert!(!a.pmtu_feedback(51, segment.header.sequence, 1046, 40, invalid).unwrap());
                    assert_eq!(a.path_mtu_info(), snapshot);
                }
                b.input(52, &segment).unwrap();
                deliver(&mut b, &mut a, 53);
                assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1046);
                assert_eq!(a.path_mtu_info().unwrap().search_low, 1046);
                assert_eq!(a.receive_mss(), 600);
                assert!(a.mss > before.0);
            }
        }
    }
}

#[test]
fn ipv6_small_probe_loss_repairs_within_safe_bound_and_reaches_receiver() {
    for timestamps in [false, true] {
        for reserved in [false, true] {
            let (mut a, mut b) = small_pair(timestamps, u32::MAX - 500);
            a.set_route_mtu(40, Some(1520)).unwrap();
            a.write(&[7; 20_000]).unwrap();
            packetization_output(&mut a, 50, reserved); // Lose the larger probe.
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            let low = a.path_mtu_info().unwrap().search_low;
            let next = a.snd_nxt;
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let repair = packetization_output(&mut a, deadline, reserved);
            let segment = wire::parse(ip(a.tuple), &repair).unwrap();
            assert_eq!(segment.header.sequence, probe.start.0);
            assert!(repair.len() as u32 + 40 <= low);
            assert_eq!(a.snd_nxt, next);
            b.input(deadline + 1, &segment).unwrap();
            deliver(&mut b, &mut a, deadline + 2);
            let mut out = [0; 2048];
            assert_eq!(b.read(&mut out).unwrap(), segment.payload.len());
            assert!(out[..segment.payload.len()].iter().all(|v| *v == 7));
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//# Even lower lower bounds MAY be permitted to support limited operation over links with MTUs that are smaller than permitted by the IP specifications.
fn ipv6_consecutive_timeouts_never_increase_small_packets_or_exceed_route() {
    for expand_route in [false, true] {
        let (mut a, _) = small_pair(false, 10);
        if expand_route {
            a.set_route_mtu(40, Some(1520)).unwrap();
        }
        a.write(&[7; 1000]).unwrap(); // Too little queued data for a larger probe.
        packet(&mut a, 50);
        let mut previous = 660;
        for _ in 0..6 {
            let deadline = a.rto_deadline.unwrap();
            a.timeout(deadline).unwrap();
            let repair = packet(&mut a, deadline);
            let current = a.path_mtu_info().unwrap().current_mtu;
            assert!(current <= previous);
            assert!(current <= a.path_mtu_info().unwrap().route_mtu.unwrap());
            assert!(repair.len() as u32 + 40 <= current);
            previous = current;
        }
        assert_eq!(previous, 572);
        assert_eq!(a.set_first_hop_mtu(a.now + 1, 1279), Err(Error::InvalidArgument));
    }
}
