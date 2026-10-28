use super::*;
use crate::{EndpointConfig, PmtudConfig};

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
fn settings() -> ConnectionConfig {
    ConnectionConfig {
        nagle: false,
        timestamps: false,
        delayed_ack_us: 0,
        ..config(65_536, 1460)
    }
}

#[test]
fn receive_offer_cap_validation_and_existing_bounds() {
    assert_eq!(ConnectionConfig::default().advertised_mss, None);
    for ipv4 in [true, false] {
        let mut c = settings();
        c.advertised_mss = Some(0);
        assert_eq!(c.validate(ipv4), Err(Error::InvalidArgument));
        let endpoint = EndpointConfig {
            connection: c.clone(),
            ..Default::default()
        };
        assert!(endpoint.validate().is_err()); // Also fail before any connection exists.
        for cap in [1, 600, 1460, u16::MAX] {
            c.advertised_mss = Some(cap);
            assert!(c.validate(ipv4).is_ok());
            let a = Connection::active(address_pair(ipv4), c.clone(), 10, 0).unwrap();
            assert_eq!(a.transport_info().advertised_mss, u32::from(cap.min(1460)));
            assert_eq!(a.scratch.len(), 1460);
        }
        c.receive_ip_payload_limit = 620;
        c.advertised_mss = Some(700);
        let mut a = Connection::active(address_pair(ipv4), c, 10, 0).unwrap();
        assert_eq!(a.transport_info().advertised_mss, 600);
        a.set_user_mss(Some(500)).unwrap();
        assert_eq!(a.transport_info().advertised_mss, 500);
        a.set_user_mss(None).unwrap();
        assert_eq!(a.transport_info().advertised_mss, 600);
    }
}

#[test]
// Independent receive offers remain within the real IP receive capability.
//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1
//= type=test
//= reason=Explicit receive-only cap bounds SYN/SYNACK MSS by actual receive budget and user cap, preserves outbound peer-MSS packetization and full receiving capacity; IPv4/IPv6 active/passive roles exercised without a route-cache equivalence claim.
//# The MSS value to be sent in an MSS Option must be less than or equal to:
//# MMS_R - 20
fn receive_offer_does_not_cap_own_sends_or_actual_reassembly() {
    for ipv4 in [true, false] {
        for active_capped in [true, false] {
            let t = address_pair(ipv4);
            let mut c = settings();
            c.advertised_mss = active_capped.then_some(600);
            let mut a = Connection::active(t, c, 10, 0).unwrap();
            let syn = packet(&mut a, 0);
            let mut c = settings();
            c.advertised_mss = (!active_capped).then_some(600);
            let mut b =
                Connection::passive(reverse(t), c, 900, 10, &wire::parse(ip(t), &syn).unwrap())
                    .unwrap();
            assert_eq!(
                wire::parse(ip(t), &syn).unwrap().options.mss,
                Some(if active_capped { 600 } else { 1460 })
            );
            let synack = deliver(&mut b, &mut a, 20);
            assert_eq!(
                wire::parse(ip(reverse(t)), &synack).unwrap().options.mss,
                Some(if active_capped { 1460 } else { 600 })
            );
            deliver(&mut a, &mut b, 30);
            let (capped, peer) = if active_capped {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            assert_eq!(capped.transport_info().advertised_mss, 600);
            let send_mss = if ipv4 { 1460 } else { 1220 };
            assert_eq!(capped.mss, send_mss);
            assert_eq!(peer.mss, 600); // Only the peer's sender sees the smaller offer.
            assert_eq!(capped.config.receive_capacity, 65_536);
            assert_eq!(
                capped.config.receive_ip_payload_limit,
                if ipv4 { 65515 } else { 65535 }
            );
            capped.write(&[7; 1460]).unwrap();
            let output = packet(capped, 40);
            assert_eq!(
                wire::parse(ip(capped.tuple()), &output)
                    .unwrap()
                    .payload
                    .len(),
                send_mss
            );
            // A receive offer cap is not a new raw-input rejection boundary.
            let incoming = Segment {
                header: Header {
                    source_port: capped.tuple.remote.port(),
                    destination_port: capped.tuple.local.port(),
                    sequence: capped.receive.next().0,
                    acknowledgment: capped.snd_una.0,
                    flags: ACK,
                    window: 65535,
                    urgent_pointer: 0,
                },
                options: wire::Options::default(),
                raw_options: &[],
                payload: &[9; 1000],
            };
            capped.input(50, &incoming).unwrap();
            let mut read = [0; 1000];
            assert_eq!(capped.read(&mut read).unwrap(), 1000);
            assert_eq!(read, [9; 1000]);
        }
    }
}

#[test]
fn receive_offer_survives_user_mss_changes_failed_encode_and_syn_retry() {
    for ipv4 in [true, false] {
        let mut c = settings();
        c.advertised_mss = Some(600);
        let t = address_pair(ipv4);
        let mut a = Connection::active(t, c, u32::MAX - 5, 0).unwrap();
        a.set_user_mss(Some(500)).unwrap();
        assert_eq!(a.transmit(0, &mut [0; 19]), Err(Error::OutputTooSmall));
        a.set_user_mss(None).unwrap();
        let syn = packet(&mut a, 0);
        assert_eq!(wire::parse(ip(t), &syn).unwrap().options.mss, Some(600));
        a.set_user_mss(Some(400)).unwrap();
        assert_eq!(a.transport_info().advertised_mss, 600);
        assert_eq!(a.mss, 400);
        a.set_user_mss(None).unwrap();
        let deadline = a.rto_deadline.unwrap();
        a.timeout(deadline).unwrap();
        let retry = packet(&mut a, deadline);
        assert_eq!(wire::parse(ip(t), &retry).unwrap().options.mss, Some(600));
    }
}

#[test]
fn receive_offer_cap_preserves_real_ack_confirmed_upward_probe() {
    for ipv4 in [true, false] {
        let t = address_pair(ipv4);
        let mut c = settings();
        c.advertised_mss = Some(600);
        c.initial_window = InitialWindow::Iw10;
        let mut p = PmtudConfig::new(1500);
        p.initial_mtu = Some(if ipv4 { 640 } else { 1280 });
        p.initial_search_low = Some(if ipv4 { 552 } else { 1280 });
        c.pmtud = Some(p);
        let mut a = Connection::active(t, c, 10, 0).unwrap();
        let syn = packet(&mut a, 0);
        assert_eq!(wire::parse(ip(t), &syn).unwrap().options.mss, Some(600));
        let mut b = Connection::passive(
            reverse(t),
            settings(),
            900,
            10,
            &wire::parse(ip(t), &syn).unwrap(),
        )
        .unwrap();
        deliver(&mut b, &mut a, 20);
        deliver(&mut a, &mut b, 30);
        let old = a.path_mtu_info().unwrap();
        a.write(&[7; 20_000]).unwrap();
        let bytes = packet(&mut a, 40);
        let probe = wire::parse(ip(t), &bytes).unwrap();
        let payload = if ipv4 { 986 } else { 1330 };
        assert_eq!(probe.payload.len(), payload);
        assert!(probe.payload.len() > 600);
        assert_eq!(a.path_mtu_info().unwrap(), old); // A send is not path proof.
        b.input(41, &probe).unwrap();
        deliver(&mut b, &mut a, 42);
        let new_mtu = if ipv4 { 1026 } else { 1390 };
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, new_mtu);
        assert_eq!(a.mss, payload);
        assert_eq!(a.transport_info().advertised_mss, 600);
        assert_eq!(
            a.config.receive_ip_payload_limit,
            if ipv4 { 65515 } else { 65535 }
        );
        assert_eq!(a.scratch.len(), 1460);
    }
}

#[test]
fn receive_offer_cap_does_not_truncate_fast_open_request_payload() {
    for ipv4 in [true, false] {
        let t = address_pair(ipv4);
        let mut c = settings();
        c.advertised_mss = Some(600);
        let mut cache = crate::fast_open::FastOpen::new().unwrap();
        cache.learn(
            0,
            t.local.ip(),
            t.remote.ip(),
            wire::FastOpenCookie::new(&[7; 8]).unwrap(),
            1460,
        );
        let cached = cache.get(0, 100, t.local.ip(), t.remote.ip());
        let mut a = Connection::active(t, c, 10, 0).unwrap();
        assert_eq!(a.prepare_fast_open(cached, &[9; 1000]).unwrap(), 1000);
        let syn = packet(&mut a, 0);
        let syn = wire::parse(ip(t), &syn).unwrap();
        assert_eq!(syn.options.mss, Some(600));
        assert_eq!(syn.payload, &[9; 1000]);
        assert_eq!(syn.options.fast_open.unwrap().as_bytes(), [7; 8]);
    }
}
