// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn fast_open_socket_mss_limits_initial_copy_in_explicit_and_deferred_opens() {
    for deferred in [false, true] {
        for (cached_mss, cap, expected) in [(940, None, 900), (1460, Some(1040), 1000), (1340, None, 1300), (10000, None, 1420)] {
            let profile = Profile::Upstream(crate::packet_profile::UpstreamOptions {
                no_timestamps: true,
                budget128m: true,
                ..Default::default()
            });
            let mut a = owner(1, profile, 16);
            let warm = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(), EINPROGRESS);
            let syn = tfo_capture(&mut a);
            tfo_client_synack(&mut a, &syn, cached_mss);
            a.execute(warm, Op::Close).unwrap();
            let _fin = tfo_capture(&mut a);

            let client = new(&mut a, SOCK_NONBLOCK);
            if let Some(cap) = cap {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_MAXSEG, cap)).unwrap();
            }
            if deferred {
                a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)).unwrap();
                assert_eq!(a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap())).unwrap().value, 0);
                tfo_no_output(&mut a);
            }
            let data: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
            let flags = MSG_DONTWAIT | if deferred { 0 } else { MSG_FASTOPEN };
            assert_eq!(a.execute(client, tfo_send(&data, flags)).unwrap().value, expected);
            let syn = tfo_capture(&mut a);
            let segment = segment(&syn);
            assert_eq!(segment.options.mss, Some(cap.map_or(1460, |n| n as u16)));
            assert_eq!(segment.payload, &data[..expected as usize]);
            let connection = cid(&a, client);
            let info = a.endpoint.transport_info(connection).unwrap();
            assert_eq!((info.send_used, info.notsent_bytes), (expected as usize, 0));
            tfo_client_synack(&mut a, &syn, 1460);
            let info = a.endpoint.transport_info(connection).unwrap();
            assert_eq!((info.send_used, info.notsent_bytes), (0, 0));
            tfo_no_output(&mut a);
        }
    }
}

#[test]
fn fast_open_blocking_mss_limit_keeps_remainder_in_the_waiting_writer() {
    for deferred in [false, true] {
        let (mut a, mut b, listener) = tfo_setup(true);
        let client = new(&mut a, 0);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_MAXSEG, 1040)).unwrap();
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)).unwrap();
        if deferred {
            a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)).unwrap();
            a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap())).unwrap();
        }
        let data: Vec<u8> = (0..2000).map(|n| (n % 251) as u8).collect();
        let (reply, rx) = mpsc::sync_channel(1);
        let mut request = Request {
            id: client,
            op: Op::Wait(Box::new(tfo_send(&data, if deferred { 0 } else { MSG_FASTOPEN })), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        };
        assert!(!a.service(&mut request));
        assert_eq!(request.send.as_ref().unwrap().accepted, 1000);
        assert!(rx.try_recv().is_err());
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).options.mss, Some(1040));
        assert_eq!(segment(&syn).payload, &data[..1000]);
        tfo_deliver(&mut b, syn);
        exchange(&mut a, &mut b);
        assert!(a.service(&mut request));
        assert_eq!(rx.recv().unwrap().unwrap().value, 2000);
        exchange(&mut a, &mut b);
        let server = b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap().value as u64;
        assert_eq!(b.execute(server, Op::Read(BYTES)).unwrap().bytes, data);
    }
}
