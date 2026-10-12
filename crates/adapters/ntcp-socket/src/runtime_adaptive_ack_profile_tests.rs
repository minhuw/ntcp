// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Included by runtime_memory_tests: configured production PacketIo and reservations.
fn adaptive_peer(a: &mut Owner, packet: &[u8], syn: bool, mss: u16, payload: &[u8]) {
    let incoming = ntcp_ip::parse(packet, false).unwrap().ip;
    let ip = ntcp::IpMetadata {
        source: incoming.destination,
        destination: incoming.source,
    };
    let sent = segment(packet);
    let [hi, lo] = mss.to_be_bytes();
    let options = [
        2, 4, hi, lo, 1, 1, 4, 2, 1, 3, 3, 6, 34, 6, 0xab, 0xcd, 0x12, 0x34, 1, 1,
    ];
    let mut tcp = [0; 1024];
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: sent.header.destination_port,
            destination_port: sent.header.source_port,
            sequence: if syn { 100 } else { 101 },
            acknowledgment: sent.header.sequence.wrapping_add(
                sent.payload.len() as u32 + u32::from(sent.header.flags & ntcp::wire::SYN != 0),
            ),
            flags: ntcp::wire::ACK
                | if syn {
                    ntcp::wire::SYN
                } else {
                    ntcp::wire::PSH
                },
            window: if syn { 5840 } else { 257 },
            urgent_pointer: 0,
        },
        if syn { &options } else { &[] },
        payload,
        &mut tcp,
    )
    .unwrap();
    let reply = a
        .frame(
            ntcp::Transmit {
                tx_timestamp: None,
                connection: None,
                ip,
                len: n,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..n],
        )
        .unwrap();
    tfo_deliver(a, reply);
}

#[test]
fn adaptive_ack_profile_syn_only_vs_fresh_data_fin_and_timer() {
    for (total, close) in [(1000, true), (1900, true), (1900, false)] {
        let mut a = owner(1, Profile::UpstreamFastOpenAdaptiveAck, 8);
        let warm = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
            EINPROGRESS
        );
        let request = tfo_capture(&mut a);
        a.test_now = Some(11_000);
        adaptive_peer(
            &mut a,
            &request,
            true,
            if total == 1000 { 1460 } else { 940 },
            &[],
        );
        assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
        // Keep warmup idle so no unrelated FIN timer can affect the trace.
        let client = new(&mut a, SOCK_NONBLOCK);
        a.test_now = Some(21_000);
        let data = vec![7; total];
        let syn_len = if total == 1000 { 1000 } else { 900 };
        assert_eq!(
            a.execute(client, tfo_send(&data, MSG_FASTOPEN))
                .unwrap()
                .value,
            syn_len as i32
        );
        let syn = tfo_capture(&mut a);
        assert_eq!(segment(&syn).payload, &data[..syn_len]);
        assert_eq!(segment(&syn).header.flags, ntcp::wire::SYN);
        assert_eq!(
            segment(&syn).options.fast_open.unwrap().as_bytes(),
            [0xab, 0xcd, 0x12, 0x34]
        );
        a.test_now = Some(41_000);
        adaptive_peer(
            &mut a,
            &syn,
            true,
            if total == 1000 { 940 } else { 1460 },
            &[],
        );
        if total == 1900 {
            // Complete the nonblocking short send through the real adapter, with Nagle unchanged.
            assert_eq!(
                a.execute(client, tfo_send(&data[syn_len..], MSG_FASTOPEN))
                    .unwrap()
                    .value,
                1000
            );
        }
        let sent = tfo_capture(&mut a);
        assert_eq!(segment(&sent).payload, &data[syn_len..]);
        assert_eq!(
            segment(&sent).header.sequence,
            segment(&syn)
                .header
                .sequence
                .wrapping_add(1 + syn_len as u32)
        );
        assert_eq!(segment(&sent).header.flags & ntcp::wire::SYN, 0);
        assert!(!a.endpoint.is_output_reserved(cid(&a, client)));
        tfo_no_output(&mut a);
        a.test_now = Some(61_000);
        adaptive_peer(&mut a, &sent, false, 0, &[9; 500]);
        if total == 1000 {
            let ack = tfo_capture(&mut a);
            assert_eq!(segment(&ack).header.flags, ntcp::wire::ACK);
            assert_eq!(segment(&ack).header.acknowledgment, 601);
            assert!(segment(&ack).payload.is_empty());
        }
        tfo_no_output(&mut a);
        assert_eq!(a.execute(client, Op::Read(4096)).unwrap().bytes, [9; 500]);
        tfo_no_output(&mut a);
        if close {
            a.test_now = Some(63_000);
            a.execute(client, Op::Close).unwrap();
            let fin = tfo_capture(&mut a);
            assert_eq!(
                segment(&fin).header.flags,
                ntcp::wire::FIN | ntcp::wire::ACK
            );
            assert_eq!(segment(&fin).header.acknowledgment, 601);
            assert!(segment(&fin).payload.is_empty());
        } else {
            let deadline = a.endpoint.next_deadline().unwrap();
            assert_eq!(deadline, 101_000); // Initial 40ms ATO, not the 200ms maximum.
            a.test_now = Some(deadline - 1);
            a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
            tfo_no_output(&mut a);
            a.test_now = Some(deadline);
            a.endpoint.on_timeout(a.now(), BUDGET).unwrap();
            let ack = tfo_capture(&mut a);
            assert_eq!(segment(&ack).header.flags, ntcp::wire::ACK);
            assert_eq!(segment(&ack).header.acknowledgment, 601);
            assert!(segment(&ack).payload.is_empty());
        }
        tfo_no_output(&mut a);
    }
}
