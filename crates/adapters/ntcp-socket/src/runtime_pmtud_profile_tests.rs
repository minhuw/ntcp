// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Fast Open path MTU discovery under the PMTUD packet profile, over the actual
// profile, IP admission and production egress.
use super::fast_open_tests::{tfo_capture, tfo_deliver, tfo_no_output, tfo_send};
use super::memory::tests::{cid, owner, path_mtu, ptb_checksums, ptb_frame, segment};
use super::tests::{ip_packet, new};
use super::*;

fn pmtud_peer_reply(a: &mut Owner, packet: &[u8], syn: bool) {
    let incoming = ntcp_ip::parse(packet, false).unwrap().ip;
    let ip = ntcp::IpMetadata {
        source: incoming.destination,
        destination: incoming.source,
    };
    let sent = segment(packet);
    let mut tcp = [0; 128];
    let n = ntcp::wire::encode(
        ip,
        ntcp::wire::Header {
            source_port: sent.header.destination_port,
            destination_port: sent.header.source_port,
            sequence: if syn { 100 } else { 101 },
            acknowledgment: sent.header.sequence.wrapping_add(
                sent.payload.len() as u32
                    + u32::from(sent.header.flags & ntcp::wire::SYN != 0)
                    + u32::from(sent.header.flags & ntcp::wire::FIN != 0),
            ),
            flags: ntcp::wire::ACK | if syn { ntcp::wire::SYN } else { 0 },
            window: 5840,
            urgent_pointer: 0,
        },
        // Peer MSS1040 must not override the smaller validated outbound PMTU.
        if syn && sent.options.fast_open.is_some() {
            &[
                2, 4, 4, 16, 1, 1, 4, 2, 1, 3, 3, 6, 34, 6, 0xab, 0xcd, 0x12, 0x34, 1, 1,
            ]
        } else if syn {
            &[2, 4, 4, 16, 1, 1, 4, 2, 1, 3, 3, 6]
        } else {
            &[]
        },
        &[],
        &mut tcp,
    )
    .unwrap();
    let reply = ip_packet(
        a,
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
    );
    tfo_deliver(a, reply);
}

fn pmtud_metric_probe(a: &mut Owner, client: u64, stage: &str, delivered: u64) {
    let info = a.endpoint.transport_info(cid(a, client)).unwrap();
    let prefix = a.execute(client, Op::TransportPrefix(1, 192)).unwrap();
    assert!(info.ledger_valid);
    assert!(info.delivered_segments_valid);
    assert_eq!(info.delivered_segments, delivered);
    assert!(!info.syn_data_acked);
    assert_eq!(prefix.bytes.len(), 192);
    assert_eq!(prefix.bytes[5] & 32, 0);
    let full = a.execute(client, Op::Transport(1)).unwrap();
    assert_eq!(full.bytes.len(), 280);
    assert_eq!(full.bytes[..192], prefix.bytes);
    eprintln!(
        "PMTU_METRIC stage={stage} mss={} delivered_valid={} delivered={} unacked={} retransmitted={} returned_len={} syn_data={}",
        info.mss,
        info.delivered_segments_valid,
        info.delivered_segments,
        info.unacked,
        info.retransmitted,
        full.bytes.len(),
        prefix.bytes[5] & 32
    );
}

#[test]
fn fast_open_pmtud_profile_exact_quote_fallback_and_bounded_retry() {
    for mtu in [800u16, 840] {
        for profile in [
            upstream_runtime_pmtud_profile_tests("no-timestamps,budget224m,prealloc3"),
            upstream_runtime_pmtud_profile_tests("no-timestamps,budget224m,prealloc3,pmtud1500"),
        ] {
            let mut a = owner(1, profile, 8);
            let warm = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(
                a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
                EINPROGRESS
            );
            let request = tfo_capture(&mut a);
            pmtud_peer_reply(&mut a, &request, true);
            assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
            // Keep the warmed connection idle: no close timer can affect this trace.
            let client = new(&mut a, SOCK_NONBLOCK);
            let data: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                a.execute(client, tfo_send(&data, MSG_FASTOPEN))
                    .unwrap()
                    .value,
                1000
            );
            let syn = tfo_capture(&mut a);
            assert_eq!(syn.len(), 1060);
            assert_eq!(segment(&syn).payload, data);
            assert_eq!(
                segment(&syn).options.fast_open.unwrap().as_bytes(),
                [0xab, 0xcd, 0x12, 0x34]
            );
            let mut feedback = ptb_frame(&syn);
            feedback[26..28].copy_from_slice(&mtu.to_be_bytes());
            ptb_checksums(&mut feedback);
            let id = cid(&a, client);
            if profile == upstream_runtime_pmtud_profile_tests("no-timestamps,budget224m,prealloc3")
            {
                tfo_deliver(&mut a, feedback);
                assert!(a.endpoint.path_mtu_info(id).unwrap().is_none());
                assert_eq!(a.endpoint.transport_info(id).unwrap().send_used, 1000);
                tfo_no_output(&mut a);
                continue;
            }
            let mut bad_checksum = feedback.clone();
            bad_checksum[38] ^= 1;
            ptb_checksums(&mut bad_checksum); // Only the quoted IPv4 checksum stays invalid.
            assert_eq!(a.execute(0, Op::Inject(bad_checksum)).unwrap_err(), EINVAL);
            assert_eq!(path_mtu(&a, client), 1500);
            tfo_no_output(&mut a);
            // Valid checksums alone are insufficient: require the tuple, a
            // sequence in the sent window (RFC 5927 section 4.1, as Linux),
            // and a candidate MTU below the quoted length and decreasing.
            for (offset, replacement) in [
                (30, 40u16),
                (50, 8081),
                (52, 0),
                (26, 1500),
                (26, 1600),
                (26, 1060),
            ] {
                let mut invalid = feedback.clone();
                if offset == 52 {
                    invalid[52] ^= 0x80; // Half the sequence space away.
                } else {
                    invalid[offset..offset + 2].copy_from_slice(&replacement.to_be_bytes());
                }
                invalid[38..40].fill(0);
                let checksum = ntcp_ip::checksum(&invalid[28..48]);
                invalid[38..40].copy_from_slice(&checksum.to_be_bytes());
                ptb_checksums(&mut invalid);
                tfo_deliver(&mut a, invalid);
                assert_eq!(path_mtu(&a, client), 1500, "offset {offset}");
                tfo_no_output(&mut a);
            }
            let now = a.now();
            tfo_deliver(&mut a, feedback.clone());
            assert_eq!(path_mtu(&a, client), u32::from(mtu));
            assert_eq!(path_mtu(&a, warm), 1080); // Peer MSS1040 + headers.
            let retry = tfo_capture(&mut a);
            assert_eq!(a.now(), now); // Immediate, without advancing to any timer.
            let bare = segment(&retry);
            assert_eq!(bare.header.sequence, segment(&syn).header.sequence);
            assert_eq!(bare.header.flags, ntcp::wire::SYN);
            assert!(bare.payload.is_empty());
            assert!(bare.options.fast_open.is_none());
            // RFC1191 section6.4: receive MSS is independent of outbound PMTU.
            assert_eq!(bare.options.mss, Some(1460));
            assert_eq!(a.endpoint.transport_info(id).unwrap().send_used, 1000);
            tfo_deliver(&mut a, feedback);
            assert_eq!(path_mtu(&a, client), u32::from(mtu));
            tfo_no_output(&mut a); // Repeated feedback cannot schedule another retry.

            pmtud_peer_reply(&mut a, &retry, true); // ACK only the SYN, not its data.
            assert!(!a.endpoint.transport_info(id).unwrap().syn_data_acked);
            assert_eq!(
                a.execute(client, Op::Transport(1)).unwrap().bytes[5] & 32,
                0
            );
            pmtud_metric_probe(&mut a, client, "synack-before-repair", 1);
            let first = tfo_capture(&mut a);
            pmtud_metric_probe(&mut a, client, "first-repair-captured", 1);
            let first_len = usize::from(mtu - 40);
            let mut next = bare.header.sequence.wrapping_add(1);
            assert_eq!(segment(&first).header.sequence, next);
            assert_eq!(segment(&first).payload, &data[..first_len]);
            assert_eq!(first.len(), usize::from(mtu));
            assert_eq!(segment(&first).header.flags & ntcp::wire::SYN, 0);
            assert_eq!(a.endpoint.transport_info(id).unwrap().send_used, 1000);
            // These are retries of already-sent SYN data, not new writes:
            // fast_open_retry bypasses ordinary new-data Nagle coalescing.
            // Keep default Nagle enabled; verify its new-data rule below.
            let tail = tfo_capture(&mut a);
            pmtud_metric_probe(&mut a, client, "both-repairs-captured", 1);
            next = next.wrapping_add(first_len as u32);
            assert_eq!(segment(&tail).header.sequence, next);
            assert_eq!(segment(&tail).payload, &data[first_len..]);
            assert_eq!(segment(&tail).payload.len(), usize::from(1040 - mtu));
            assert!(tail.len() <= usize::from(mtu));
            assert_eq!(segment(&tail).header.flags & ntcp::wire::SYN, 0);
            assert_eq!(
                a.execute(client, Op::Write(b"new".to_vec())).unwrap().value,
                3
            );
            tfo_no_output(&mut a); // Ordinary short new write waits for the flight ACK.
            pmtud_peer_reply(&mut a, &tail, false); // Cumulative ACK covers all 1000 bytes.
            pmtud_metric_probe(&mut a, client, "repair-acknowledged", 3);
            let new_data = tfo_capture(&mut a);
            assert_eq!(
                segment(&new_data).header.sequence,
                bare.header.sequence.wrapping_add(1001)
            );
            assert_eq!(segment(&new_data).payload, b"new");
            assert_eq!(a.endpoint.transport_info(id).unwrap().send_used, 3);
            pmtud_peer_reply(&mut a, &new_data, false);
            pmtud_metric_probe(&mut a, client, "new-data-acknowledged", 4);
            assert_eq!(a.endpoint.transport_info(id).unwrap().send_used, 0);
            assert!(!a.endpoint.transport_info(id).unwrap().syn_data_acked);
            tfo_no_output(&mut a);
        }
    }
}

pub(super) fn upstream_runtime_pmtud_profile_tests(
    options: &str,
) -> crate::packet_profile::Profile {
    crate::packet_profile::profile(&format!(
        "upstream,local=192.0.2.1{}{}",
        if options.is_empty() { "" } else { "," },
        options
    ))
    .unwrap()
    .1
}

#[test]
fn fast_open_pmtud_delivery_counts_syn_repair_and_fin_once() {
    for mtu in [800u16, 840] {
        let mut a = owner(
            1,
            upstream_runtime_pmtud_profile_tests("no-timestamps,budget224m,prealloc3,pmtud1500"),
            8,
        );
        let warm = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(warm, tfo_send(&[], MSG_FASTOPEN)).unwrap_err(),
            EINPROGRESS
        );
        let request = tfo_capture(&mut a);
        pmtud_peer_reply(&mut a, &request, true);
        assert!(segment(&tfo_capture(&mut a)).payload.is_empty());
        let client = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(client, tfo_send(&[0x42; 1000], MSG_FASTOPEN))
                .unwrap()
                .value,
            1000
        );
        let syn = tfo_capture(&mut a);
        let mut feedback = ptb_frame(&syn);
        feedback[26..28].copy_from_slice(&mtu.to_be_bytes());
        ptb_checksums(&mut feedback);
        tfo_deliver(&mut a, feedback);
        let bare = tfo_capture(&mut a);
        assert!(segment(&bare).payload.is_empty());
        pmtud_peer_reply(&mut a, &bare, true);
        pmtud_metric_probe(&mut a, client, "native-control-syn-acked", 1);
        let first = tfo_capture(&mut a);
        let tail = tfo_capture(&mut a);
        assert_eq!(segment(&first).payload.len(), usize::from(mtu - 40));
        assert_eq!(segment(&tail).payload.len(), usize::from(1040 - mtu));
        pmtud_peer_reply(&mut a, &tail, false);
        pmtud_metric_probe(&mut a, client, "native-control-data-acked", 3);
        a.execute(client, Op::Shutdown(SHUT_WR)).unwrap();
        let fin = tfo_capture(&mut a);
        assert!(segment(&fin).payload.is_empty());
        assert_ne!(segment(&fin).header.flags & ntcp::wire::FIN, 0);
        pmtud_peer_reply(&mut a, &fin, false);
        pmtud_metric_probe(&mut a, client, "native-control-fin-acked", 4);
        assert_eq!(
            a.endpoint.transport_info(cid(&a, client)).unwrap().state,
            State::FinWait2
        );
        pmtud_peer_reply(&mut a, &fin, false);
        pmtud_metric_probe(&mut a, client, "native-control-duplicate-fin-ack", 4);
    }
}
