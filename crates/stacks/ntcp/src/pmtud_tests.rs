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
            let checksum = ntcp_ip_common::checksum(&out[..header]);
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
    let parsed = parse_ip_test(&out, true).unwrap();
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
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Dynamic send path MSS never mutates config.mss receive offer; family-floor wire test asserts unchanged receive capability.
//# PMTU Discovery does not affect the value sent in the TCP MSS option, because that value
//# is used by the other end of the connection, which may be using an unrelated PMTU value.

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=IPv6 core rejects1279 without changing1500 estimate and accepts1280; native IPv6 socket transport is not claimed.
//# If a node receives a Packet Too Big message reporting a next-hop MTU that is less than
//# the IPv6 minimum link MTU, it must discard it. A node must not reduce its estimate of
//# the Path MTU below the IPv6 minimum link MTU on receipt of a Packet Too Big message.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Connection caches PMTU-derived MSS and bounds packetization by it; family-floor wire tests assert repaired packets within the updated PMTU. GET_MAXSIZES polling is an example, not a required API. Probe behavior is the selected RFC4821 extension.
//# The TCP layer must track the PMTU for the destination of a connection; it should not
//# send datagrams that would be larger than this. A simple implementation could ask the
//# IP layer for this value (using the GET_MAXSIZES interface described in [1]) each
//# time it created a new segment, but this could be inefficient. Moreover, TCP
//# implementations that follow the "slow-start" congestion-avoidance algorithm [4]
//# typically calculate and cache several other values derived from the PMTU. It may be
//# simpler to receive asynchronous notification when the PMTU changes, so that these
//# variables may be updated.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Accepted feedback refreshes only the matched Connection; the family-floor test verifies retry sequence/payload and complete packet size within the new PMTU. Cross-connection dispatch is additionally exercised by native tuple validation; this does not close exact dropped-range notification or burst deduplication.
//# Alternatively, the retransmission could be done in immediate response to a
//# notification that the Path MTU has changed, but only for the specific connection
//# specified by the Datagram Too Big message. The datagram size used in the
//# retransmission should, of course, be no larger than the new PMTU.

//= https://www.rfc-editor.org/rfc/rfc1191#section-8
//= type=test
//= reason=The IPv4 estimate retains the legal 68-byte floor; the core wire test demonstrates bounded payload repair at that floor. This repeats the floor invariant, not a guarantee against an on-path ICMP blocker.
//# In the first attack, the false message indicates a PMTU much smaller than reality.
//# This should not entirely stop data flow, since the victim host should never set its
//# PMTU estimate below the absolute minimum, but at 8 octets of IP data per datagram,
//# progress could be slow.

//= https://www.rfc-editor.org/rfc/rfc8201#section-3
//= type=test
//= reason=Enabled IPv6 state starts at the caller first-hop bound (subject to peer/allocation caps); family-floor test asserts the initial 1500-byte estimate before rejecting subminimum feedback.
//# The basic idea is that a source node initially assumes that the PMTU of a path is
//# the (known) MTU of the first hop in the path.

//= https://www.rfc-editor.org/rfc/rfc8201#section-3
//= type=test
//= reason=Enabled IPv6 core consumes validated PTB, reduces the estimate and emits a smaller unfragmented retry. The dual-family floor test checks complete packet length and retry payload; no native IPv6 socket claim.
//# Upon receipt of such a message, the source node reduces its assumed PMTU for the
//# path based on the MTU of the constricting hop as reported in the Packet Too Big
//# message. The decreased PMTU causes the source to send smaller packets or change
//# EMTU_S to cause the upper layer to reduce the size of IP packets it sends.

//= https://www.rfc-editor.org/rfc/rfc8201#section-3
//= type=test
//= reason=Enabled IPv6 core reduces its estimate from validated PTB; the dual-family floor test checks the new estimate and bounded retry.
//# Reductions of the PMTU are detected by Packet Too Big messages.

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=Enabled IPv6 core applies a validated initial PTB decrease; the floor test checks 1500 to 1280 and repacketized retry. Later reports below proven delivery follow the selected deferred security policy, not unconditional trust of every ICMP packet.
//# When a node receives a Packet Too Big message, it must reduce its estimate of the
//# PMTU for the relevant path, based on the value of the MTU field in the message. The
//# precise behavior of a node in this circumstance is not specified, since different
//# applications may have different requirements, and since different implementation
//# architectures may favor different strategies.

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=Validated initial IPv6 PTB reduces packet size; the dual-family floor test asserts a complete retry no larger than 1280. Smaller successive legal reports pass the same strictly decreasing path; no source fragmentation is used.
//# After receiving a Packet Too Big message, a node must attempt to avoid eliciting
//# more such messages in the near future. The node must reduce the size of the packets
//# it is sending along the path. Using a PMTU estimate larger than the IPv6 minimum
//# link MTU may continue to elicit Packet Too Big messages. Because each of these
//# messages (and

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.1
//= type=test
//= reason=Enabled TCP limits complete IPv6 packets to the path budget rather than invoking source fragmentation; the family-floor test parses base-header packets and checks resized retry length with timestamp options. Extension headers and shared caches are not prerequisites of this avoidance recommendation.
//# However, packetization layers are encouraged to avoid sending messages that will
//# require source fragmentation (for the case against fragmentation, see [FRAG]).

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Enabled IPv6 PMTU starts at the supplied first-hop bound, with separate allocation/peer ceilings. The dual-family floor test asserts 1500 initially; the small-allocation test covers independent limiting.
//# Initially, the PMTU value for a path is assumed to be the (known) MTU of the
//# first-hop link.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
//= type=test
//= reason=Validated feedback updates the matched Connection and emits a retry no larger than the new IPv6 PMTU; the dual-family floor test checks sequence, payload and full packet length. Exact dropped-range notification is distinct and remains open in 8201-064/066.
//# Alternatively, the retransmission could be done in immediate response to a
//# notification that the Path MTU was decreased, but only for the specific connection
//# specified by the Packet Too Big message. The packet size used in the retransmission
//# should be no larger than the new PMTU.

//= https://www.rfc-editor.org/rfc/rfc8201#section-6
//= type=test
//= reason=Same enabled-core floor invariant as 8201-034: sub1280 feedback is discarded and a legal 1280 report is accepted. The dual-family wire test asserts both outcomes; no native IPv6 socket or complete threat-model claim.
//# In the first attack, the false message indicates a PMTU much smaller than reality.
//# In response, the victim node should never set its PMTU estimate below the IPv6
//# minimum link MTU. A sender that falsely reduces to this MTU would observe suboptimal
//# performance.

fn pmtud_wire_family_floors_options_wrap_and_receive_offer() {
    for ipv4 in [true, false] {
        for iss in [0, u32::MAX - 100] {
            let (mut a, _) = family_pair(cfg(1500), ipv4, iss);
            let advertised = a.config.mss;
            let original_cwnd = a.congestion.cwnd();
            let original_mss = a.mss;
            a.write(&[7; 1460]).unwrap(); // insufficient trailing data: not a probe
            let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
            let ip = parse_ip_test(&frame, false).unwrap();
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
            let ip = parse_ip_test(&retry, false).unwrap();
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
    let parsed = parse_ip_test(&syn, false).unwrap();
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
//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
//# When a host receives a Datagram Too Big message, it MUST reduce its estimate of the PMTU
//# for the relevant path, based on the value of the Next-Hop MTU field in the message (see
//# section 4). We do not specify the precise behavior of a host in this circumstance, since
//# different applications may have different requirements, and since different
//# implementation architectures may favor different strategies.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
//# We do require that after receiving a Datagram Too Big message, a host MUST attempt to
//# avoid eliciting more such messages in the near future. The host may either reduce the
//# size of the datagrams it is sending along the path, or cease setting the Don't Fragment
//# bit in the headers of those datagrams. Clearly, the former strategy may continue to
//# elicit Datagram Too Big messages for a while, but since each of these messages (and the
//# dropped datagrams they respond to) consume Internet resources, the host MUST force the
//# PMTU Discovery process to converge.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
//# A host MUST never reduce its estimate of the Path MTU below 68 octets.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Enabled IPv4 PMTUD: exact sent evidence, legal floor and strictly decreasing candidates; repeated/nondecreasing reports do not rearm. Security-selected deferred updates are tested separately from immediate initial discovery.
//# A host MUST not increase its estimate of the Path MTU in response to the contents of a
//# Datagram Too Big message. A message purporting to announce an increase in the Path MTU
//# might be a stale datagram that has been floating around in the Internet, a false packet
//# injected as part of a denial-of-service attack, or the result of having multiple paths
//# to the destination.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Nondecreasing, stale and impossible exact-size quotes are rejected; decreasing accepted feedback alone reaches packetization refresh.
//# This means that the TCP layer must be able to recognize when a Datagram Too Big
//# notification actually decreases the PMTU that it has already used to send a datagram on
//# the given connection, and should ignore any other notifications.

//= https://www.rfc-editor.org/rfc/rfc5927#section-4.1
//= type=test
//= reason=Informational mitigation selected as policy: live serial send-window validation plus stronger exact recent packet gate; stale/idle and wrapped-sequence quotes tested, not authentication.
//# Many TCP implementations have incorporated a validation check such that they react only
//# to those ICMP error messages that appear to relate to segments currently "in flight" to
//# the destination system. These implementations check that the TCP sequence number
//# contained in the payload of the ICMP error message is within the range SND.UNA =<
//# SEG.SEQ < SND.NXT. This means that they require that the sequence number be within the
//# range of the data already sent but not yet acknowledged. If an ICMP error message does
//# not pass this check, it is discarded.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
//= type=test
//= reason=Selected plausibility gate rejects a candidate larger than max_sent and also requires it to be smaller than the exact recently sent packet. The security test rejects equal/larger reported sizes; this does not authenticate ICMP.
//# Upon receipt of an ICMP "Packet Too Big" error message, the Next-Hop MTU claimed by the
//# ICMP message (henceforth "claimedmtu") is compared with maxsizesent. If claimedmtu is
//# larger than maxsizesent, then the ICMP error message is silently discarded. The
//# rationale for this is that the ICMP error message cannot be legitimate if it claims to
//# have been triggered by a packet larger than the largest packet we have so far sent for
//# this connection.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
//= type=test
//= reason=Selected below-proven-size update policy records a pending report without lowering PMTU; the wire test asserts PMTU remains 1500 until matching-head timeout.
//# On the other hand, if claimedmtu is smaller than maxsizeacked, TCP is supposed to be in
//# the Path-MTU Update stage. At this stage, these implementations are more cautious with
//# the errors being reported by the network, and therefore just record the received error
//# message, and delay the update of the assumed Path-MTU.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
//= type=test
//= reason=Selected policy clears pending when the quoted sequence is acknowledged; the security test exercises advancing partial ACK and proves a later timeout does not apply the report. Additional clearing on any other progress is a deliberate deviation, not literal algorithm equivalence.
//# If, while there is a pending ICMP "Packet Too Big" error message, the TCP SEQ claimed by
//# the pending message is acknowledged (i.e., an ACK that acknowledges that sequence number
//# is received), then the "pending error" condition is cleared.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
//= type=test
//= reason=Informational serial-arithmetic guidance: Seq::in_window and wrapping comparisons, exercised across u32 wrap; exact-match sent evidence is an additional policy gate.
//# Notes: All comparisons between sequence numbers must be performed using sequence number
//# arithmetic.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.2
//= type=test
//= reason=Selected cautious-update behavior defers a candidate below proven delivery; existing wire test contrasts progress clearing with quoted-head timeout. Historical variable resets are not claimed.
//# The Path-MTU Update stage is when TCP tries to send segments that are equal to or
//# smaller than the ones that have already been sent and acknowledged for this
//# connection. During the Path-MTU Update stage, TCP already has knowledge of the
//# estimated Path-MTU for the given connection. Thus, in this case, these
//# implementations are more cautious with the errors being reported by the network.

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
//= type=test
//= reason=Selected live-sequence check uses serial arithmetic for SND.UNA<=seq<SND.NXT; the same stale/idle/wrapped quote test supports 044. Unrelated initialization and reset deviations do not invalidate this branch.
//# if (claimedtcpseq < SND.UNA || claimedtcpseq >= SND.NXT) drop_message();

//= https://www.rfc-editor.org/rfc/rfc5927#section-7.4
//= type=test
//= reason=Selected gate rejects candidate>=current_mtu or >=max_sent, and additionally requires a smaller value than the exact quoted sent size. The security wire test rejects equal and larger reports; stricter rejection is not a missing historical branch.
//# else { if (claimedmtu > maxsizesent || claimedmtu >= current_mtu) drop_message();

//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= type=test
//= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
//# Upon receipt of such a message (henceforth called a "Datagram Too Big" message), the
//# source host reduces its assumed PMTU for the path.

//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= type=test
//= reason=Enabled IPv4 PMTUD retains DF in the codec and reacts to validated lower-MTU feedback; zero-MTU and family-floor tests exercise decrease and bounded repair. This is not a claim about arbitrary external embeddings.
//# Normally, the host continues to set DF in all datagrams, so that if the route
//# changes and the new PMTU is lower, it will be discovered.

//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= type=test
//= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
//# Reductions of the PMTU are detected by Datagram Too Big messages, except on paths
//# for which the host has stopped setting the DF bit.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Enabled core applies validated initial PTB decreases and repacketizes to the new budget; feedback below previously proven delivery is deliberately deferred until the quoted head times out. Immediate and deferred cases are separate from upward probing.
//# Hosts using PMTU Discovery MUST detect decreases in Path MTU as fast as possible.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=IPv4 zero Next-Hop MTU selects the next lower plateau using exact sent length and legacy header correction. Connection, direct-state and native socket tests cover zero-MTU processing; the following section5 cross-reference is context, not a missing feature.
//# Hosts MUST be able to deal with Datagram Too Big messages that do not include the
//# next-hop MTU, since it is not feasible to upgrade all the routers in the Internet in
//# any finite time. A Datagram Too Big message from an unmodified router can be
//# recognized by the presence of a zero in the (newly-defined) Next-Hop MTU field.

//= https://www.rfc-editor.org/rfc/rfc1191#section-8
//= type=test
//= reason=IPv4 feedback rejects equal/larger and impossible candidates; exact-quote tests show these do not raise the estimate. The hypothetical attack narrative is not a separate router round-trip or on-path-blocker obligation.
//# In the other attack, the false message indicates a PMTU greater than reality. If
//# believed, this could cause temporary blockage as the victim sends datagrams that
//# will be dropped by some router. Within one round-trip time, the host would discover
//# its mistake (receiving Datagram Too Big messages from that router), but frequent
//# repetition of this attack could cause lots of datagrams to be dropped. A host,
//# however, should never raise its estimate of the PMTU based on a Datagram Too Big
//# message, so should not be vulnerable to this attack.

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
//= https://www.rfc-editor.org/rfc/rfc4821#section-5.1
//= type=test
//= reason=Supported non-probe accounting subtracts actual IP header length and TCP options. The IPv4 options test rejects a mismatched quote header and bounds repair including those headers; unsupported IPsec/IPv6 extension headers are not emitted.
//# The way in which PLPMTUD operates across multiple layers requires a mechanism for
//# accounting header sizes at all layers between IP and the Packetization Layer
//# (inclusive). When transmitting non-probe packets, it is sufficient for the
//# Packetization Layer to ensure an upper bound on final IP packet size, so as not to
//# exceed the current

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
//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=Both families retain ten-minute PTB hold through ACK progress and local link growth; only subsequent ACK-confirmed PLPMTUD can raise effective PMTU.
//# Nodes may detect increases in PMTU, but because doing so requires sending packets larger
//# than the current estimated PMTU, and because the likelihood is that the PMTU will not
//# have increased, this must be done at infrequent intervals. An attempt to detect an
//# increase (by sending a packet larger than the current estimate) must not be done less
//# than 5 minutes after a Packet Too Big message has been received for the given path. The
//# recommended setting for this timer is twice its minimum value (10 minutes).

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=Binary target is strictly above search_low and <=search_high; actual IP probe size checked for IPv4/IPv6 and constrained by peer/allocation ceilings.
//# When transmitting probes, the Packetization Layer MUST select a probe size that is
//# larger than search_low and smaller than or equal to search_high.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.6.1
//= type=test
//= reason=Unambiguous explicit-probe cumulative ACK raises low and effective MTU; failed encoding cannot create a probe or advance flight.
//# When the probe is delivered, it is an indication that the Path MTU is at least as large
//# as the probe size. Set search_low to the probe size. If the probe size is larger than
//# the eff_pmtu, raise eff_pmtu to the probe size. The probe size might be smaller than the
//# eff_pmtu if the flow has not been using the full MTU of the path because it is subject
//# to some other limitation, such as available data in an interactive session.

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.2
//= type=test
//= reason=Enabled core implements validated PTB, real-data ACK-confirmed probes, bounded search and R1 black-hole fallback. Native IPv4 TUN/AF_PACKET ingress and real MTU startup integrate it. This closes the implementation recommendation, not all external RFC clauses: RFC1191/8201/4821 inventories retain exact gaps; native IPv6 sockets remain unsupported.
//# Instead, implementation of Path MTU Discovery (PMTUD) and Packetization Layer Path MTU
//# Discovery (PLPMTUD) is strongly recommended in order for TCP to improve segmentation
//# decisions.
//= https://www.rfc-editor.org/rfc/rfc4821#section-2
//= type=test
//= reason=Explicit probe ACK raises effective PMTU and search_low; the wire test checks both families and the next larger probe.
//# The general strategy is for the Packetization Layer to find an appropriate Path
//# MTU by probing the path with progressively larger packets. If a probe packet is
//# successfully delivered, then the effective Path MTU is raised to the probe size.

//= https://www.rfc-editor.org/rfc/rfc4821#section-5.1
//= type=test
//= reason=The selected probe size includes IP and TCP headers. The wire test asserts final IPv4/IPv6 probe length equals the recorded size and failed encoding cannot commit probe state; no unsupported extension-header emission is claimed.
//# effective Path MTU. All Packetization Layers participating in classical Path MTU
//# Discovery have this requirement already. When conducting a probe, the
//# Packetization Layer MUST determine the probe packet's final size including IP
//# headers. This requirement is specific to PLPMTUD, and satisfying it may require
//# additional inter- layer communication in existing implementations.

//= https://www.rfc-editor.org/rfc/rfc4821#section-5.2
//= type=test
//= reason=Pmtud is stored on the individual Connection, not indexed by remote network or subnet number. A paired connection test leaves the peer PMTUD-disabled while updating only the sender; no route-mask representation is used.
//# Network or subnet numbers MUST NOT be used as representations of a path, because
//# there is not a general mechanism to determine the network mask at the remote host.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.5
//= type=test
//= reason=Probe is committed only after successful encoding; final IP length equals the selected size in IPv4 and IPv6. Outcome-specific response requirements are separate, not prerequisites for this size/commit clause.
//# Once a probe size in the appropriate range has been selected, and the above
//# preconditions have been met, the Packetization Layer MAY conduct a probe. To do
//# so, it creates a probe packet such that its size, including the outermost IP
//# headers, is equal to the probe size. After sending the probe it awaits a response,
//# which will have one of the following results:

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=State relationship is retained as operative: upward probe success sets low and effective PMTU together; the wire test checks both values and the next upward probe. Initial eff>low is permitted and does not imply an implicit-ACK update here; that distinct SHOULD remains TODO at 111.
//# When probing upward, eff_pmtu always equals search_low. In other states, such as
//# initial conditions, after ICMP PTB message processing or following PLPMTUD on
//# another flow sharing the same path representation, eff_pmtu may be different from
//# search_low. Normally, eff_pmtu will be greater than or equal to search_low and
//# less than search_high. It is generally expected but not required that probe size
//# will be greater than eff_pmtu.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Accepted PTB inhibits upward probing for 600 seconds, including after ACK progress and local link growth. The core test checks the deadline and subsequent real probe for both IP families.
//# An attempt to detect an increase (by sending a datagram larger than the current
//# estimate) MUST NOT be done less than 5 minutes after a Datagram Too Big message has
//# been received for the given destination,

//= https://www.rfc-editor.org/rfc/rfc8201#section-1
//= type=test
//= reason=Enabled IPv6 core implements PTB decrease, full packet budgets and ACK-confirmed upward discovery; the dual-family test performs a real probe after PTB holdoff. Optional minimal implementations are not required to omit discovery. No native IPv6 socket claim.
//# IPv6 nodes should implement Path MTU Discovery in order to discover and take
//# advantage of paths with PMTU greater than the IPv6 minimum link MTU [RFC8200]. A
//# minimal IPv6 implementation (e.g., in a boot ROM) may choose to omit implementation
//# of Path MTU Discovery.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.3
//= type=test
//= reason=Enabled IPv6 core holds PTB for 600 seconds and defaults converged-search aging to 600 seconds, reopens the upper search bound on expiry, and emits an ACK-confirmed larger probe. The dual-family real-probe test exercises periodic retry; configurable periodic aging is separately covered at 8201-069.
//# If the stale PMTU value is too large, this will be discovered almost immediately
//# once a large enough packet is sent on the path. No such mechanism exists for
//# realizing that a stale PMTU value is too small, so an implementation should "age"
//# cached values. When a PMTU value has not been decreased for a while (on the order of
//# 10 minutes), it should probe to find if a larger PMTU is supported.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
//= type=test
//= reason=Connection uses the PMTU-derived budget for ordinary data/retries and a distinct bounded real-data probe size. Dual-family wire tests check the exact larger probe and unchanged effective PMTU before ACK; base-header IPv6 packets are unfragmented. IP-service polling is an optional implementation example.
//# A packetization layer (e.g., TCP) must use the PMTU for the path(s) in use by a
//# connection; it should not send segments that would result in packets larger than the
//# PMTU, except to probe during PMTU Discovery (this probe packet must not be
//# fragmented to the PMTU). A simple implementation could ask the IP layer for this
//# value each time it created a new segment, but this could be inefficient. An
//# implementation typically caches other values derived from the PMTU. It may be
//# simpler to receive asynchronous notification when the PMTU changes, so that these
//# variables may be also updated.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.5
//= type=test
//= reason=TCP packetizes ordinary data to the path budget and provides real-data discovery probes. The dual-family test checks complete probe length and ACK-confirmed increase; this is the transport duty, not an NFS conformance claim.
//# In this case, the transport is responsible for ensuring that transmitted segments
//# (except probes) conform to the Path MTU, including supporting PMTU Discovery probe
//# transmissions as needed.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3
//= type=test
//= reason=Exact PTB half of the two-timer recommendation in parent 1191-013: accepted PTB holds upward probing for the recommended 600 seconds. The separate 2-minute post-success half is unselected, not covered by this evidence.
//# 10 minutes

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
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//= reason=R1 uses third consecutive data RTO; earlier RTOs preserve PMTU, later ones halve to family floor while cwnd follows normal timeout response.
//# Under all conditions, a full-stop timeout (also known as a "persistent timeout" in other
//# documents) SHOULD be taken as an indication of some significantly disruptive event in
//# the network, such as a router failure or a routing change to a path with a smaller MTU.
//# For TCP, this occurs when the R1 timeout threshold described by [RFC1122] expires.

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.7.2
//= type=test
//= reason=Enabled core implements validated PTB, real-data ACK-confirmed probes, bounded search and R1 black-hole fallback. Native IPv4 TUN/AF_PACKET ingress and real MTU startup integrate it. This closes the implementation recommendation, not all external RFC clauses: RFC1191/8201/4821 inventories retain exact gaps; native IPv6 sockets remain unsupported.
//# Instead, implementation of Path MTU Discovery (PMTUD) and Packetization Layer Path MTU
//# Discovery (PLPMTUD) is strongly recommended in order for TCP to improve segmentation
//# decisions.
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=By default Pmtud::new initializes search_low to min(bound,1024) for IPv4 or min(bound,1280) for IPv6. The full-stop test checks both family starting lows through the first fallback; independent creation-time configurability is covered at 113.
//# For initial conditions when there is no information about the path, eff_pmtu may
//# be greater than search_low. The initial value of search_low SHOULD be
//# conservatively low, but performance may be better if eff_pmtu starts at a higher,
//# less conservative, value. See Section 7.2.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.7
//= type=test
//# If there is a full-stop timeout and there was not an ICMP message indicating a reason (PTB, Net unreachable, etc., or the ICMP message was ignored for some reason), the RECOMMENDED first recovery action is to treat this as a detected ICMP black hole as defined in [RFC2923].
fn pmtud_full_stop_r1_halving_and_normal_congestion_response() {
    for ipv4 in [true, false] {
        for feedback in 0..4 {
            let (mut a, _) = family_pair(cfg(1500), ipv4, 0);
            a.write(&[7; 1400]).unwrap();
            let original = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
            // A stale quote cannot explain the current full stop.
            assert!(
                !a.network_error(41, a.snd_nxt.0, NetworkError::SoftUnreachable)
                    .unwrap()
            );
            let known_mtu = match feedback {
                1 => {
                    assert!(
                        a.network_error(42, a.snd_una.0, NetworkError::SoftUnreachable)
                            .unwrap()
                    );
                    assert_eq!(
                        a.take_events().network_error,
                        Some(NetworkError::SoftUnreachable)
                    );
                    Some(1500)
                }
                2 => {
                    assert!(
                        !a.network_error(42, a.snd_una.0, NetworkError::SourceQuench)
                            .unwrap()
                    );
                    assert_eq!(a.take_events().network_error, None);
                    None
                }
                3 => {
                    let mtu = if ipv4 { 1006 } else { 1280 };
                    assert!(
                        a.pmtu_feedback(
                            42,
                            a.snd_una.0,
                            original.len() as u32,
                            if ipv4 { 20 } else { 40 },
                            mtu
                        )
                        .unwrap()
                    );
                    Some(mtu)
                }
                _ => None,
            };
            assert_eq!(a.state(), State::Established);
            for count in 1..=8 {
                let expiry = a.loss_timer.unwrap().1;
                a.timeout(expiry).unwrap();
                assert_eq!(a.consecutive_timeouts, count);
                let expected = if let Some(mtu) = known_mtu {
                    mtu
                } else if count < 3 {
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
                assert_eq!(a.state(), State::Established);
            }
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
        // The last emitted segment can extend beyond the initial probe boundary.
        let trailing_end = a.snd_nxt;
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
            let parsed = parse_ip_test(&retry, false).unwrap();
            assert_eq!(
                wire::parse(ip(a.tuple), parsed.payload)
                    .unwrap()
                    .header
                    .sequence,
                probe.end.0
            );
        }
        ack(&mut a, 45, trailing_end);
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
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
//# o The available window is greater than the probe size.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
//# o For a protocol using in-band data for probing, enough data is available to send the
//# probe.

//= https://www.rfc-editor.org/rfc/rfc4821#section-7.4
//= type=test
//= reason=Admission requires probe payload plus three MSS of queued/window credit, measured RTT and timestamp/pacing credit. This test asserts absent probe for insufficient window/queue/RTT and bounded paced output.
//# In addition, the timely loss detection algorithms in most protocols have pre-conditions
//# that SHOULD be satisfied before sending a probe. For example, TCP Fast Retransmit is not
//# robust unless there are sufficient segments following a probe; that is, the sender
//# SHOULD have enough data queued and sufficient receiver window to send the probe plus at
//# least Tcprexmtthresh [RFC2760] additional segments. This restriction may inhibit probing
//# in some protocol states, such as too close to the end of a connection, or when the
//# window is too small.

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
//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
//# A host doing PMTU Discovery must obey the rule that it not send IP datagrams larger than
//# 576 octets unless it has permission from the receiver. For TCP connections, this means
//# that a host must not send datagrams larger than 40 octets plus the Maximum Segment Size
//# (MSS) sent by its peer.

//= https://www.rfc-editor.org/rfc/rfc1191#section-3.1
//= type=test
//= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
//# Note: The TCP MSS is defined to be the relevant IP datagram size minus 40 [9]. The
//# default of 576 octets for the maximum IP datagram size yields a default of 536 octets
//# for the TCP MSS.

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.4
//= type=test
//= reason=Peer MSS is stored separately from receive capability; missing IPv4 MSS defaults536 and emitted packets remain <=576 even with local MTU9000.
//# A TCP implementation must also store the MSS value received from its peer (which
//# defaults to 536), and not send any segment larger than this MSS, regardless of the PMTU.
//# In 4.xBSD-derived implementations, this requires adding an additional field to the TCP
//# state record.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
//= type=test
//= reason=IPv6 core stores peer MSS separately, defaults1220, caps transmit size independently of local link and retains receive MSS1460.
//# A TCP implementation must also store the Maximum Segment Size (MSS) value received from
//# its peer, which represents the EMTU_R, the largest packet that can be reassembled by the
//# receiver, and must not send any segment larger than this MSS, regardless of the PMTU.

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.4
//= type=test
//= reason=IPv6 core stores peer MSS separately, defaults1220, caps transmit size independently of local link and retains receive MSS1460.
//# The value sent in the TCP MSS option is independent of the PMTU; it is determined by the
//# receiver reassembly limit EMTU_R. This MSS option value is used by the other end of the
//# connection, which may be using an unrelated PMTU value. See Section 5, "Packet Size
//# Issues", and Section 8.3, "Maximum Upper-Layer Payload Size", of [RFC8200] for
//# information on selecting a value for the TCP MSS option.

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
//= https://www.rfc-editor.org/rfc/rfc4821#section-6.2
//= type=test
//= reason=TCP probes use real queued stream bytes, respecting record boundary and allocation; no synthetic padding or control-only TCP size probe.
//# These techniques do not work for TCP, because there is not a separate length field or
//# other mechanism to differentiate between padding and real payload data. With TCP the
//# only approach is to send additional payload data in an over-sized segment. There are at
//# least two variants of this approach, discussed in Section 10.1.

//= https://www.rfc-editor.org/rfc/rfc4821#section-10.1
//= type=test
//= reason=TCP probes use real queued stream bytes, respecting record boundary and allocation; no synthetic padding or control-only TCP size probe.
//# TCP has no mechanism to distinguish in-band data from padding. Therefore, TCP must
//# generate probes by appropriately segmenting data. There are two approaches to
//# segmentation: overlapping and non- overlapping.

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
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.1
//= type=test
//= reason=Every non-probe output checks final TCP header/options/data against path payload budget before commit; floor68 retry includes timestamps and SACK within budget.
//# When transmitting non-probes, the Packetization Layer SHOULD create packets of a size
//# less than or equal to eff_pmtu.

//= https://www.rfc-editor.org/rfc/rfc4821#section-8
//= type=test
//= reason=TCP avoids fragmentation by respecting the current complete-IP non-probe budget; the floor/options repair test checks the emitted size. The UDP example does not require a host datagram fragmentation service.
//# Packetization Layers SHOULD avoid sending messages that will require fragmentation
//# [Kent87] [frag-errors]. However, entirely preventing fragmentation is not always
//# possible. Some Packetization Layers, such as a UDP application outside the kernel,
//# may be unable to change the size of messages it sends, resulting in datagram sizes
//# that exceed the Path MTU.

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
    let packet = parse_ip_test(&bytes, false).unwrap();
    let segment = wire::parse(ip(a.tuple), packet.payload).unwrap();
    assert!(segment.options.timestamps.is_some());
    assert!(segment.options.sack_blocks[0].is_some());
    assert_eq!(segment.header.sequence, seq);
    assert!(segment.payload.len() <= 4);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= type=test
//= reason=PMTU decrease rescales cwnd by new/old MSS for Reno and CUBIC without changing allocation or existing pacing debt; tested with PRR enabled.
//# Whenever the MTU is reduced (e.g., when processing ICMP PTB messages), the congestion
//# state variable SHOULD be rescaled so as not to raise the window size in packets.

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
    let parsed = parse_ip_test(&frame, false).unwrap();
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

#[test]
//= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
//= type=test
//= reason=Initial/search bound intersects supplied interface, peer, administrative and allocation limits. Administrative ceilings survive validated growth without changing receive MSS.
//# The initial value for search_high SHOULD be the largest possible packet that might be
//# supported by the flow. This may be limited by the local interface MTU, by an explicit
//# protocol mechanism such as the TCP MSS option, or by an intrinsic limit such as the size
//# of a protocol length field. In addition, the initial value for search_high MAY be
//# limited by a configuration option to prevent probing above some maximum size.
//# Search_high is likely to be the same as the initial Path MTU as computed by the
//# classical Path MTU Discovery algorithm.

fn pmtud_lower_mss_persists_administrative_ceiling_across_validated_growth() {
    for ceiling in [468u16, 1000] {
        let mut config = cfg(1500);
        config.timestamps = false;
        let (mut a, _) = family_pair(config, true, 0);
        assert_eq!(a.mss, 1460);
        a.write(&[1; 1460]).unwrap();
        let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        let seq = a.snd_una.0;
        assert!(
            a.pmtu_feedback(41, seq, frame.len() as u32, 20, 508)
                .unwrap()
        );
        assert_eq!(a.mss, 468);

        a.lower_mss(ceiling).unwrap();
        assert_eq!(a.send_mss_limit, ceiling);
        assert_eq!(a.mss, 468);
        assert_eq!(a.config.mss, 1460);
        let before = a.path_mtu_info();
        assert_eq!(a.lower_mss(0), Err(Error::InvalidArgument));
        assert_eq!(a.lower_mss(ceiling + 1), Err(Error::InvalidArgument));
        assert_eq!(a.path_mtu_info(), before);
        a.lower_mss(ceiling).unwrap();
        let end = a.snd_nxt;
        ack(&mut a, 50, end);

        // For the equal-effective ceiling, first lower the link so real
        // probe/ACK growth can exercise the saved ceiling too.
        if ceiling == 468 {
            a.set_first_hop_mtu(51, 296).unwrap();
        }
        let reduced = a.path_mtu_info().unwrap().current_mtu;
        a.set_first_hop_mtu(52, 2000).unwrap();
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, reduced);
        let deadline = a.pmtud.as_ref().unwrap().deadline.unwrap();
        a.timeout(deadline).unwrap();
        assert_eq!(
            a.path_mtu_info().unwrap().search_high,
            u32::from(ceiling) + 40
        );
        a.write(&[5; 20_000]).unwrap();
        for step in 0..16 {
            let now = deadline + step * 1000;
            let frame = wire_packet(&mut a, now, OutgoingIpv4Options::default());
            let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
            assert_eq!(frame.len(), probe.size as usize);
            assert!(probe.size > a.path_mtu_info().unwrap().current_mtu);
            assert!(frame.len() <= usize::from(ceiling) + 40);
            ack(&mut a, now + 100, probe.end);
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, probe.size);
            assert!(a.mss <= usize::from(ceiling));
            if a.mss == usize::from(ceiling) {
                break;
            }
        }
        assert_eq!(a.mss, usize::from(ceiling));
        assert_eq!(a.lower_mss(ceiling + 1), Err(Error::InvalidArgument));
    }
}

// Test-only projection lets the original mixed-family assertions stay intact.
fn parse_ip_test(
    bytes: &[u8],
    source_routes: bool,
) -> Result<ntcp_ip::Packet<'_>, ntcp_ip_common::Error> {
    if bytes.first().ok_or(ntcp_ip_common::Error::Truncated)? >> 4 == 6 {
        let p = ntcp_ip6::parse(bytes)?;
        Ok(ntcp_ip::Packet {
            ip: p.ip,
            traffic_class: p.traffic_class,
            hop_limit: p.hop_limit,
            protocol: p.protocol,
            ipv4_options: Default::default(),
            payload: p.payload,
        })
    } else {
        ntcp_ip::parse(bytes, source_routes)
    }
}

#[path = "pmtud_ipv6_evidence_tests.rs"]
mod ipv6_evidence;
