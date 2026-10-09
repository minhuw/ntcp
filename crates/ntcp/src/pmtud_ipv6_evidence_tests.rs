use super::*;
use crate::{Endpoint, EndpointConfig};

fn v6_config() -> ConnectionConfig {
    ConnectionConfig {
        timestamps: false,
        sack: false,
        delayed_ack_us: 0,
        ..cfg(1500)
    }
}

// A router quotes the actual base-header packet, possibly only the first
// eight TCP bytes. Its address need not be either endpoint's address.
fn ptb(frame: &[u8], mtu: u32) -> Vec<u8> {
    let mut bytes = vec![0; 48 + frame.len()];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&((8 + frame.len()) as u16).to_be_bytes());
    bytes[6] = 58;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(
        &"2001:db8::fe"
            .parse::<core::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    bytes[24..40].copy_from_slice(&frame[8..24]);
    bytes[40] = 2;
    bytes[44..48].copy_from_slice(&mtu.to_be_bytes());
    bytes[48..].copy_from_slice(frame);
    seal_ptb(&mut bytes);
    bytes
}

fn seal_ptb(bytes: &mut [u8]) {
    bytes[42..44].fill(0);
    let outer = ntcp_ip::parse(bytes, false).unwrap();
    let sum = ntcp_ip::icmpv6_checksum(outer.ip, outer.payload).unwrap();
    bytes[42..44].copy_from_slice(&sum.to_be_bytes());
}

fn feedback(a: &mut Connection, now: u64, bytes: &[u8]) -> bool {
    let f = ntcp_ip::decode_icmp(bytes).unwrap();
    assert_eq!(f.kind, ntcp_ip::FeedbackKind::PacketTooBig);
    assert_eq!(f.quoted.ip.source, a.tuple.local.ip());
    assert_eq!(f.quoted.ip.destination, a.tuple.remote.ip());
    assert_eq!(f.quoted.source_port, a.tuple.local.port());
    assert_eq!(f.quoted.destination_port, a.tuple.remote.port());
    a.pmtu_feedback(
        now,
        f.quoted.sequence,
        f.quoted.ip_packet_len,
        f.quoted.ip_header_len,
        f.candidate_mtu.unwrap(),
    )
    .unwrap()
}

fn receive(b: &mut Connection, now: u64, frame: &[u8]) {
    let p = ntcp_ip::parse(frame, false).unwrap();
    b.input(
        now,
        &wire::parse(
            IpMetadata {
                source: p.ip.source,
                destination: p.ip.destination,
            },
            p.payload,
        )
        .unwrap(),
    )
    .unwrap();
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=IPv6 base-header wire test from 819b8f2 covers decode_icmp checksum, truncation, impossible quoted payload length and outer-destination rejection, then exact sent-ledger sequence/size validation and stale quotes after real receiver ACKs, idle or with new flight, including wrap. A valid minimal quote is accepted. Plausibility validation is not authentication against a knowledgeable attacker; no native IPv6 socket or extension-header claim.
//# Nodes should appropriately validate the payload of ICMPv6 PTB messages to ensure
//# these are received in response to transmitted traffic (i.e., a reported error
//# condition that corresponds to an IPv6 packet actually sent by the application)
//# per [ICMPv6].

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=Pmtud::feedback rejects nondecreasing candidates. IPv6 base-header wire test from 819b8f2 supplies exact emitted-packet quotes with equal/larger MTUs (1500, 2000, UINT32_MAX), then repeats 1400/1500/2000 after an accepted 1400 decrease; estimates never increase, including wrapped sequence ranges. No native IPv6 socket or extension-header claim.
//# A node must not increase its estimate of the Path MTU in response to the
//# contents of a Packet Too Big message. A message purporting to announce an
//# increase in the Path MTU might be a stale packet that has been floating around
//# in the network, a false packet injected as part of a denial-of-service (DoS)
//# attack, or the result of having multiple paths to the destination, each with a
//# different PMTU.

//= https://www.rfc-editor.org/rfc/rfc8201#section-6
//= type=test
//= reason=The strictly-decreasing feedback guard prevents the described increase attack. IPv6 base-header wire test from 819b8f2 rejects equal/larger MTUs before and after a valid decrease, including wrap. The hypothetical router round-trip is not claimed as a separate implemented behavior; no native IPv6 socket or extension-header claim.
//# In the second attack, the false message indicates a PMTU larger than reality. If
//# believed, this could cause temporary blockage as the victim sends packets that
//# will be dropped by some router. Within one round-trip time, the node would
//# discover its mistake (receiving Packet Too Big messages from that router), but
//# frequent repetition of this attack could cause lots of packets to be dropped. A
//# node, however, must not raise its estimate of the PMTU based on a Packet Too Big
//# message, so it should not be vulnerable to this attack.

#[test]
fn ipv6_ptb_malformed_forged_stale_and_nonincreasing_wire_quotes() {
    for iss in [0, u32::MAX - 100] {
        let (mut a, mut b) = family_pair(v6_config(), false, iss);
        a.write(&[7; 1440]).unwrap();
        let frame = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        assert_eq!(frame.len(), 1500);
        let before = a.path_mtu_info().unwrap();
        let valid = ptb(&frame[..48], 1400);
        let mut malformed = valid.clone();
        malformed[42] ^= 1;
        assert_eq!(
            ntcp_ip::decode_icmp(&malformed).unwrap_err(),
            ntcp_ip::Error::Checksum
        );
        for cut in [40, 47] {
            assert!(ntcp_ip::decode_icmp(&ptb(&frame[..cut], 1400)).is_err());
        }
        let mut malformed = valid.clone();
        malformed[52..54].copy_from_slice(&19u16.to_be_bytes());
        seal_ptb(&mut malformed);
        assert_eq!(
            ntcp_ip::decode_icmp(&malformed).unwrap_err(),
            ntcp_ip::Error::Quote
        );
        let mut wrong_outer = valid.clone();
        wrong_outer[39] ^= 1;
        seal_ptb(&mut wrong_outer);
        assert_eq!(
            ntcp_ip::decode_icmp(&wrong_outer).unwrap_err(),
            ntcp_ip::Error::Quote
        );
        for (offset, value) in [(47, frame[47].wrapping_add(1)), (5, frame[5] - 1)] {
            let mut forged = frame[..48].to_vec();
            forged[offset] = value;
            assert!(!feedback(&mut a, 41, &ptb(&forged, 1400)));
        }
        for mtu in [0, 1279, 1500, 2000, u32::MAX] {
            assert!(!feedback(&mut a, 41, &ptb(&frame[..48], mtu)));
            assert_eq!(a.path_mtu_info().unwrap(), before);
        }
        assert!(feedback(&mut a, 42, &valid));
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
        for mtu in [1400, 1500, 2000] {
            assert!(!feedback(&mut a, 43, &ptb(&frame[..48], mtu)));
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
        }
        receive(&mut b, 44, &frame);
        deliver(&mut b, &mut a, 45);
        assert!(!feedback(&mut a, 46, &ptb(&frame[..48], 1280)));
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
        a.write(&[8; 1440]).unwrap();
        wire_packet(&mut a, 47, OutgoingIpv4Options::default());
        assert!(!feedback(&mut a, 48, &ptb(&frame[..48], 1280)));
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1400);
    }
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-4
//= type=test
//= reason=Enabled IPv6 core applies validated initial decreases and deliberately defers below-proven-delivery reports under the selected security policy. Test from 819b8f2 establishes proof with a real 1500-byte packet/receiver ACK, contrasts progress clearing with quoted-head RTO applying 1280, and verifies bounded wire repair and receiver ACK progress through wrap. No unconditional trust of PTB or native IPv6 socket claim.
//# the dropped packets they respond to) consume network resources, nodes using Path
//# MTU Discovery must detect decreases in PMTU as fast as possible.

#[test]
fn ipv6_below_proven_ptb_progress_clears_but_head_rto_applies() {
    for iss in [0, u32::MAX - 100] {
        for progress in [false, true] {
            let (mut a, mut b) = family_pair(v6_config(), false, iss);
            a.write(&[2; 1440]).unwrap();
            let proven = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
            assert_eq!(proven.len(), 1500);
            receive(&mut b, 41, &proven);
            deliver(&mut b, &mut a, 50);
            a.write(&[3; 2880]).unwrap();
            let frame = wire_packet(&mut a, 60, OutgoingIpv4Options::default());
            assert_eq!(frame.len(), 1500);
            assert!(feedback(&mut a, 61, &ptb(&frame[..48], 1280)));
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1500);
            if progress {
                receive(&mut b, 62, &frame);
                deliver(&mut b, &mut a, 63);
                // Keep a subsequent real packet outstanding for an RTO after progress.
                wire_packet(&mut a, 64, OutgoingIpv4Options::default());
            }
            let expiry = a.loss_timer.unwrap().1;
            let cwnd = a.congestion.cwnd();
            a.timeout(expiry).unwrap();
            let mtu = if progress { 1500 } else { 1280 };
            assert_eq!(a.path_mtu_info().unwrap().current_mtu, mtu);
            assert!(a.congestion.cwnd() < cwnd);
            let repair = wire_packet(&mut a, expiry, OutgoingIpv4Options::default());
            assert!(repair.len() <= mtu as usize);
            receive(&mut b, expiry, &repair);
            let una = a.snd_una;
            deliver(&mut b, &mut a, expiry + 1);
            assert!(after(a.snd_una, una));
        }
    }
}

fn endpoint_packet(a: &mut Endpoint, now: u64) -> Vec<u8> {
    let mut tcp = vec![0; 2000];
    let tx = a.poll_transmit(now, &mut tcp, 16).unwrap().packet.unwrap();
    let mut frame = vec![0; 40 + tx.len];
    frame[40..].copy_from_slice(&tcp[..tx.len]);
    frame[0] = 0x60;
    frame[4..6].copy_from_slice(&(tx.len as u16).to_be_bytes());
    frame[6] = 6;
    frame[7] = tx.hop_limit;
    let (core::net::IpAddr::V6(src), core::net::IpAddr::V6(dst)) =
        (tx.ip.source, tx.ip.destination)
    else {
        panic!("IPv6 only")
    };
    frame[8..24].copy_from_slice(&src.octets());
    frame[24..40].copy_from_slice(&dst.octets());
    frame
}

fn endpoint_feedback(a: &mut Endpoint, now: u64, bytes: &[u8]) -> bool {
    let f = ntcp_ip::decode_icmp(bytes).unwrap();
    a.pmtu_feedback(
        now,
        Tuple {
            local: core::net::SocketAddr::new(f.quoted.ip.source, f.quoted.source_port),
            remote: core::net::SocketAddr::new(f.quoted.ip.destination, f.quoted.destination_port),
        },
        f.quoted.sequence,
        f.quoted.ip_packet_len,
        f.quoted.ip_header_len,
        f.candidate_mtu.unwrap(),
    )
    .unwrap()
}

//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Endpoint::pmtu_feedback dispatches the decoded quoted outbound tuple to its connection-local path. IPv6 base-header test from 819b8f2 rejects wrong quoted source/destination addresses and ports and isolates accepted 1280/1400 updates across two distinct local addresses. This does not establish same-address per-interface isolation, Routing Header interpretation or native IPv6 sockets.
//# When a Packet Too Big message is received, the node determines which path the
//# message applies to based on the contents of the Packet Too Big message. For
//# example, if the destination address is used as the local representation of a
//# path, the destination address from the original packet would be used to
//# determine which path the message applies to.

#[test]
fn ipv6_endpoint_quoted_tuple_dispatch_and_distinct_local_identity_isolation() {
    let mut a = Endpoint::new(
        EndpointConfig {
            connection: v6_config(),
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    let mut flows = Vec::new();
    for (n, local) in ["[2001:db8:1::1]:1000", "[2001:db8:2::1]:1000"]
        .iter()
        .enumerate()
    {
        let now = n as u64 * 100;
        let t = Tuple {
            local: local.parse().unwrap(),
            remote: "[2001:db8::2]:2000".parse().unwrap(),
        };
        let id = a.connect(now, t.local, t.remote).unwrap();
        let syn = endpoint_packet(&mut a, now);
        let p = ntcp_ip::parse(&syn, false).unwrap();
        let mut peer = v6_config();
        peer.pmtud = None;
        let mut b = Connection::passive(
            reverse(t),
            peer,
            900,
            now + 10,
            &wire::parse(
                IpMetadata {
                    source: p.ip.source,
                    destination: p.ip.destination,
                },
                p.payload,
            )
            .unwrap(),
        )
        .unwrap();
        let bytes = packet(&mut b, now + 20);
        a.input(now + 20, ip(b.tuple), &bytes).unwrap();
        receive(&mut b, now + 30, &endpoint_packet(&mut a, now + 30));
        a.write(id, &[9; 1440]).unwrap();
        let frame = endpoint_packet(&mut a, now + 40);
        assert_eq!(frame.len(), 1500);
        flows.push((id, frame));
    }
    for offset in [23, 39, 41, 43] {
        // quoted source/destination address and ports
        let mut forged = flows[0].1[..48].to_vec();
        forged[offset] ^= 0x10;
        assert!(!endpoint_feedback(&mut a, 150, &ptb(&forged, 1280)));
        for (id, _) in &flows {
            assert_eq!(a.path_mtu_info(*id).unwrap().unwrap().current_mtu, 1500);
        }
    }
    assert!(endpoint_feedback(
        &mut a,
        151,
        &ptb(&flows[0].1[..48], 1280)
    ));
    assert_eq!(
        a.path_mtu_info(flows[0].0).unwrap().unwrap().current_mtu,
        1280
    );
    assert_eq!(
        a.path_mtu_info(flows[1].0).unwrap().unwrap().current_mtu,
        1500
    );
    assert!(endpoint_feedback(
        &mut a,
        152,
        &ptb(&flows[1].1[..48], 1400)
    ));
    assert_eq!(
        a.path_mtu_info(flows[1].0).unwrap().unwrap().current_mtu,
        1400
    );
    assert_eq!(
        a.path_mtu_info(flows[0].0).unwrap().unwrap().current_mtu,
        1280
    );
}

fn lost_probe_repairs(iss: u32, smaller_ptb: bool) {
    let t = Tuple {
        local: "[2001:db8::1]:1000".parse().unwrap(),
        remote: "[2001:db8::2]:2000".parse().unwrap(),
    };
    let mut a = Connection::active(t, v6_config(), iss, 0).unwrap();
    let bytes = packet(&mut a, 0);
    let mut syn = wire::parse(ip(t), &bytes).unwrap();
    // As in the IPv4 lifecycle fixture, negotiate a legacy non-WS peer.
    syn.options.window_scale = None;
    let mut peer = v6_config();
    peer.pmtud = None;
    let mut b = Connection::passive(reverse(t), peer, 900, 10, &syn).unwrap();
    deliver(&mut b, &mut a, 20);
    deliver(&mut a, &mut b, 30);
    a.write(b"x").unwrap();
    deliver(&mut a, &mut b, 32);
    deliver(&mut b, &mut a, 33);
    a.write(&[7; 20_000]).unwrap();
    let lost = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
    let probe = a.pmtud.as_ref().unwrap().probe.unwrap();
    assert_eq!(lost.len(), probe.size as usize);
    assert!(probe.size > 1280);
    let before = a.path_mtu_info().unwrap();
    let cwnd = a.congestion.cwnd();
    let mut trailing = Vec::new();
    for _ in 0..8 {
        trailing.push(wire_packet(&mut a, 41, OutgoingIpv4Options::default()));
    }
    for frame in &trailing {
        let recovering = a.congestion.in_fast_recovery();
        receive(&mut b, 43, frame);
        deliver(&mut b, &mut a, 43);
        if !recovering && a.congestion.in_fast_recovery() {
            assert!(a.congestion.cwnd() < cwnd);
        }
    }
    assert!(a.retx_pending);
    assert!(a.congestion.in_fast_recovery());
    // Later duplicate ACKs inflate Reno cwnd; ssthresh retains the loss reduction.
    assert!(a.congestion.ssthresh() < cwnd);
    if smaller_ptb {
        // Two downstream routers quote the same actual dropped probe.
        assert!(feedback(&mut a, 44, &ptb(&lost[..48], probe.size - 1)));
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, probe.size - 1);
        assert!(feedback(&mut a, 45, &ptb(&lost[..48], 1280)));
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1280);
        assert!(a.congestion.ssthresh() < cwnd);
    }
    let mut repairs = 0;
    for n in 0..16 {
        let now = 50 + n;
        let start = a.snd_una;
        let frame = wire_packet(&mut a, now, OutgoingIpv4Options::default());
        let p = ntcp_ip::parse(&frame, false).unwrap();
        let s = wire::parse(
            IpMetadata {
                source: p.ip.source,
                destination: p.ip.destination,
            },
            p.payload,
        )
        .unwrap();
        if start.in_window(probe.start, probe.end.distance_from(probe.start)) == Some(true) {
            assert_eq!(s.header.sequence, start.0);
            assert!(frame.len() <= before.search_low as usize);
            assert!(
                s.payload.len() as u32 <= probe.end.distance_from(start),
                "iss={iss}, smaller_ptb={smaller_ptb}: repair payload={} crosses remaining probe gap={}",
                s.payload.len(),
                probe.end.distance_from(start)
            );
            repairs += 1;
        }
        receive(&mut b, now, &frame);
        deliver(&mut b, &mut a, now);
        if a.pmtud.as_ref().unwrap().probe.is_none() && !after(probe.end, a.snd_una) {
            break;
        }
    }
    assert!(repairs >= 2);
    assert!(!after(probe.end, a.snd_una));
    assert!(a.pmtud.as_ref().unwrap().probe.is_none());
    assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1280);
    if !smaller_ptb {
        assert_eq!(a.path_mtu_info().unwrap().search_high, probe.size - 1);
    }
}

#[test]
fn ipv6_lost_probe_real_receiver_repairs_and_congestion() {
    for iss in [0, u32::MAX - 4000] {
        lost_probe_repairs(iss, false);
    }
}

#[test]
fn ipv6_smaller_ptb_preserves_probe_repair_boundary_regression() {
    lost_probe_repairs(0, true);
}

#[test]
fn ipv6_smaller_ptb_preserves_wrapped_probe_repair_boundary_regression() {
    lost_probe_repairs(u32::MAX - 4000, true);
}

#[test]
fn ipv6_same_prefix_proxy_wire_path_does_not_bypass_downstream_ptb() {
    // Model a proxy next hop for the same-/64 destination. The core has no
    // neighbor cache or prefix routes: this exercises its wire behavior only,
    // not Neighbor Discovery, proxy configuration, or route selection.
    for iss in [0, u32::MAX - 100] {
        let (mut a, mut b) = family_pair(v6_config(), false, iss);
        a.write(&[9; 1440]).unwrap();
        let original = wire_packet(&mut a, 40, OutgoingIpv4Options::default());
        assert_eq!(original.len(), 1500);
        let end = a.snd_nxt;
        let receiver_start = b.receive.next();
        // First hop admits 1500, proxy's downstream link admits only 1280.
        // Drop rather than forwarding the oversize original to the receiver.
        assert!(original.len() > 1280);
        assert!(feedback(&mut a, 41, &ptb(&original[..48], 1280)));
        assert_eq!(b.receive.next(), receiver_start);
        assert_eq!(a.path_mtu_info().unwrap().first_hop_mtu, 1500);
        assert_eq!(a.path_mtu_info().unwrap().current_mtu, 1280);
        for attempt in 0..4 {
            if !after(end, a.snd_una) {
                break;
            }
            let now = if attempt == 0 {
                42
            } else {
                // Outside fast recovery, the remaining original tail waits for
                // the ordinary retransmission timer; do not invent ACKs/work.
                let expiry = a.loss_timer.unwrap().1;
                a.timeout(expiry).unwrap();
                expiry
            };
            let repair = wire_packet(&mut a, now, OutgoingIpv4Options::default());
            assert!(repair.len() <= 1280);
            receive(&mut b, now, &repair);
            deliver(&mut b, &mut a, now);
        }
        assert_eq!(a.snd_una, end);
        let mut received = [0; 1440];
        assert_eq!(b.read(&mut received), Ok(1440));
        assert_eq!(received, [9; 1440]);
    }
}

#[test]
fn ipv6_endpoint_rejects_scoped_link_identity_instead_of_claiming_interface_isolation() {
    let mut a = Endpoint::new(
        EndpointConfig {
            connection: v6_config(),
            ..EndpointConfig::default()
        },
        [1; 32],
        0,
        |_| true,
    )
    .unwrap();
    for scope in [1, 2] {
        let local = core::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 1000, 0, scope);
        let remote = core::net::SocketAddrV6::new("fe80::2".parse().unwrap(), 2000, 0, scope);
        assert_eq!(
            a.connect(0, local.into(), remote.into()),
            Err(crate::EndpointError::InvalidAddress)
        );
    }
}
