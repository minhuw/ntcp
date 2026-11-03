// The physical input pipeline through real Host/Endpoint owners: UDP, TCP
// and ICMP datagrams arriving as fragments, the Echo service, reassembly
// errors and the Host ICMP output drain.
use super::*;

type Side = (Host, Endpoint, IngressContext);

const UDP: UdpLimits = UdpLimits {
    flows: 1,
    receive_datagrams: 1,
    max_payload: 4000,
    events: 1,
    evicted_signatures: 1,
    probe_receipts: 2,
};
const OUTPUT: IcmpOutputLimits = IcmpOutputLimits {
    messages: 3,
    message_bytes: 4096,
    hop_limit: 64,
};

fn reassembly() -> ReassemblyLimits {
    ReassemblyLimits {
        assemblies: 4,
        fragments: 600,
        buffered_bytes: 8192,
        ipv4_datagram: 4096,
        ipv6_datagram: 4136,
        ipv4_timeout_seconds: 60,
    }
}

fn side(local: SocketAddr, identity: u128, cfg: &EndpointConfig, output: IcmpOutputLimits) -> Side {
    managed_limited(local, identity, cfg.clone(), false, None, None, |p, l| {
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        let (p, mut l) = managed_icmp_output_limits(p, l, output).unwrap();
        l.reassembly = reassembly();
        (p, l, 1)
    })
}

fn ip(source: IpAddr, destination: IpAddr) -> IpMetadata {
    IpMetadata {
        source,
        destination,
    }
}

// A complete datagram of `protocol` carrying `data` (already checksummed).
fn datagram(ip: IpMetadata, protocol: u8, data: &[u8]) -> Vec<u8> {
    let v6 = ip.source.is_ipv6();
    let header = if v6 { 40 } else { 20 };
    let mut packet = vec![0; header + data.len()];
    packet[header..].copy_from_slice(data);
    let n = if v6 {
        let h = ntcp_ip6::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
        };
        ntcp_ip6::encode_datagram(&mut packet, h, protocol, data.len()).unwrap()
    } else {
        let h = ntcp_ip::Header {
            ip,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        ntcp_ip::encode_datagram(&mut packet, h, protocol, data.len(), 0).unwrap()
    };
    assert_eq!(n, packet.len());
    packet
}

fn udp(ip: IpMetadata, ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + payload.len()];
    message[8..].copy_from_slice(payload);
    let n = ntcp_ip_common::encode_udp(
        ip.source,
        ip.destination,
        ports.0,
        ports.1,
        &mut message,
        payload.len(),
    )
    .unwrap();
    datagram(ip, 17, &message[..n])
}

fn echo(ip: IpMetadata, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![0; 8 + data.len()];
    message[8..].copy_from_slice(data);
    let n = ntcp_icmp::encode_echo(
        ip,
        ntcp_icmp::EchoKind::Request,
        identifier,
        sequence,
        &mut message,
        data.len(),
    )
    .unwrap();
    datagram(ip, if ip.source.is_ipv4() { 1 } else { 58 }, &message[..n])
}

// Source fragments of a complete option-free datagram, `chunk` data octets
// each (a multiple of 8), through the codecs' fragmenters.
fn fragments(packet: &[u8], identification: u32, chunk: usize) -> Vec<Vec<u8>> {
    let v6 = packet[0] >> 4 == 6;
    let (parsed_ip, protocol, data) = if v6 {
        let p = ntcp_ip6::parse(packet).unwrap();
        (p.ip, p.protocol, p.payload)
    } else {
        let p = ntcp_ip::parse(packet, false).unwrap();
        (p.ip, p.protocol, p.payload)
    };
    let mut out = Vec::new();
    for offset in (0..data.len()).step_by(chunk) {
        let piece = &data[offset..data.len().min(offset + chunk)];
        let mut buffer = vec![0; 128 + piece.len()];
        let n = if v6 {
            let h = ntcp_ip6::Header {
                ip: parsed_ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
            };
            ntcp_ip6::Fragmenter::new(h, protocol, identification, data.len())
                .unwrap()
                .encode(&mut buffer, offset, piece)
                .unwrap()
        } else {
            let h = ntcp_ip::Header {
                ip: parsed_ip,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            };
            ntcp_ip::Fragmenter::new(h, protocol, identification as u16, data.len(), 0)
                .unwrap()
                .encode(&mut buffer, offset, piece)
                .unwrap()
        };
        buffer.truncate(n);
        out.push(buffer);
    }
    out
}

fn input_frame(side: &mut Side, now: u64, frame: &[u8]) -> Result<ntcp::InputDisposition, Error> {
    side.0.input_ip(
        &mut side.1,
        side.2,
        now,
        frame,
        RxPacketMetadata::default(),
        0,
        None,
    )
}

// Drain the Host ICMP output; every message is submitted.
fn drain(side: &mut Side, now: u64) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    loop {
        let mut packet = vec![0; 8192];
        let mut frame = None;
        match side.0.icmp_output(now, &mut packet, |_, bytes| {
            frame = Some(bytes.to_vec());
            BackendOutcome::Submitted
        }) {
            Ok(None) => return sent,
            Ok(Some(BackendOutcome::Submitted)) => sent.push(frame.unwrap()),
            other => panic!("unexpected ICMP output {other:?}"),
        }
    }
}

fn icmp_message(packet: &[u8]) -> (IpMetadata, &[u8]) {
    if packet[0] >> 4 == 6 {
        let p = ntcp_ip6::parse(packet).unwrap();
        assert_eq!(p.protocol, 58);
        (p.ip, p.payload)
    } else {
        let p = ntcp_ip::parse(packet, false).unwrap();
        assert_eq!(p.protocol, 1);
        (p.ip, p.payload)
    }
}

#[test]
fn fragmented_udp_is_checked_and_queued_as_one_complete_datagram() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 61, &cfg, OUTPUT);
        let options = UdpOptions {
            dscp: 0,
            hop_limit: 64,
        };
        let flow = a.0.udp_open(&a.1, local, None, options).unwrap();
        let payload: Vec<u8> = (0..3000).map(|i| (i * 7) as u8).collect();
        let to_us = ip(remote.ip(), local.ip());
        let complete = udp(to_us, (remote.port(), local.port()), &payload);
        // Larger than the 1500-octet link: it arrives only as fragments.
        let pieces = fragments(&complete, 7, 1200);
        assert_eq!(pieces.len(), 3);
        let mut bytes = vec![0; 4000];
        // Reversed arrival: nothing reaches the flow before completion.
        for piece in pieces[1..].iter().rev() {
            assert_eq!(
                input_frame(&mut a, 1, piece),
                Ok(ntcp::InputDisposition::Processed)
            );
            assert_eq!(a.0.udp_receive(flow, &mut bytes).unwrap(), None);
        }
        assert_eq!(
            input_frame(&mut a, 2, &pieces[0]),
            Ok(ntcp::InputDisposition::Processed)
        );
        assert_eq!(
            a.0.udp_receive(flow, &mut bytes).unwrap(),
            Some((remote, payload.len()))
        );
        assert_eq!(&bytes[..payload.len()], &payload[..]);
        assert_eq!(a.0.reassembly_counters().completed, 1);

        // The UDP checksum is verified once over the complete datagram.
        let mut corrupt = complete.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let pieces = fragments(&corrupt, 8, 1200);
        for piece in &pieces[..2] {
            input_frame(&mut a, 3, piece).unwrap();
        }
        assert_eq!(
            input_frame(&mut a, 3, &pieces[2]),
            Ok(ntcp::InputDisposition::Dropped)
        );
        assert_eq!(a.0.udp_receive(flow, &mut bytes).unwrap(), None);

        // A full receive queue drops the completed datagram.
        for id in [9, 10] {
            for piece in fragments(&complete, id, 1200) {
                input_frame(&mut a, 4, &piece).unwrap();
            }
        }
        assert_eq!(a.0.reassembly_counters().completed, 4);
        assert!(a.0.udp_receive(flow, &mut bytes).unwrap().is_some());
        assert_eq!(a.0.udp_receive(flow, &mut bytes).unwrap(), None);
    }
}

#[test]
fn fragmented_tcp_segments_reach_the_endpoint_like_any_other() {
    for v6 in [false, true] {
        let cfg = config(4);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 63, &cfg, OUTPUT);
        let mut b = managed(remote, 64, cfg.clone());
        let listener = a.1.listen(local, 4).unwrap();
        let id =
            b.1.connect_with_path_provider(0, remote, local, options(&cfg, 0), &mut b.0)
                .unwrap();
        let mut now = 0;
        pump(&mut b, &mut a, &mut now);
        let child = a.1.accept(listener).unwrap();
        b.1.write(id, &[5; 1400]).unwrap();
        let segment = emit(&mut b.0, &mut b.1, now + 10).unwrap();
        // IPv6 fragment zero must hold the whole TCP header (RFC 7112); an
        // IPv4 first fragment of 8 data octets is legal.
        let chunk = if v6 { 512 } else { 8 };
        let mut pieces = fragments(&segment, 11, chunk);
        let first = pieces.remove(0);
        pieces.push(first);
        for piece in &pieces {
            input_frame(&mut a, now + 11, piece).unwrap();
        }
        let mut bytes = [0; 2000];
        assert_eq!(a.1.read(child, &mut bytes).unwrap(), 1400);
        assert_eq!(&bytes[..1400], &[5; 1400][..]);
        assert_eq!(a.0.reassembly_counters().completed, 1);
    }
}

#[test]
fn echo_requests_are_answered_exactly_whole_or_reassembled() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 65, &cfg, OUTPUT);
        let to_us = ip(remote.ip(), local.ip());
        let data: Vec<u8> = (0..900).map(|i| (i * 13) as u8).collect();
        let request = echo(to_us, 0x1234, 77, &data);
        assert_eq!(
            input_frame(&mut a, 1, &request),
            Ok(ntcp::InputDisposition::Processed)
        );
        // input_icmp answers an unfragmented request through the same service.
        assert_eq!(
            a.0.input_icmp(&mut a.1, a.2, 1, &request).unwrap(),
            IcmpDispatch::Completed(IcmpOutcome::Echo(EchoDisposition::Queued))
        );
        // A fragmented request is reassembled and answered.
        for piece in fragments(&request, 21, 304) {
            input_frame(&mut a, 2, &piece).unwrap();
        }
        let replies = drain(&mut a, 3);
        assert_eq!(replies.len(), 3);
        for reply in &replies {
            let (outer, message) = icmp_message(reply);
            assert_eq!(outer, ip(local.ip(), remote.ip()));
            let decoded = ntcp_icmp::decode_echo(outer, message).unwrap();
            assert_eq!(
                (
                    decoded.kind,
                    decoded.identifier,
                    decoded.sequence,
                    decoded.data
                ),
                (ntcp_icmp::EchoKind::Reply, 0x1234, 77, &data[..])
            );
            if !v6 {
                assert_eq!(reply[6] & 0x40, 0x40, "unfragmented IPv4 replies keep DF");
            }
        }
        let counters = a.0.icmp_output_counters();
        assert_eq!((counters.echo_replies, counters.unsent), (3, 0));

        // A full queue drops further requests; nothing is truncated.
        for sequence in 0..4 {
            input_frame(&mut a, 4, &echo(to_us, 1, sequence, &data)).unwrap();
        }
        assert_eq!(a.0.icmp_output_pending(), 3);
        assert_eq!(a.0.icmp_output_counters().dropped, 1);
        assert_eq!(drain(&mut a, 5).len(), 3);

        // Without source fragmentation configured (no fragments, no
        // identifiers), a reply larger than the path allows unfragmented
        // is not sent rather than truncated.
        let large: Vec<u8> = vec![3; 2000];
        for piece in fragments(&echo(to_us, 2, 2, &large), 22, 1200) {
            input_frame(&mut a, 6, &piece).unwrap();
        }
        let mut packet = vec![0; 8192];
        assert_eq!(
            a.0.icmp_output(7, &mut packet, |_, _| panic!("no backend call")),
            Err(Error::Unsupported)
        );
        assert_eq!(a.0.icmp_output_counters().unsent, 1);

        // A corrupt request and an Echo Reply addressed to us are not answered.
        let mut corrupt = echo(to_us, 3, 3, &data);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(input_frame(&mut a, 8, &corrupt).is_err());
        assert_eq!(a.0.icmp_output_pending(), 0);
    }
}

#[test]
fn echo_service_without_output_and_blocked_backends() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let to_us = ip(remote.ip(), local.ip());
        let request = echo(to_us, 4, 4, &[1; 64]);
        // Output disabled: requests are dropped, never queued.
        let mut off = side(local, 67, &cfg, IcmpOutputLimits::default());
        assert_eq!(
            input_frame(&mut off, 1, &request),
            Ok(ntcp::InputDisposition::Dropped)
        );
        assert_eq!(off.0.icmp_output_pending(), 0);
        // WouldBlock keeps the reply queued for the next drain.
        let mut a = side(local, 68, &cfg, OUTPUT);
        input_frame(&mut a, 1, &request).unwrap();
        let mut packet = vec![0; 8192];
        assert_eq!(
            a.0.icmp_output(2, &mut packet, |egress, _| {
                assert_eq!(egress.link, a.2.link());
                BackendOutcome::WouldBlock
            }),
            Ok(Some(BackendOutcome::WouldBlock))
        );
        assert_eq!(a.0.icmp_output_pending(), 1);
        assert_eq!(drain(&mut a, 3).len(), 1);
        // A removed source leaves nothing to answer from.
        input_frame(&mut a, 4, &request).unwrap();
        let source =
            a.0.paths()
                .local_source(ScopedAddress::new(local.ip(), None).unwrap(), a.2.link())
                .unwrap();
        a.0.remove_source_owner(source, a.2.link()).unwrap();
        assert!(
            a.0.icmp_output(5, &mut packet, |_, _| unreachable!())
                .is_err()
        );
        assert_eq!(a.0.icmp_output_counters().unsent, 1);
    }
}

#[test]
fn reassembly_errors_reach_the_icmp_output_through_the_limiter() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 69, &cfg, OUTPUT);
        let to_us = ip(remote.ip(), local.ip());
        let complete = udp(to_us, (remote.port(), local.port()), &[9; 2000]);
        let pieces = fragments(&complete, 31, 1000);
        // Fragment zero only: its datagram expires without further traffic
        // and draws a Time Exceeded (code 1) quoting fragment zero.
        input_frame(&mut a, 0, &pieces[0]).unwrap();
        // A later fragment alone expires silently.
        input_frame(&mut a, 0, &fragments(&complete, 32, 1000)[1]).unwrap();
        let second = cfg.connection.timebase.units_per_second;
        a.0.service_changes(&mut a.1, 60 * second - 1).unwrap();
        assert_eq!(a.0.icmp_output_pending(), 0);
        assert_eq!(a.0.next_reassembly_deadline(), Some(60 * second));
        a.0.service_changes(&mut a.1, 60 * second).unwrap();
        assert_eq!(a.0.reassembly_counters().expired, 2);
        let sent = drain(&mut a, 60 * second);
        assert_eq!(sent.len(), 1);
        let (outer, message) = icmp_message(&sent[0]);
        assert_eq!(outer, ip(local.ip(), remote.ip()));
        assert_eq!(&message[..2], if v6 { [3, 1] } else { [11, 1] });
        assert_eq!(&message[8..8 + 40], &pieces[0][..40]);

        // IPv6 only: a misaligned non-final fragment draws Parameter Problem
        // code 0 pointing at Payload Length; a link-layer multicast arrival
        // draws nothing (RFC 4443 section 2.4(e)).
        let mut misaligned = pieces[0].clone();
        misaligned.pop();
        let len = misaligned.len();
        if v6 {
            misaligned[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        } else {
            misaligned[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            misaligned[10..12].fill(0);
            let sum = ntcp_ip_common::checksum(&misaligned[..20]);
            misaligned[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        let mut out = vec![0; 8192];
        assert!(matches!(
            a.0.receive(a.2, 1, &misaligned, true, &mut out),
            Ok(Received::Discarded)
        ));
        assert_eq!(a.0.icmp_output_pending(), 0);
        assert!(matches!(
            a.0.receive(a.2, 1, &misaligned, false, &mut out),
            Ok(Received::Discarded)
        ));
        if v6 {
            let sent = drain(&mut a, 61 * second);
            assert_eq!(sent.len(), 1);
            let (_, message) = icmp_message(&sent[0]);
            assert_eq!((message[0], message[1]), (4, 0));
            assert_eq!(&message[4..8], &4u32.to_be_bytes());
        } else {
            assert_eq!(a.0.icmp_output_pending(), 0);
        }
    }
}

// One IPv6 fragment as a peer may send it, without the source fragmenter's
// validation: base -> Fragment -> `data`.
fn raw_fragment6(
    ip: IpMetadata,
    next_header: u8,
    identification: u32,
    offset: u16,
    more: bool,
    data: &[u8],
) -> Vec<u8> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (ip.source, ip.destination) else {
        panic!("IPv6 addresses");
    };
    let mut b = vec![0; 48 + data.len()];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    b[6] = 44;
    b[7] = 64;
    b[8..24].copy_from_slice(&source.octets());
    b[24..40].copy_from_slice(&destination.octets());
    b[40] = next_header;
    b[42..44].copy_from_slice(&(offset | u16::from(more)).to_be_bytes());
    b[44..48].copy_from_slice(&identification.to_be_bytes());
    b[48..].copy_from_slice(data);
    b
}

// RFC 5722 section 4 and RFC 8200 section 4.5: once an IPv6 datagram is
// abandoned for overlap, its later fragments are discarded silently, even
// those that would otherwise draw a Parameter Problem; without a marker,
// and once the marker has expired (silently), they draw their errors.
#[test]
fn abandoned_ipv6_datagrams_draw_no_parameter_problems() {
    let cfg = config(2);
    let (local, remote) = addresses(true);
    let mut a = side(local, 73, &cfg, OUTPUT);
    let to_us = ip(remote.ip(), local.ip());
    let second = cfg.connection.timebase.units_per_second;
    let complete = udp(to_us, (remote.port(), local.port()), &[9; 2000]);
    let checked = |id| {
        [
            // Non-final and not a multiple of 8: code 0 at Payload Length.
            (raw_fragment6(to_us, 17, id, 1000, true, &[1; 999]), 0, 4),
            // Ends beyond 65535: code 0 at the Fragment Offset.
            (raw_fragment6(to_us, 17, id, 65528, false, &[1; 16]), 0, 42),
            // Fragment zero without the whole TCP header: code 3, pointer 0.
            (raw_fragment6(to_us, 6, id, 0, true, &[1; 8]), 3, 0),
        ]
    };
    let mut out = vec![0; 8192];
    let mut receive = |a: &mut Side, now, frame: &[u8]| match a
        .0
        .receive(a.2, now, frame, false, &mut out)
        .unwrap()
    {
        Received::Held => "held",
        Received::Discarded => "discarded",
        Received::Datagram(_) => "datagram",
    };
    let problems = |a: &mut Side, now| -> Vec<(u8, u8, u32)> {
        drain(a, now)
            .iter()
            .map(|packet| {
                let (outer, message) = icmp_message(packet);
                assert_eq!(outer, ip(local.ip(), remote.ip()));
                assert_eq!(message[0], 4);
                let pointer = u32::from_be_bytes(message[4..8].try_into().unwrap());
                (message[0], message[1], pointer)
            })
            .collect()
    };
    // Without a marker each fragment draws its Parameter Problem.
    for (frame, _, _) in checked(34) {
        assert_eq!(receive(&mut a, 0, &frame), "discarded");
    }
    assert_eq!(problems(&mut a, 0), [(4, 0, 4), (4, 0, 42), (4, 3, 0)]);
    // Overlap: the datagram is abandoned silently, leaving its marker.
    assert_eq!(
        receive(&mut a, 1, &fragments(&complete, 33, 1000)[0]),
        "held"
    );
    assert_eq!(
        receive(&mut a, 1, &fragments(&complete, 33, 504)[1]),
        "discarded"
    );
    assert_eq!(a.0.reassembly_counters().discarded.overlap, 1);
    // Its later fragments are discarded silently as rejected.
    for (frame, _, _) in checked(33) {
        assert_eq!(receive(&mut a, 2, &frame), "discarded");
    }
    assert_eq!(a.0.icmp_output_pending(), 0);
    let discarded = a.0.reassembly_counters().discarded;
    assert_eq!(
        (
            discarded.rejected,
            discarded.misaligned,
            discarded.oversize,
            discarded.incomplete_header
        ),
        (3, 1, 1, 1)
    );
    // The marker expires at its original deadline without any message.
    a.0.service_changes(&mut a.1, 1 + 60 * second).unwrap();
    assert_eq!(a.0.reassembly_counters().expired, 1);
    assert_eq!(a.0.icmp_output_pending(), 0);
    // Afterwards the identity starts a new assembly; its checks apply again.
    for (frame, _, _) in checked(33) {
        assert_eq!(receive(&mut a, 2 + 60 * second, &frame), "discarded");
    }
    assert_eq!(
        problems(&mut a, 2 + 60 * second),
        [(4, 0, 4), (4, 0, 42), (4, 3, 0)]
    );
    assert_eq!(
        receive(&mut a, 2 + 60 * second, &fragments(&complete, 33, 1000)[0]),
        "held"
    );
    assert_eq!(a.0.reassembly_counters().discarded.rejected, 3);

    // IPv4 keeps overlap support and defines none of these errors: the same
    // overlap is held, a misaligned fragment is discarded silently, and the
    // datagram still completes.
    let (local, remote) = addresses(false);
    let mut b = side(local, 74, &cfg, OUTPUT);
    let to_us = ip(remote.ip(), local.ip());
    let complete = udp(to_us, (remote.port(), local.port()), &[9; 2000]);
    let wide = fragments(&complete, 33, 1000);
    assert_eq!(receive(&mut b, 1, &wide[0]), "held");
    assert_eq!(
        receive(&mut b, 1, &fragments(&complete, 33, 504)[1]),
        "held"
    );
    let mut misaligned = wide[1].clone();
    misaligned.pop();
    let len = misaligned.len();
    misaligned[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    misaligned[10..12].fill(0);
    let sum = ntcp_ip_common::checksum(&misaligned[..20]);
    misaligned[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(receive(&mut b, 2, &misaligned), "discarded");
    assert_eq!(b.0.icmp_output_pending(), 0);
    for piece in &wide[1..] {
        receive(&mut b, 3, piece);
    }
    let counters = b.0.reassembly_counters();
    assert_eq!(
        (
            counters.completed,
            counters.discarded.misaligned,
            counters.discarded.rejected
        ),
        (1, 1, 0)
    );
}

#[test]
fn completed_datagrams_own_their_bytes_for_retention() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 71, &cfg, OUTPUT);
        let options = UdpOptions {
            dscp: 0,
            hop_limit: 64,
        };
        let flow = a.0.udp_open(&a.1, local, None, options).unwrap();
        let to_us = ip(remote.ip(), local.ip());
        let complete = udp(to_us, (remote.port(), local.port()), &[6; 2500]);
        let mut out = vec![0; 4200];
        let mut retained = None;
        for piece in fragments(&complete, 41, 1200) {
            match a.0.receive(a.2, 1, &piece, false, &mut out).unwrap() {
                Received::Held => {}
                Received::Datagram(datagram) => {
                    // Reconstructed by the engine, not a physical arrival.
                    assert_eq!(a.0.reassembly_counters().completed, 1);
                    // Fragment zero's header, its Identification kept (and
                    // so the IPv4 header checksum differs).
                    let bytes = datagram.bytes();
                    let fixed = if v6 { 40 } else { 4 };
                    assert_eq!(bytes.len(), complete.len());
                    assert!(bytes[..fixed] == complete[..fixed]);
                    assert!(
                        bytes[if v6 { 40 } else { 12 }..] == complete[if v6 { 40 } else { 12 }..]
                    );
                    retained = Some((datagram.envelope(), datagram.bytes().to_vec()));
                }
                Received::Discarded => panic!("discarded"),
            }
        }
        // Retained beyond the engine's next use, then dispatched.
        let (envelope, bytes) = retained.unwrap();
        for piece in fragments(&complete, 42, 1200).iter().take(1) {
            input_frame(&mut a, 2, piece).unwrap();
        }
        assert!(envelope.datagram(&bytes[1..]).is_none());
        let datagram = envelope.datagram(&bytes).unwrap();
        assert_eq!(
            a.0.decode_datagram(datagram).unwrap().protocol,
            ntcp_ip::PROTOCOL_UDP
        );
        assert_eq!(
            a.0.input_datagram(&mut a.1, 3, datagram, RxPacketMetadata::default(), 0, None),
            Ok(ntcp::InputDisposition::Processed)
        );
        let mut payload = vec![0; 4000];
        assert_eq!(
            a.0.udp_receive(flow, &mut payload).unwrap(),
            Some((remote, 2500))
        );
        // The physical limit still bounds every arriving packet.
        assert!(a.0.decode_ingress(a.2, &complete).is_ok());
        // An IPv6 atomic fragment is processed as a complete packet.
        if v6 {
            let mut atomic = vec![0; complete.len() + 8];
            atomic[..40].copy_from_slice(&complete[..40]);
            atomic[4..6].copy_from_slice(&((complete.len() - 32) as u16).to_be_bytes());
            atomic[6] = 44;
            atomic[40] = 17;
            atomic[44..48].copy_from_slice(&5u32.to_be_bytes());
            atomic[48..].copy_from_slice(&complete[40..]);
            let before = a.0.reassembly_counters();
            let Received::Datagram(datagram) =
                a.0.receive(a.2, 4, &atomic, false, &mut out).unwrap()
            else {
                panic!("atomic fragment held");
            };
            // RFC 6946: it bypasses assembly state entirely.
            assert_eq!(a.0.reassembly_counters(), before);
            assert!(datagram.bytes() == &complete[..]);
        }
    }
}

#[test]
fn retired_addresses_discard_their_assemblies_at_the_next_service_pass() {
    for v6 in [false, true] {
        let cfg = config(2);
        let (local, remote) = addresses(v6);
        let mut a = side(local, 73, &cfg, OUTPUT);
        let to_us = ip(remote.ip(), local.ip());
        let complete = udp(to_us, (remote.port(), local.port()), &[1; 2000]);
        input_frame(&mut a, 0, &fragments(&complete, 51, 1000)[0]).unwrap();
        a.0.service_changes(&mut a.1, 1).unwrap();
        assert_eq!(a.0.reassembly_counters().retired, 0);
        let source =
            a.0.paths()
                .local_source(ScopedAddress::new(local.ip(), None).unwrap(), a.2.link())
                .unwrap();
        a.0.remove_source_owner(source, a.2.link()).unwrap();
        a.0.service_changes(&mut a.1, 2).unwrap();
        assert_eq!(a.0.reassembly_counters().retired, 1);
        assert_eq!(a.0.next_reassembly_deadline(), None);
        assert_eq!(a.0.icmp_output_pending(), 0);
    }
}

// Every physical packet of one ICMP output transaction.
fn drain_packets(side: &mut Side, now: u64) -> Result<Option<Vec<Vec<u8>>>, Error> {
    let mut packet = vec![0; 8192];
    let mut frames = Vec::new();
    match side.0.icmp_output(now, &mut packet, |_, bytes| {
        frames.push(bytes.to_vec());
        BackendOutcome::Submitted
    })? {
        None => Ok(None),
        Some(BackendOutcome::Submitted) => Ok(Some(frames)),
        other => panic!("unexpected ICMP output {other:?}"),
    }
}

// Reassemble one originated datagram from its physical packets: the outer
// addresses, its upper-layer bytes and each packet's (length, DF, id).
fn reconstruct(frames: &[Vec<u8>]) -> (IpMetadata, Vec<u8>, Vec<(usize, bool, Option<u32>)>) {
    let mut data = Vec::new();
    let mut shape = Vec::new();
    let mut outer = None;
    for (i, frame) in frames.iter().enumerate() {
        let (ip, offset, more, id, payload, df) = if frame[0] >> 4 == 6 {
            let p = ntcp_ip6::parse_fragment(frame).unwrap();
            let (offset, more, id) = p
                .fragment
                .map_or((0, false, None), |f| {
                    (usize::from(f.offset), f.more_fragments, Some(f.identification))
                });
            (p.ip, offset, more, id, p.payload, false)
        } else {
            let p = ntcp_ip::parse_fragment(frame, false).unwrap();
            let f = p.fragmentation;
            let fragmented = f.more_fragments || f.offset != 0;
            (
                p.ip,
                usize::from(f.offset),
                f.more_fragments,
                fragmented.then_some(u32::from(f.identification)),
                p.payload,
                f.dont_fragment,
            )
        };
        assert_eq!(offset, data.len(), "in-order, contiguous fragments");
        assert_eq!(more, i + 1 != frames.len());
        outer = Some(ip);
        data.extend_from_slice(payload);
        shape.push((frame.len(), df, id));
    }
    (outer.unwrap(), data, shape)
}

fn fragmenting_side(local: SocketAddr, identity: u128, capacity: bool) -> Side {
    let cfg = config(2);
    let mut side = managed_limited(local, identity, cfg, false, None, None, |p, mut l| {
        l.datagrams = DatagramLimits {
            max_fragments: 8,
            identifiers: IdentifierLimits {
                lifetime_seconds: 120,
                ipv4_tuples: 2,
                ipv6_leases: 8,
            },
            connectionless: ConnectionlessSizing::default(),
            // Deployment knowledge of the peer's reassembly capacity.
            peer_reassembly_ipv4: capacity.then_some(4096),
            peer_reassembly_ipv6: capacity.then_some(4136),
            adjunct: AdjunctLimits::default(),
        };
        let (p, l) = managed_udp_limits(p, l, UDP).unwrap();
        let (p, mut l) = managed_icmp_output_limits(p, l, OUTPUT).unwrap();
        l.reassembly = reassembly();
        (p, l, 1)
    });
    let mut counter = 0x11u8;
    side.0.set_entropy(std::boxed::Box::new(move |out: &mut [u8]| {
        for b in out.iter_mut() {
            *b = counter;
            counter = counter.wrapping_add(1);
        }
        Ok(())
    }));
    // The previous context stopped at 0: identifiers start one MDL later.
    side.0.start_identifiers(Continuity::QuietSince(0)).unwrap();
    side
}

#[test]
fn fragmented_echo_requests_get_fragmented_replies_within_the_peer_capacity() {
    const MDL: u64 = 120_000_000;
    for v6 in [false, true] {
        let (local, remote) = addresses(v6);
        let to_us = ip(remote.ip(), local.ip());
        let from_us = ip(local.ip(), remote.ip());
        let data: Vec<u8> = (0..2000).map(|i| (i * 11) as u8).collect();
        let request = echo(to_us, 0x4242, 9, &data);
        let header = if v6 { 40 } else { 20 };

        // With the peer's capacity and an identifier: the reassembled
        // request is answered with fragments of the connectionless
        // effective size (1024 IPv4, 1280 IPv6), each IPv4 one with DF.
        let mut a = fragmenting_side(local, 75, true);
        for piece in fragments(&request, 23, 1200) {
            input_frame(&mut a, MDL + 1, &piece).unwrap();
        }
        let frames = drain_packets(&mut a, MDL + 2).unwrap().unwrap();
        let (outer, message, shape) = reconstruct(&frames);
        assert_eq!(outer, from_us);
        let reply = ntcp_icmp::decode_echo(outer, &message).unwrap();
        assert_eq!(
            (reply.kind, reply.identifier, reply.sequence, reply.data),
            (ntcp_icmp::EchoKind::Reply, 0x4242, 9, &data[..])
        );
        assert_eq!(shape.len(), if v6 { 2 } else { 3 });
        let id = shape[0].2.unwrap();
        for (i, &(len, df, fragment_id)) in shape.iter().enumerate() {
            assert_eq!(fragment_id, Some(id));
            assert!(len <= if v6 { 1280 } else { 1024 });
            if i + 1 != shape.len() {
                assert_eq!(len, if v6 { 1280 } else { 1020 });
            }
            if !v6 {
                assert!(df, "DF on every IPv4 fragment");
            }
        }
        assert_eq!(message.len() + header, request.len());

        // Without an identifier (still within the quiet period) a reply
        // the path carries whole goes out whole; a larger one is unsent.
        let mut quiet = fragmenting_side(local, 76, true);
        let medium: Vec<u8> = vec![4; 1300];
        for piece in fragments(&echo(to_us, 1, 1, &medium), 24, 1200) {
            input_frame(&mut quiet, 1, &piece).unwrap();
        }
        let frames = drain_packets(&mut quiet, 2).unwrap().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), header + 8 + medium.len());
        if !v6 {
            assert_eq!(frames[0][6] & 0x40, 0x40);
        }
        for piece in fragments(&request, 25, 1200) {
            input_frame(&mut quiet, 3, &piece).unwrap();
        }
        assert_eq!(
            drain_packets(&mut quiet, 4),
            Err(Error::Unsupported)
        );
        assert_eq!(quiet.0.icmp_output_counters().unsent, 1);

        // Without the stated capacity only the receiver guarantee holds
        // (576 IPv4, 1500 IPv6): the 2028/2048-octet reply exceeds it and
        // the path budget, so it is counted unsent; a reply within the
        // budget but beyond what may be fragmented goes out whole.
        let mut plain = fragmenting_side(local, 77, false);
        for piece in fragments(&request, 26, 1200) {
            input_frame(&mut plain, MDL + 1, &piece).unwrap();
        }
        assert_eq!(drain_packets(&mut plain, MDL + 2), Err(Error::Unsupported));
        assert_eq!(plain.0.icmp_output_counters().unsent, 1);
        for piece in fragments(&echo(to_us, 2, 2, &medium), 27, 1200) {
            input_frame(&mut plain, MDL + 3, &piece).unwrap();
        }
        let frames = drain_packets(&mut plain, MDL + 4).unwrap().unwrap();
        let (_, message, shape) = reconstruct(&frames);
        assert_eq!(&message[8..], &medium[..]);
        if v6 {
            // 1348 octets are within IPv6's 1500 guarantee: fragmented to
            // the 1280 effective size.
            assert_eq!(shape.len(), 2);
        } else {
            assert_eq!(shape, [(header + 8 + medium.len(), true, None)]);
        }
    }
}

// RFC 8201 section 5.6: Echo Replies leave through the same capped emitter.
// After the owner disables discovery on the IPv6 default route, a queued
// 1448-octet reply is cut into fragments of at most 1280 octets (within the
// 1500-octet peer guarantee) and reassembles to the exact reply message.
#[test]
fn echo_replies_on_a_discovery_disabled_ipv6_route_are_at_most_1280() {
    // Identifiers are available one maximum datagram lifetime after start.
    const MDL: u64 = 120_000_000;
    let (local, remote) = addresses(true);
    let mut a = fragmenting_side(local, 9990, false);
    let capability = a.0.administration();
    let prefix = path::IpPrefix::new("::".parse().unwrap(), 0).unwrap();
    let route = a.0.admin_select_route(&capability, prefix).unwrap();
    let candidate = a
        .0
        .admin_validate(
            &capability,
            MDL,
            path::AdminChange {
                target: path::AdminTarget::Route(route),
                expected: 0,
                policy: path::AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    let to_us = ip(remote.ip(), local.ip());
    let data: Vec<u8> = (0..1400).map(|i| (i * 7) as u8).collect();
    let request = echo(to_us, 0x4321, 9, &data);
    assert_eq!(request.len(), 1448);
    input_frame(&mut a, MDL + 1, &request).unwrap();
    let frames = drain_packets(&mut a, MDL + 2).unwrap().unwrap();
    assert!(frames.len() > 1);
    assert!(frames.iter().all(|f| f.len() <= 1280));
    let (outer, message, _) = reconstruct(&frames);
    assert_eq!(outer, ip(local.ip(), remote.ip()));
    let decoded = ntcp_icmp::decode_echo(outer, &message).unwrap();
    assert_eq!(decoded.kind, ntcp_icmp::EchoKind::Reply);
    assert_eq!(decoded.data, &data[..]);
}

// Parent decision D17 / SEMANTICS 7: a queued Echo Reply (final bytes: the
// request is gone) never blocks an administrative change. Without stated
// peer capacity the reply is beyond what may be fragmented (576 IPv4, 1500
// IPv6) and leaves whole within the path budget (a control reply shows
// it). A downward route set below it (and on IPv6 a discovery disable,
// capping the budget at 1280) applies at once while it is queued and
// updates the path's TCP connection and UDP flow in the same call; the
// emitter then discards the reply and counts it unsent, exactly as after a
// trusted PTB decrease, and the connection keeps working.
#[test]
fn queued_oversized_echo_reply_never_blocks_a_restriction_and_is_counted_unsent() {
    const MDL: u64 = 120_000_000;
    for v6 in [false, true] {
        for disable in [false, true] {
            if disable && !v6 {
                // An IPv4 disable changes no packet budget in this stage.
                continue;
            }
            let (local, remote) = addresses(v6);
            let identity = 9994 + 4 * u128::from(v6) + 2 * u128::from(disable);
            let mut a = fragmenting_side(local, identity, false);
            let cfg = config(2);
            let mut b = managed(remote, identity + 1, cfg.clone());
            if v6 {
                // A reply larger than the IPv6 guarantee needs a larger link.
                a.0.set_link_mtu(a.2.link(), 4000).unwrap();
            }
            let listener = b.1.listen(remote, 2).unwrap();
            let tcp = a
                .1
                .connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
            let mut now = 0;
            pump(&mut a, &mut b, &mut now);
            b.1.accept(listener).unwrap();
            let flow = a
                .0
                .udp_open(&a.1, SocketAddr::new(local.ip(), 5000), Some(SocketAddr::new(remote.ip(), 7)), UdpOptions { dscp: 0, hop_limit: 64 })
                .unwrap();
            a.0.udp_path_limits(&a.1, flow, None).unwrap();
            let path = a.0.binding(tcp).unwrap().snapshot.path();
            let route = a.0.binding(tcp).unwrap().snapshot.key().route();
            let to_us = ip(remote.ip(), local.ip());
            let data: Vec<u8> = (0..if v6 { 2000 } else { 1000 }).map(|i| (i * 13) as u8).collect();
            let header = if v6 { 40 } else { 20 };
            let reply_len = header + 8 + data.len();
            // Control: the reply leaves whole under the current budget.
            // Whole within the 1500-octet receiving link, else fragmented.
            let request = echo(to_us, 7, 1, &data);
            let pieces = if request.len() <= 1500 { vec![request] } else { fragments(&request, 41, 1200) };
            for piece in pieces {
                input_frame(&mut a, MDL + 1, &piece).unwrap();
            }
            let frames = drain_packets(&mut a, MDL + 2).unwrap().unwrap();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].len(), reply_len);
            // The same reply queued again; the owner restricts the route.
            // Whole within the 1500-octet receiving link, else fragmented.
            let request = echo(to_us, 7, 2, &data);
            let pieces = if request.len() <= 1500 { vec![request] } else { fragments(&request, 42, 1200) };
            for piece in pieces {
                input_frame(&mut a, MDL + 3, &piece).unwrap();
            }
            let capability = a.0.administration();
            assert!(
                a.0.admin_clients(&capability, &a.1, path)
                    .unwrap()
                    .any(|c| c.client == crate::AdminClient::Echo { queued: 1 })
            );
            let (policy, budget) = if disable {
                (path::AdminPolicy { discovery_disabled: true, estimate: None }, 1280)
            } else {
                let value = if v6 { 1500 } else { 900 };
                (path::AdminPolicy { discovery_disabled: false, estimate: Some(value) }, value)
            };
            assert!(reply_len > budget as usize);
            let candidate = a
                .0
                .admin_validate(
                    &capability,
                    MDL + 4,
                    path::AdminChange { target: path::AdminTarget::Route(route), expected: 0, policy },
                )
                .unwrap();
            assert_eq!(a.0.admin_apply(&capability, &mut a.1, candidate), Ok(1));
            let snapshot = a.0.paths().path_snapshot(path).unwrap();
            assert_eq!(snapshot.ip_packet_budget().unwrap(), budget);
            assert_eq!(a.0.binding(tcp).unwrap().snapshot, snapshot);
            assert!(!a.0.paths().is_dirty(a.0.binding(tcp).unwrap().client).unwrap());
            assert!(a.1.managed_path(tcp).unwrap().ordinary_ip_budget <= budget);
            let overhead = if v6 { 48 } else { 28 };
            assert_eq!(a.0.udp_path_change(flow).unwrap().unwrap().max_payload as u32, budget - overhead);
            // Sized at emission: discarded and counted unsent.
            let unsent = a.0.icmp_output_counters().unsent;
            assert_eq!(drain_packets(&mut a, MDL + 5), Err(Error::Unsupported));
            assert_eq!(a.0.icmp_output_counters().unsent, unsent + 1);
            assert_eq!(a.0.icmp_output_pending(), 0);
            now = MDL + 10;
            a.1.write(tcp, &[6; 4000]).unwrap();
            pump(&mut a, &mut b, &mut now);
            let progress = a.1.send_progress(tcp).unwrap();
            assert_eq!(progress.acknowledged, progress.queued_end);
        }
    }
}

// RFC 1191 section 6.6 (the user's recorded decision B): after the owner
// disables discovery on the IPv4 default route (a forwarder next hop), the
// 1448-octet Echo Reply to a peer with stated reassembly capacity is cut to
// the RFC 1122 section 3.3.3 limit of 576 octets, every fragment DF-clear
// with MF, offsets and the one Identification of the reply intact and a
// valid header checksum; the fragments reassemble to the exact reply.
#[test]
fn echo_replies_on_a_discovery_disabled_ipv4_route_are_df_clear_fragments_within_576() {
    const MDL: u64 = 120_000_000;
    let (local, remote) = addresses(false);
    let mut a = fragmenting_side(local, 9992, true);
    let capability = a.0.administration();
    let prefix = path::IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap();
    let route = a.0.admin_select_route(&capability, prefix).unwrap();
    let candidate = a
        .0
        .admin_validate(
            &capability,
            MDL,
            path::AdminChange {
                target: path::AdminTarget::Route(route),
                expected: 0,
                policy: path::AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    let to_us = ip(remote.ip(), local.ip());
    let data: Vec<u8> = (0..1420).map(|i| (i * 7) as u8).collect();
    let request = echo(to_us, 0x4321, 9, &data);
    input_frame(&mut a, MDL + 1, &request).unwrap();
    let frames = drain_packets(&mut a, MDL + 2).unwrap().unwrap();
    assert!(frames.len() >= 3);
    let identification = u16::from_be_bytes([frames[0][4], frames[0][5]]);
    let mut offset = 0;
    for (index, frame) in frames.iter().enumerate() {
        assert!(frame.len() <= 576);
        assert_eq!(frame[6] & 0x40, 0, "DF clear on every fragment");
        assert_eq!(ntcp_ip_common::checksum(&frame[..20]), 0);
        assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), identification);
        let flags = u16::from_be_bytes([frame[6], frame[7]]);
        assert_eq!(flags & 0x2000 != 0, index + 1 != frames.len(), "MF");
        assert_eq!(usize::from(flags & 0x1fff) * 8, offset);
        offset += frame.len() - 20;
    }
    let (outer, message, _) = reconstruct(&frames);
    assert_eq!(outer, ip(local.ip(), remote.ip()));
    let decoded = ntcp_icmp::decode_echo(outer, &message).unwrap();
    assert_eq!(decoded.kind, ntcp_icmp::EchoKind::Reply);
    assert_eq!(decoded.data, &data[..]);
}

// On a discovery-disabled IPv4 route every Echo Reply leaves DF clear and
// needs a leased Identification, whole or fragmented. Inside the
// allocator's start quiet period the reply is held at the head of the
// queue (WouldBlock, nothing submitted, nothing counted unsent) and is sent
// once an identifier can be issued: held output, never a reused value.
#[test]
fn df_clear_echo_replies_are_held_while_no_identifier_can_be_issued() {
    const MDL: u64 = 120_000_000;
    let (local, remote) = addresses(false);
    for size in [100usize, 1420] {
        let mut a = fragmenting_side(local, 9993 + size as u128, true);
        let capability = a.0.administration();
        let prefix = path::IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap();
        let route = a.0.admin_select_route(&capability, prefix).unwrap();
        let candidate = a
            .0
            .admin_validate(
                &capability,
                1,
                path::AdminChange {
                    target: path::AdminTarget::Route(route),
                    expected: 0,
                    policy: path::AdminPolicy {
                        discovery_disabled: true,
                        estimate: None,
                    },
                },
            )
            .unwrap();
        a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
        let data: Vec<u8> = (0..size).map(|i| (i * 3) as u8).collect();
        let request = echo(ip(remote.ip(), local.ip()), 0x5150, 3, &data);
        input_frame(&mut a, 2, &request).unwrap();
        let mut packet = vec![0; 8192];
        for now in [3, MDL - 1] {
            let mut submitted = 0;
            let outcome = a
                .0
                .icmp_output(now, &mut packet, |_, _| {
                    submitted += 1;
                    BackendOutcome::Submitted
                })
                .unwrap();
            assert_eq!(outcome, Some(BackendOutcome::WouldBlock), "held");
            assert_eq!(submitted, 0);
            assert_eq!(a.0.icmp_output_counters().unsent, 0);
        }
        let frames = drain_packets(&mut a, MDL + 1).unwrap().unwrap();
        assert_eq!(frames.len() > 1, size > 576);
        let identification = u16::from_be_bytes([frames[0][4], frames[0][5]]);
        assert_ne!(identification, 0);
        for frame in &frames {
            assert!(frame.len() <= 576);
            assert_eq!(frame[6] & 0x40, 0, "DF clear");
            assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), identification);
            assert_eq!(ntcp_ip_common::checksum(&frame[..20]), 0);
        }
        let (_, message, _) = reconstruct(&frames);
        let decoded = ntcp_icmp::decode_echo(ip(local.ip(), remote.ip()), &message).unwrap();
        assert_eq!(decoded.data, &data[..]);
        assert_eq!(drain_packets(&mut a, MDL + 2), Ok(None));
    }
}

// Identifier backpressure holds only the message that needs an identifier.
// With one destination's path discovery-disabled (DF clear) and the
// allocator's start quiet period active, its Echo Reply waits while the
// reply to a destination on the enabled path, queued behind it, leaves at
// once with DF; the held reply goes out DF-clear with a leased
// Identification once one can be issued.
#[test]
fn an_identifier_blocked_reply_does_not_hold_other_destinations_output() {
    const MDL: u64 = 120_000_000;
    let (local, remote) = addresses(false);
    let neighbor: IpAddr = "198.51.100.7".parse().unwrap();
    let mut a = fragmenting_side(local, 9995, true);
    // Create the path to `remote` (an enabled-path reply needs no identifier).
    let data = [0x5a; 64];
    input_frame(&mut a, 1, &echo(ip(remote.ip(), local.ip()), 0x6001, 1, &data)).unwrap();
    let frames = drain_packets(&mut a, 1).unwrap().unwrap();
    assert_eq!(frames.len(), 1);
    assert_ne!(frames[0][6] & 0x40, 0, "DF on the enabled path");
    let capability = a.0.administration();
    let target = a
        .0
        .admin_paths(&capability)
        .unwrap()
        .find(|p| p.snapshot.key().destination().address() == remote.ip())
        .unwrap();
    let candidate = a
        .0
        .admin_validate(
            &capability,
            2,
            path::AdminChange {
                target: path::AdminTarget::Path(target.snapshot.path()),
                expected: target.generation,
                policy: path::AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            },
        )
        .unwrap();
    a.0.admin_apply(&capability, &mut a.1, candidate).unwrap();
    // The disabled destination's request first, the neighbor's behind it.
    input_frame(&mut a, 3, &echo(ip(remote.ip(), local.ip()), 0x6001, 2, &data)).unwrap();
    input_frame(&mut a, 3, &echo(ip(neighbor, local.ip()), 0x6002, 1, &data)).unwrap();
    assert_eq!(a.0.icmp_output_pending(), 2);
    let frames = drain_packets(&mut a, 4).unwrap().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(&frames[0][16..20], &[198, 51, 100, 7], "the neighbor's reply");
    assert_ne!(frames[0][6] & 0x40, 0, "DF kept on the enabled path");
    assert_eq!(a.0.icmp_output_pending(), 1);
    let mut packet = vec![0; 8192];
    let mut submitted = 0;
    let outcome = a
        .0
        .icmp_output(5, &mut packet, |_, _| {
            submitted += 1;
            BackendOutcome::Submitted
        })
        .unwrap();
    assert_eq!(outcome, Some(BackendOutcome::WouldBlock), "only the held reply is left");
    assert_eq!(submitted, 0);
    assert_eq!(a.0.icmp_output_counters().unsent, 0);
    let frames = drain_packets(&mut a, MDL + 1).unwrap().unwrap();
    assert_eq!(frames.len(), 1);
    let IpAddr::V4(held) = remote.ip() else { unreachable!() };
    assert_eq!(frames[0][16..20], held.octets(), "the held reply");
    assert_eq!(frames[0][6] & 0x40, 0, "DF clear on the disabled path");
    assert_ne!(u16::from_be_bytes([frames[0][4], frames[0][5]]), 0);
    assert_eq!(ntcp_ip_common::checksum(&frames[0][..20]), 0);
    assert_eq!(drain_packets(&mut a, MDL + 2), Ok(None));
}
