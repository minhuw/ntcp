// Destination processing (`Host::process`): every complete IPv4 datagram,
// whole or reassembled, is processed once before TCP or ICMP dispatch, and
// both consume the processed options rather than parsing the header again.
use super::dispatch::{ptb, seal_ipv4, tcp_report};
use super::*;
use core::net::Ipv4Addr;
use ntcp::{Ipv4Timestamp, Ipv4TimestampProvider};

type Side = (Host, Endpoint, IngressContext);

// Record Route and Timestamp (flag 0) with two free slots each, an opaque
// copied option and an opaque non-copied option, padded with EOL.
const OPTIONS: [u8; 32] = [
    7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, // RR
    68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, // TS
    158, 4, 1, 2, // copied
    30, 2, // not copied
    0, 0, 0,
];
const SAMPLE: u32 = 0x8000_0007;

#[derive(Default)]
struct Clock {
    calls: usize,
}
impl Ipv4TimestampProvider for Clock {
    fn ipv4_timestamp(&mut self) -> Option<Ipv4Timestamp> {
        self.calls += 1;
        Some(Ipv4Timestamp::nonstandard(7))
    }
}

fn side(local: SocketAddr, identity: u128, cfg: &EndpointConfig) -> Side {
    managed_limited(local, identity, cfg.clone(), false, None, None, |p, l| {
        let output = IcmpOutputLimits {
            messages: 2,
            message_bytes: 4096,
            hop_limit: 64,
        };
        let (p, mut l) = managed_icmp_output_limits(p, l, output).unwrap();
        l.reassembly = ReassemblyLimits {
            assemblies: 4,
            fragments: 600,
            buffered_bytes: 8192,
            ipv4_datagram: 4096,
            ipv6_datagram: 4136,
            ipv4_timeout_seconds: 60,
        };
        (p, l, 1)
    })
}

fn profile(side: &mut Side, interpretation: bool, source_routes: bool) {
    side.0.ports[0].as_mut().unwrap().receive.ipv4 = Ipv4Receive::Enabled {
        interpretation,
        source_routes,
    };
}

fn v4(address: IpAddr) -> Ipv4Addr {
    let IpAddr::V4(address) = address else {
        panic!("IPv4 only")
    };
    address
}

// `frame`, an IPv4 packet, with `options` (a whole number of words) as its
// header options.
pub(super) fn with_options(frame: &[u8], options: &[u8]) -> Vec<u8> {
    let old = usize::from(frame[0] & 15) * 4;
    let header = 20 + options.len();
    let mut packet = vec![0; header + frame.len() - old];
    packet[..20].copy_from_slice(&frame[..20]);
    packet[0] = 0x40 | (header / 4) as u8;
    let total = packet.len() as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[20..header].copy_from_slice(options);
    packet[header..].copy_from_slice(&frame[old..]);
    seal_ipv4(&mut packet);
    packet
}

// RFC 791 source fragments of `packet`, `chunk` data octets each: fragment
// zero carries every option, later ones only the copied options.
fn fragments(packet: &[u8], identification: u16, chunk: usize) -> Vec<Vec<u8>> {
    let header = usize::from(packet[0] & 15) * 4;
    let mut copied = [0; 40];
    let copied_len = ntcp::copied_fragment_options(&packet[20..header], &mut copied).unwrap();
    let data = &packet[header..];
    (0..data.len())
        .step_by(chunk)
        .map(|offset| {
            let piece = &data[offset..data.len().min(offset + chunk)];
            let options = if offset == 0 {
                &packet[20..header]
            } else {
                &copied[..copied_len]
            };
            let h = 20 + options.len();
            let mut fragment = vec![0; h + piece.len()];
            fragment[..20].copy_from_slice(&packet[..20]);
            fragment[0] = 0x40 | (h / 4) as u8;
            let total = fragment.len() as u16;
            fragment[2..4].copy_from_slice(&total.to_be_bytes());
            fragment[4..6].copy_from_slice(&identification.to_be_bytes());
            let more = u16::from(offset + piece.len() < data.len()) << 13;
            fragment[6..8].copy_from_slice(&(more | (offset / 8) as u16).to_be_bytes());
            fragment[20..h].copy_from_slice(options);
            fragment[h..].copy_from_slice(piece);
            seal_ipv4(&mut fragment);
            fragment
        })
        .collect()
}

// One physical packet through receive, destination processing and
// dispatch: the processed envelope and bytes of a completed datagram.
fn deliver(
    side: &mut Side,
    now: u64,
    frame: &[u8],
    clock: &mut Clock,
) -> Option<(ProcessedEnvelope, Vec<u8>, ntcp::InputDisposition)> {
    let mut out = vec![0; 8192];
    let Received::Datagram(datagram) = side.0.receive(side.2, now, frame, false, &mut out).unwrap()
    else {
        return None;
    };
    let processed = side.0.process(datagram, Some(clock)).unwrap();
    let disposition = side
        .0
        .input_datagram(&mut side.1, now, processed, RxPacketMetadata::default(), 0)
        .unwrap();
    Some((
        processed.envelope(),
        processed.bytes().to_vec(),
        disposition,
    ))
}

fn processed_options(envelope: ProcessedEnvelope, bytes: &[u8]) -> Ipv4Options {
    envelope.datagram(bytes).unwrap().packet().options
}

// Arrival orders of the fragments of one datagram.
fn arrange(order: usize, mut pieces: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    match order {
        // In order.
        0 => pieces,
        // Reversed.
        1 => pieces.into_iter().rev().collect(),
        // A duplicate of a later fragment before completion.
        2 => {
            let duplicate = pieces[1].clone();
            pieces.insert(1, duplicate);
            pieces
        }
        // Fragment zero last.
        _ => {
            let first = pieces.remove(0);
            pieces.push(first);
            pieces
        }
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
//# passed to the transport layer (or to ICMP processing when the datagram is
//# an ICMP message). The IP and transport layer MUST each interpret those IP
//# options that they understand and silently ignore the others.
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# The destination host MUST (if possible) add the current timestamp to
//# a Timestamp option before passing the option to the transport layer
//# or to ICMP for processing.
fn tcp_receives_every_option_recorded_once_for_whole_and_reassembled_datagrams() {
    for interpretation in [true, false] {
        let cfg = config(2);
        let (local, remote) = addresses(false);
        let mut a = side(local, 1401, &cfg);
        profile(&mut a, interpretation, false);
        let mut b = managed(remote, 1402, cfg.clone());
        let listener = a.1.listen(local, 2).unwrap();
        let id =
            b.1.connect_with_path_provider(0, remote, local, options(&cfg, 0), &mut b.0)
                .unwrap();
        let mut now = 0;
        pump(&mut b, &mut a, &mut now);
        let child = a.1.accept(listener).unwrap();
        let received = Ipv4Options::parse(&OPTIONS, false).unwrap();
        let expected = if interpretation {
            received.record(v4(local.ip()), SAMPLE).unwrap()
        } else {
            // Interpretation disabled: every option still delivered, unrecorded.
            received
        };
        // Whole, then fragments in order, reversed, duplicated, zero last.
        for case in 0..5 {
            now += 100;
            b.1.write(id, &[case as u8; 1000]).unwrap();
            let segment = emit(&mut b.0, &mut b.1, now).unwrap();
            let frame = with_options(&segment, &OPTIONS);
            let pieces = if case == 0 {
                vec![frame.clone()]
            } else {
                arrange(case - 1, fragments(&frame, 40 + case as u16, 256))
            };
            let mut clock = Clock::default();
            let delivered: Vec<_> = pieces
                .iter()
                .filter_map(|piece| deliver(&mut a, now, piece, &mut clock))
                .collect();
            assert_eq!(delivered.len(), 1, "case {case}");
            let (envelope, bytes, disposition) = &delivered[0];
            assert_eq!(*disposition, ntcp::InputDisposition::Processed);
            // Sampled once, for the one Timestamp slot written.
            assert_eq!(clock.calls, usize::from(interpretation), "case {case}");
            assert_eq!(processed_options(*envelope, bytes), expected);
            assert_eq!(a.1.received_ipv4_options(child).unwrap(), Some(expected));
            // The datagram bytes keep the options as they arrived.
            assert_eq!(&bytes[20..52], &OPTIONS);
            let mut data = [0; 1000];
            assert_eq!(a.1.read(child, &mut data).unwrap(), 1000);
            assert_eq!(data, [case as u8; 1000]);
            // Retained and dispatched again: nothing processed or recorded
            // a second time (the duplicate segment changes nothing).
            let again = envelope.datagram(bytes).unwrap();
            assert_eq!(a.0.decode_datagram(again).unwrap().options, expected);
            a.0.input_datagram(&mut a.1, now, again, RxPacketMetadata::default(), 0)
                .unwrap();
            assert_eq!(a.1.received_ipv4_options(child).unwrap(), Some(expected));
            assert_eq!(clock.calls, usize::from(interpretation));
            pump(&mut b, &mut a, &mut now);
        }
        assert_eq!(a.0.reassembly_counters().completed, 4);
        std::println!(
            "interpretation={interpretation}: TCP received {expected:?} once per datagram"
        );
    }
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# The destination host MUST (if possible) add the current timestamp to
//# a Timestamp option before passing the option to the transport layer
//# or to ICMP for processing.
fn timestamps_are_sampled_only_for_a_slot_this_host_writes() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = side(local, 1403, &cfg);
    let me = v4(local.ip());
    let to_us = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let mut message = [0; 16];
    let n =
        ntcp_icmp::encode_echo(to_us, ntcp_icmp::EchoKind::Request, 1, 1, &mut message, 8).unwrap();
    let mut request = vec![0; 20 + n];
    request[20..].copy_from_slice(&message[..n]);
    let header = ntcp_ip::Header {
        ip: to_us,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
        ipv4_options: Default::default(),
    };
    ntcp_ip::encode_datagram(&mut request, header, 1, n, 0).unwrap();
    let other = Ipv4Addr::new(198, 51, 100, 9).octets();
    let mut flag3 = [68, 12, 5, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    flag3[4..8].copy_from_slice(&other);
    let full = [68, 12, 13, 0xe0, 0, 0, 0, 1, 0, 0, 0, 2];
    let mut advanced = full;
    advanced[3] = 0xf0;
    let cases: [(&[u8], usize, Vec<u8>); 3] = [
        // Record Route alone: recorded without any time.
        (&[7, 7, 4, 0, 0, 0, 0, 0], 0, {
            let mut rr = vec![7, 7, 8, 0, 0, 0, 0];
            rr[3..7].copy_from_slice(&me.octets());
            rr
        }),
        // A prespecified slot for another host: unchanged, never sampled.
        (&flag3, 0, flag3.to_vec()),
        // A full area: overflow advanced, never sampled.
        (&full, 0, advanced.to_vec()),
    ];
    for (raw, calls, expected) in cases {
        let frame = with_options(&request, raw);
        let mut clock = Clock::default();
        let (envelope, bytes, _) = deliver(&mut a, 1, &frame, &mut clock).unwrap();
        assert_eq!(clock.calls, calls);
        assert_eq!(
            processed_options(envelope, &bytes).as_bytes(),
            &expected[..]
        );
    }
    // Exhausted overflow discards the datagram before dispatch, unsampled.
    let frame = with_options(&request, &advanced);
    let mut out = vec![0; 256];
    let Received::Datagram(datagram) = a.0.receive(a.2, 2, &frame, false, &mut out).unwrap() else {
        panic!("whole")
    };
    let mut clock = Clock::default();
    assert_eq!(
        a.0.process(datagram, Some(&mut clock)).unwrap_err(),
        Error::Codec(ntcp_ip::Error::Options)
    );
    assert_eq!(clock.calls, 0);
    assert_eq!(
        a.0.input_ip(
            &mut a.1,
            a.2,
            2,
            &frame,
            RxPacketMetadata::default(),
            0,
            Some(SAMPLE)
        ),
        Ok(ntcp::InputDisposition::Dropped)
    );
}

// Every arrival order of an Echo Request (whole, in order, reversed, with
// a duplicate, fragment zero last) is processed once before the Echo
// service; with interpretation disabled every option still arrives,
// unrecorded and unsampled, and the reply carries none of them.
#[test]
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
//# passed to the transport layer (or to ICMP processing when the datagram is
//# an ICMP message). The IP and transport layer MUST each interpret those IP
//# options that they understand and silently ignore the others.
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# The destination host MUST (if possible) add the current timestamp to
//# a Timestamp option before passing the option to the transport layer
//# or to ICMP for processing.
fn echo_requests_are_processed_once_in_every_arrival_order() {
    for interpretation in [true, false] {
        let cfg = config(2);
        let (local, remote) = addresses(false);
        let mut a = side(local, 1405, &cfg);
        profile(&mut a, interpretation, false);
        let to_us = IpMetadata {
            source: remote.ip(),
            destination: local.ip(),
        };
        let data = [9; 900];
        let mut message = vec![0; 8 + data.len()];
        message[8..].copy_from_slice(&data);
        let n = ntcp_icmp::encode_echo(
            to_us,
            ntcp_icmp::EchoKind::Request,
            3,
            4,
            &mut message,
            data.len(),
        )
        .unwrap();
        let mut request = vec![0; 20 + n];
        request[20..].copy_from_slice(&message[..n]);
        let header = ntcp_ip::Header {
            ip: to_us,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        ntcp_ip::encode_datagram(&mut request, header, 1, n, 0).unwrap();
        let frame = with_options(&request, &OPTIONS);
        let received = Ipv4Options::parse(&OPTIONS, false).unwrap();
        let expected = if interpretation {
            received.record(v4(local.ip()), SAMPLE).unwrap()
        } else {
            received
        };
        // The reply continues only the recorded RR and TS (23 octets and
        // one EOL), never the opaque options.
        let reply_options = &expected.as_bytes()[..23];
        for case in 0..5 {
            let pieces = if case == 0 {
                vec![frame.clone()]
            } else {
                arrange(case - 1, fragments(&frame, 77 + case as u16, 256))
            };
            let mut clock = Clock::default();
            let delivered: Vec<_> = pieces
                .iter()
                .filter_map(|piece| deliver(&mut a, 5, piece, &mut clock))
                .collect();
            assert_eq!(delivered.len(), 1, "case {case}");
            assert_eq!(clock.calls, usize::from(interpretation), "case {case}");
            let (envelope, bytes, disposition) = &delivered[0];
            assert_eq!(*disposition, ntcp::InputDisposition::Processed);
            let processed = envelope.datagram(bytes).unwrap();
            assert_eq!(processed.packet().options, expected, "case {case}");
            assert_eq!(processed.reassembled(), case != 0);
            assert_eq!(a.0.icmp_output_counters().echo_replies, case as u64 + 1);
            let mut packet = vec![0; 8192];
            let mut first = None;
            a.0.icmp_output(5, &mut packet, |_, bytes| {
                first.get_or_insert_with(|| bytes.to_vec());
                BackendOutcome::Submitted
            })
            .unwrap()
            .unwrap();
            let first = first.unwrap();
            let header = usize::from(first[0] & 15) * 4;
            if interpretation {
                assert_eq!(&first[20..43], reply_options, "case {case}");
                assert_eq!(&first[43..header], &[0]);
            } else {
                assert_eq!(header, 20, "case {case}");
            }
            assert_eq!(clock.calls, usize::from(interpretation));
        }
    }
}

// A PTB about a reserved owner's segment is deferred after processing:
// replaying the token, while still reserved and once released, applies
// the report without sampling or recording again.
#[test]
fn deferred_icmp_replay_never_processes_the_datagram_again() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = side(local, 1411, &cfg);
    let mut b = managed(remote, 1412, cfg.clone());
    b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    a.1.write(id, &[7; 2800]).unwrap();
    let original = emit(&mut a.0, &mut a.1, now + 1).unwrap();
    let (held, _, frame) = selected(&mut a.1, now + 1).unwrap();
    assert!(a.1.is_output_reserved(id));
    let report = with_options(&ptb(&original, 1100), &OPTIONS);
    let mut out = vec![0; 2048];
    let Received::Datagram(datagram) = a.0.receive(a.2, now + 2, &report, false, &mut out).unwrap()
    else {
        panic!("whole")
    };
    let mut clock = Clock::default();
    let processed = a.0.process(datagram, Some(&mut clock)).unwrap();
    assert_eq!(clock.calls, 1);
    let IcmpDispatch::Deferred(deferred) =
        a.0.input_icmp_datagram(&mut a.1, now + 2, processed)
            .unwrap()
    else {
        panic!("a reserved owner defers")
    };
    for _ in 0..2 {
        assert!(matches!(
            a.0.replay_icmp(&mut a.1, deferred, now + 3).unwrap(),
            IcmpDispatch::Deferred(_)
        ));
    }
    let context = a.0.egress_context(&mut a.1, held).unwrap();
    let ticket = a.0.submission_ticket(&mut a.1, context).unwrap();
    a.0.submit(&mut a.1, now + 3, ticket, context, &frame, 0, |_| {
        BackendOutcome::Submitted
    })
    .unwrap();
    let (report_out, _) = tcp_report(a.0.replay_icmp(&mut a.1, deferred, now + 4).unwrap());
    assert!(matches!(
        report_out,
        TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
    ));
    assert_eq!(clock.calls, 1);
    // The processed bytes still hold the options exactly as received.
    assert_eq!(&processed.bytes()[20..52], &OPTIONS);
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
//# passed to the transport layer (or to ICMP processing when the datagram is
//# an ICMP message). The IP and transport layer MUST each interpret those IP
//# options that they understand and silently ignore the others.
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= type=test
//# The destination host MUST (if possible) add the current timestamp to
//# a Timestamp option before passing the option to the transport layer
//# or to ICMP for processing.
fn icmp_errors_consume_processed_outer_options_and_keep_quotes_historical() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = side(local, 1407, &cfg);
    let mut b = managed(remote, 1408, cfg.clone());
    b.1.listen(remote, 1).unwrap();
    let id =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let mut now = 0;
    pump(&mut a, &mut b, &mut now);
    a.1.write(id, &[7; 1400]).unwrap();
    let original = emit(&mut a.0, &mut a.1, now + 1).unwrap();
    let me = v4(local.ip());
    // A completed loose source route (one recorded hop) ahead of RR and TS.
    let mut outer = [0; 32];
    outer[..7].copy_from_slice(&[131, 7, 8, 192, 0, 2, 9]);
    outer[7..18].copy_from_slice(&OPTIONS[..11]);
    outer[18..30].copy_from_slice(&OPTIONS[11..23]);
    // Before T14 the ICMP decoder parsed the outer header again with source
    // routes refused: a report the Host admitted was rejected there.
    profile(&mut a, true, true);
    let report = with_options(&ptb(&original, 1100), &outer);
    let mut out = vec![0; 2048];
    let Received::Datagram(datagram) = a.0.receive(a.2, now + 2, &report, false, &mut out).unwrap()
    else {
        panic!("whole")
    };
    let mut clock = Clock::default();
    let processed = a.0.process(datagram, Some(&mut clock)).unwrap();
    assert_eq!(clock.calls, 1);
    let options = processed.packet().options;
    let expected = Ipv4Options::parse(&outer, true)
        .unwrap()
        .record(me, SAMPLE)
        .unwrap();
    assert_eq!(options, expected);
    // The error consumer sees the processed outer options, the quote stays
    // the received bytes.
    let feedback = crate::icmp_feedback(&processed.packet()).unwrap();
    assert_eq!(feedback.outer_options, expected);
    assert_eq!(processed.packet().payload, &report[52..]);
    assert_eq!(&processed.bytes()[20..52], &outer);
    let (report_out, _) = tcp_report(
        a.0.input_icmp_datagram(&mut a.1, now + 2, processed)
            .unwrap(),
    );
    assert!(matches!(
        report_out,
        TcpReport::PacketTooBig(PmtuFeedback::Decreased { .. })
    ));
    assert_eq!(clock.calls, 1);

    // A quote carrying RR, TS and an unfinished source route is historical:
    // never recorded, its bytes unchanged, its final destination recovered.
    let mut quoted_options = [0; 32];
    quoted_options[..7].copy_from_slice(&[131, 7, 4, 192, 0, 2, 9]);
    quoted_options[7..30].copy_from_slice(&OPTIONS[..23]);
    let mut historical = with_options(&original, &quoted_options);
    // The unfinished route names its next hop as the header destination.
    historical[16..20].copy_from_slice(&[192, 0, 2, 9]);
    historical[23..27].copy_from_slice(&original[16..20]);
    seal_ipv4(&mut historical);
    let error = with_options(&ptb(&historical, 1100), &outer);
    let Received::Datagram(datagram) = a.0.receive(a.2, now + 3, &error, false, &mut out).unwrap()
    else {
        panic!("whole")
    };
    let mut clock = Clock::default();
    let processed = a.0.process(datagram, Some(&mut clock)).unwrap();
    assert_eq!(clock.calls, 1);
    let feedback = crate::icmp_feedback(&processed.packet()).unwrap();
    assert_eq!(feedback.outer_options, expected);
    assert_eq!(feedback.quoted.ip.destination, remote.ip());
    let quote = &processed.packet().payload[8..];
    assert_eq!(quote, &historical[..quote.len()]);
    // The quoted unfinished route still points at its first slot.
    assert_eq!(&quote[20..24], &[131, 7, 4, 192]);
    a.0.input_icmp_datagram(&mut a.1, now + 3, processed)
        .unwrap();
}

#[test]
fn admitted_source_routed_echo_reaches_the_echo_service() {
    let cfg = config(2);
    let (local, remote) = addresses(false);
    let mut a = side(local, 1409, &cfg);
    profile(&mut a, true, true);
    let to_us = IpMetadata {
        source: remote.ip(),
        destination: local.ip(),
    };
    let mut message = [0; 16];
    let n =
        ntcp_icmp::encode_echo(to_us, ntcp_icmp::EchoKind::Request, 1, 1, &mut message, 8).unwrap();
    let mut request = vec![0; 20 + n];
    request[20..].copy_from_slice(&message[..n]);
    let header = ntcp_ip::Header {
        ip: to_us,
        hop_limit: 64,
        dscp: 0,
        ecn: 0,
        ipv4_options: Default::default(),
    };
    ntcp_ip::encode_datagram(&mut request, header, 1, n, 0).unwrap();
    let frame = with_options(&request, &[131, 7, 8, 192, 0, 2, 9, 0]);
    let mut clock = Clock::default();
    let mut out = vec![0; 256];
    let Received::Datagram(datagram) = a.0.receive(a.2, 1, &frame, false, &mut out).unwrap() else {
        panic!("whole")
    };
    let processed = a.0.process(datagram, Some(&mut clock)).unwrap();
    // The Echo service sees the admitted route and answers along its
    // authorized reversal.
    assert_eq!(
        a.0.input_icmp_datagram(&mut a.1, 1, processed).unwrap(),
        IcmpDispatch::Completed(IcmpOutcome::Echo(EchoDisposition::Queued))
    );
    assert_eq!(a.0.icmp_output_pending(), 1);
    assert_eq!(clock.calls, 0);
    // Refused by the profile: rejected before any processing.
    profile(&mut a, true, false);
    assert!(a.0.receive(a.2, 2, &frame, false, &mut out).is_err());
}
