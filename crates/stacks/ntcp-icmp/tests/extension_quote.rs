#![cfg(feature = "ipv6")]
use std::net::Ipv6Addr;

use ntcp::IpMetadata;
use ntcp_icmp::*;

const SOURCE: &str = "2001:db8::1";
const ROUTER: &str = "2001:db8:9::1";
const SEGMENT: &str = "2001:db8:a::1";
const MIDDLE: &str = "2001:db8:b::1";
const FINAL: &str = "2001:db8:c::1";

fn addr(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn metadata(source: &str, destination: &str) -> IpMetadata {
    IpMetadata {
        source: addr(source).into(),
        destination: addr(destination).into(),
    }
}

// Base header to `destination`, `headers` (selector and the octets after
// each Next Header field) and the upper layer.
fn packet(destination: &str, headers: &[(u8, &[u8])], protocol: u8, upper: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 40];
    b[0] = 0x60;
    b[7] = 64;
    b[8..24].copy_from_slice(&addr(SOURCE).octets());
    b[24..40].copy_from_slice(&addr(destination).octets());
    let mut selector = 6;
    for (kind, rest) in headers {
        b[selector] = *kind;
        selector = b.len();
        b.push(0);
        b.extend_from_slice(rest);
    }
    b[selector] = protocol;
    b.extend_from_slice(upper);
    let payload = (b.len() - 40) as u16;
    b[4..6].copy_from_slice(&payload.to_be_bytes());
    b
}

// Segment Routing Header body after its Next Header octet (RFC 8754
// section 2), Segment List[0] first.
fn srh(segments_left: u8, last_entry: u8, list: &[&str]) -> Vec<u8> {
    let mut rest = vec![
        (2 * list.len()) as u8,
        4,
        segments_left,
        last_entry,
        0,
        0,
        0,
    ];
    for a in list {
        rest.extend_from_slice(&addr(a).octets());
    }
    rest
}

fn rh0(segments_left: u8, list: &[&str]) -> Vec<u8> {
    let mut rest = vec![(2 * list.len()) as u8, 0, segments_left, 0, 0, 0, 0];
    for a in list {
        rest.extend_from_slice(&addr(a).octets());
    }
    rest
}

// A TCP SYN from SOURCE whose checksum covers the final destination.
fn tcp(final_destination: &str) -> Vec<u8> {
    let mut b = vec![0; 60];
    let len = ntcp::wire::encode(
        metadata(SOURCE, final_destination),
        ntcp::wire::Header {
            source_port: 1234,
            destination_port: 8080,
            sequence: 0x89ab_cdef,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 1024,
            urgent_pointer: 0,
        },
        &[],
        &[],
        &mut b,
    )
    .unwrap();
    b.truncate(len);
    b
}

// ICMPv6 error from ROUTER to SOURCE quoting `quote`, carried after
// `outer_headers`.
fn error(kind: u8, code: u8, word: u32, outer_headers: &[(u8, &[u8])], quote: &[u8]) -> Vec<u8> {
    let mut icmp = vec![kind, code, 0, 0];
    icmp.extend_from_slice(&word.to_be_bytes());
    icmp.extend_from_slice(quote);
    let reply = metadata(ROUTER, SOURCE);
    let sum = icmpv6_checksum(reply, &icmp).unwrap();
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut b = packet(SOURCE, outer_headers, 58, &icmp);
    b[8..24].copy_from_slice(&addr(ROUTER).octets());
    b
}

fn ptb(quote: &[u8]) -> Vec<u8> {
    error(2, 0, 1280, &[], quote)
}

// RFC 8201 section 5.2's "last address" was written for Type 0; a Segment
// Routing Header names its final segment in Segment List[0].
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
//= type=test
//= reason=Quote decoding walks the bounded quoted chain and locates the destination from the Routing header before the upper layer (ntcp_ip_common Chain::final_destination): with no Routing header or Segments Left equal to zero, the Destination Address field of the IPv6 header; with Segments Left greater than zero, by Routing type, the user's recorded disposition (decision A, D8) of this note, written for the Type 0 header: a Type 0 header's last address Address[n] (even Hdr Ext Len, 1 <= Segments Left <= n), and a Segment Routing Header's Segment List[0], its final segment (RFC 8754 section 2 stores the list in reverse; 2(Last Entry + 1) <= Hdr Ext Len and Segments Left <= Last Entry + 1); an unknown type, or an earlier Routing header still active, declines attribution rather than guessing. Type 0 evidence is quote-decoder evidence only: no Type 0 header is ever originated. A PTB quoting the Host's own SRH output is correlated only after the quoted list is validated against the route generation that authorized the submission (Segments Left and the base Destination Address may advance in flight). ntcp-icmp's extension_quote tests (an SRH and a Type 0 header whose first and last addresses differ, advanced and finished SRHs, unknown and ambiguous declines), the Host segment_routes PTB tests and the integration/rfc_host srh tun_echo case, in which a kernel PTB quotes Segments Left 1 with a base Destination Address S1 different from the final destination, verify it.
//# Note: if the original packet contained a Routing header, the Routing header should be used to determine the location of the destination address within the original packet. If Segments Left is equal to zero, the destination address is in the Destination Address field in the IPv6 header. If Segments Left is greater than zero, the destination address is the last address (Address[n]) in the Routing header.
#[test]
fn routed_quotes_correlate_with_the_type_specific_final_destination() {
    let segment = tcp(FINAL);
    // SRH in flight to its first segment: Segment List[0] is the final
    // destination although the base header names another address.
    let header = srh(2, 2, &[FINAL, MIDDLE, SEGMENT]);
    let quoted = packet(SEGMENT, &[(43, &header)], 6, &segment);
    let feedback = decode_icmp(&ptb(&quoted)).unwrap();
    assert_eq!(feedback.candidate_mtu, Some(1280));
    assert_eq!(feedback.quoted.ip, metadata(SOURCE, FINAL));
    assert_eq!(usize::from(feedback.quoted.ip_header_len), 40 + 56);
    assert_eq!(feedback.quoted.ip_packet_len as usize, quoted.len());
    assert_eq!(
        (feedback.quoted.source_port, feedback.quoted.sequence),
        (1234, 0x89ab_cdef)
    );
    // The quoted TCP checksum covers that final destination.
    let upper = &quoted[96..];
    assert_eq!(
        ntcp_ip_common::pseudo_header_checksum(addr(SOURCE).into(), addr(FINAL).into(), 6, upper),
        Ok(0)
    );
    // After advancing to the middle segment the correlation is unchanged.
    let advanced = srh(1, 2, &[FINAL, MIDDLE, SEGMENT]);
    let quoted = packet(MIDDLE, &[(43, &advanced)], 6, &segment);
    assert_eq!(
        decode_icmp(&ptb(&quoted)).unwrap().quoted.ip,
        metadata(SOURCE, FINAL)
    );
    // Finished: the base destination, which is then the final one.
    let done = srh(0, 2, &[FINAL, MIDDLE, SEGMENT]);
    let quoted = packet(FINAL, &[(43, &done)], 6, &segment);
    assert_eq!(
        decode_icmp(&ptb(&quoted)).unwrap().quoted.ip,
        metadata(SOURCE, FINAL)
    );
    // RH0 (decoded only from quotes): its last address, distinct from the
    // first.
    let legacy = rh0(2, &[MIDDLE, FINAL]);
    let quoted = packet(SEGMENT, &[(43, &legacy)], 6, &segment);
    assert_eq!(
        decode_icmp(&ptb(&quoted)).unwrap().quoted.ip,
        metadata(SOURCE, FINAL)
    );
    // Unknown types and ambiguous chains are declined, never guessed.
    let mut unknown = srh(1, 1, &[FINAL, SEGMENT]);
    unknown[1] = 253;
    let active = srh(1, 1, &[FINAL, SEGMENT]);
    for headers in [
        vec![(43, &unknown[..])],
        vec![(43, &active[..]), (43, &active[..])],
    ] {
        let quoted = packet(SEGMENT, &headers, 6, &segment);
        assert_eq!(decode_icmp(&ptb(&quoted)).unwrap_err(), Error::Quote);
    }
    // The outer checksum is still validated.
    let quoted = packet(SEGMENT, &[(43, &header)], 6, &segment);
    let mut corrupt = ptb(&quoted);
    corrupt[44] ^= 1;
    assert_eq!(decode_icmp(&corrupt).unwrap_err(), Error::Checksum);
}

#[test]
fn quotes_need_every_header_up_to_the_selectors_and_execute_no_options() {
    let segment = tcp(FINAL);
    // A Destination Options header holding an action-10 option, then an SRH:
    // the option is historical and is not acted on.
    let options = [0, 0x9e, 0, 1, 2, 0, 0];
    let header = srh(1, 1, &[FINAL, SEGMENT]);
    let quoted = packet(SEGMENT, &[(60, &options), (43, &header)], 6, &segment);
    let header_len = 40 + 8 + 40;
    for cut in 0..=quoted.len() {
        let result = decode_icmp_quote(&ptb(&quoted[..cut]));
        if cut < header_len + 8 {
            // Missing headers or selector octets decline attribution.
            assert!(
                matches!(result, Err(Error::Truncated | Error::Quote)),
                "cut={cut} {result:?}"
            );
        } else {
            let feedback = result.unwrap();
            assert_eq!(feedback.quoted.ip, metadata(SOURCE, FINAL));
            assert_eq!(usize::from(feedback.quoted.ip_header_len), header_len);
            assert_eq!(feedback.quoted.ip_packet_len as usize, quoted.len());
            assert!(matches!(
                feedback.quoted.transport,
                QuotedTransport::Tcp {
                    source_port: 1234,
                    destination_port: 8080,
                    ..
                }
            ));
        }
    }
}

#[test]
fn quoted_fragments_after_routing_headers_keep_later_data_opaque() {
    let header = srh(1, 1, &[FINAL, SEGMENT]);
    let mut udp = vec![0; 16];
    ntcp_ip_common::encode_udp(
        addr(SOURCE).into(),
        addr(FINAL).into(),
        4000,
        53,
        &mut udp,
        8,
    )
    .unwrap();
    // Fragment zero: the UDP header follows the Fragment header.
    let first = [17, 0, 0, 1, 0, 0, 0, 9];
    let quoted = packet(SEGMENT, &[(43, &header), (44, &first[1..])], 17, &udp);
    let feedback = decode_icmp_quote(&ptb(&quoted)).unwrap();
    let fragment = feedback.quoted.fragment.unwrap();
    assert_eq!((fragment.offset, fragment.more_fragments), (0, true));
    assert_eq!(fragment.data(), &udp[..8]);
    assert_eq!(feedback.quoted.ip, metadata(SOURCE, FINAL));
    assert_eq!(feedback.quoted.ip_header_len, 88);
    assert!(matches!(
        feedback.quoted.transport,
        QuotedTransport::Udp {
            destination_port: 53,
            ..
        }
    ));
    // A later fragment: its data is never parsed for ports.
    let later = [17, 0, 0x04, 0xd0, 0, 0, 0, 9];
    let quoted = packet(SEGMENT, &[(43, &header), (44, &later[1..])], 6, &udp);
    let feedback = decode_icmp_quote(&ptb(&quoted)).unwrap();
    let fragment = feedback.quoted.fragment.unwrap();
    assert_eq!((fragment.offset, fragment.more_fragments), (1232, false));
    assert_eq!(feedback.quoted.transport, QuotedTransport::Other);
    assert_eq!(feedback.quoted.ip_header_len, 88);
    assert_eq!(
        decode_icmp(&ptb(&quoted)).unwrap_err(),
        Error::FragmentationUnsupported
    );
}

#[test]
fn outer_extension_headers_pass_receive_processing() {
    let segment = tcp(SEGMENT);
    let quoted = packet(SEGMENT, &[], 6, &segment);
    let padding = [0, 1, 4, 0, 0, 0, 0];
    let feedback = decode_icmp_quote(&error(2, 0, 1280, &[(60, &padding)], &quoted)).unwrap();
    assert_eq!(feedback.outer, metadata(ROUTER, SOURCE));
    assert_eq!(feedback.candidate_mtu, Some(1280));
    // An outer option whose action discards the packet is not decoded; an
    // active outer Routing header is refused.
    let discard = [0, 0x5e, 0, 1, 2, 0, 0];
    assert_eq!(
        decode_icmp_quote(&error(2, 0, 1280, &[(60, &discard)], &quoted)).unwrap_err(),
        Error::Options
    );
    let active = srh(1, 1, &[SOURCE, SEGMENT]);
    assert_eq!(
        decode_icmp_quote(&error(2, 0, 1280, &[(43, &active)], &quoted)).unwrap_err(),
        Error::ExtensionsUnsupported
    );
    // Parameter Problem code 3 (RFC 7112) decodes like the other codes.
    let feedback = decode_icmp_quote(&error(4, 3, 0, &[], &quoted)).unwrap();
    assert_eq!(
        (feedback.kind, feedback.code),
        (FeedbackKind::ParameterProblem, 3)
    );
    assert_eq!(
        decode_icmp_quote(&error(4, 4, 0, &[], &quoted)).unwrap_err(),
        Error::ProtocolUnsupported
    );
}

#[test]
fn error_quote_is_bounded_by_the_actual_outer_header() {
    let invoking = vec![0x60; 2000];
    let reply = metadata(SOURCE, ROUTER);
    let mut message = vec![0; 2000];
    // The quote fills the minimum MTU after the outer header that will
    // carry the error and the ICMP header.
    for outer in [40, 40 + 8 + 16 * 2, 40 + 8 + 16 * 20, 1272] {
        let n = encode_error(
            reply,
            ErrorMessage::ReassemblyTimeExceeded,
            &invoking,
            outer,
            &mut message,
        )
        .unwrap();
        assert_eq!(outer + n, 1280, "outer={outer}");
        assert_eq!(icmpv6_checksum(reply, &message[..n]).unwrap(), 0);
    }
    // No outer header is shorter than the base header, and one that
    // leaves no room for the ICMP header refuses rather than wraps.
    for (outer, expected) in [
        (39, Error::Invalid),
        (1281, Error::Length),
        (usize::MAX, Error::Length),
    ] {
        let before = message.clone();
        assert_eq!(
            encode_error(
                reply,
                ErrorMessage::ReassemblyTimeExceeded,
                &invoking,
                outer,
                &mut message
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(message, before);
    }
    for outer in [1273, 1280] {
        let n = encode_error(
            reply,
            ErrorMessage::ReassemblyTimeExceeded,
            &invoking,
            outer,
            &mut message,
        );
        assert_eq!(n.unwrap_err(), Error::Length);
    }
}
