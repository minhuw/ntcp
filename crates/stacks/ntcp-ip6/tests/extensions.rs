use std::net::Ipv6Addr;

use ntcp_ip_common::{Error, PROTOCOL_UDP, encode_udp, parse_udp, pseudo_header_checksum};
use ntcp_ip6::{
    Chain, Completeness, Fault, FragmentHeader, OptionAction, parse, parse_fragment, quote_header,
};

const SOURCE: &str = "2001:db8::1";
const DESTINATION: &str = "2001:db8::2";

fn addr(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

// One extension header: its selector and every octet after its Next Header
// field (for Hop-by-Hop, Routing and Destination Options, Hdr Ext Len first).
type Ext<'a> = (u8, &'a [u8]);

// A packet from SOURCE to `destination` with `headers` in wire order, then
// `protocol` and `upper`; each Next Header names its successor.
fn packet_to(destination: Ipv6Addr, headers: &[Ext], protocol: u8, upper: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 40];
    b[0] = 0x60;
    b[7] = 64;
    b[8..24].copy_from_slice(&addr(SOURCE).octets());
    b[24..40].copy_from_slice(&destination.octets());
    let mut selector = 6;
    for (kind, rest) in headers {
        b[selector] = *kind;
        selector = b.len();
        b.push(0);
        b.extend_from_slice(rest);
        assert_eq!((rest.len() + 1) % 8, 0, "whole 8-octet units");
    }
    b[selector] = protocol;
    b.extend_from_slice(upper);
    let payload = u16::try_from(b.len() - 40).unwrap();
    b[4..6].copy_from_slice(&payload.to_be_bytes());
    b
}

fn packet(headers: &[Ext], protocol: u8, upper: &[u8]) -> Vec<u8> {
    packet_to(addr(DESTINATION), headers, protocol, upper)
}

// Options header body (Hdr Ext Len, then `options`) padded with PadN.
fn options(options: &[u8]) -> Vec<u8> {
    let mut rest = vec![0];
    rest.extend_from_slice(options);
    match (rest.len() + 1) % 8 {
        0 => {}
        7 => rest.push(0),
        used => {
            let pad = 8 - used;
            rest.extend_from_slice(&[1, (pad - 2) as u8]);
            rest.resize(rest.len() + pad - 2, 0);
        }
    }
    rest[0] = ((rest.len() + 1) / 8 - 1) as u8;
    rest
}

// Routing header body: Hdr Ext Len, Routing Type, Segments Left, then
// `data` (type-specific fields from octet 4 on).
fn routing(kind: u8, segments_left: u8, data: &[u8]) -> Vec<u8> {
    let mut rest = vec![0, kind, segments_left];
    rest.extend_from_slice(data);
    assert_eq!((rest.len() + 1) % 8, 0);
    rest[0] = ((rest.len() + 1) / 8 - 1) as u8;
    rest
}

// Fragment header body after its Next Header octet.
fn fragment(offset: u16, more: bool, identification: u32) -> Vec<u8> {
    let mut rest = vec![0];
    rest.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
    rest.extend_from_slice(&identification.to_be_bytes());
    rest
}

// RH0 with `addresses` after its reserved word.
fn rh0(segments_left: u8, addresses: &[Ipv6Addr]) -> Vec<u8> {
    let mut data = vec![0; 4];
    for a in addresses {
        data.extend_from_slice(&a.octets());
    }
    routing(0, segments_left, &data)
}

// SRH (RFC 8754 section 2): Segment List[0] first, then optional TLV bytes.
fn srh(segments_left: u8, last_entry: u8, list: &[Ipv6Addr], tlvs: &[u8]) -> Vec<u8> {
    let mut data = vec![last_entry, 0, 0, 0];
    for a in list {
        data.extend_from_slice(&a.octets());
    }
    data.extend_from_slice(tlvs);
    routing(4, segments_left, &data)
}

const TCP_HEADER: [u8; 20] = [
    0x04, 0xd2, 0x1f, 0x90, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 4, 0, 0, 0, 0, 0,
];

//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= type=test
//= reason=Selector 59 in the base header or any traversed extension header ends the chain after exact declared-bound checks: no transport payload is exposed and the borrowed input bytes and quoted length/protocol remain intact. Forwarding remains outside the existing endpoint scope.
//# The value 59 in the Next Header field of an IPv6 header or any
//# extension header indicates that there is nothing following that
//# header. If the Payload Length field of the IPv6 header indicates the
//# presence of octets past the end of a header whose Next Header field
//# contains 59, those octets must be ignored and passed on unchanged if
//# the packet is forwarded.
#[test]
fn both_destination_options_positions_unusual_order_repetition_and_no_next_header() {
    let pre = options(&[]);
    let route = routing(4, 0, &[0; 20]);
    let hop = options(&[]);
    // RFC 8200 section 4.1's order: Hop-by-Hop, Destination Options before
    // Routing, Routing, Destination Options for the final destination.
    let p = packet(
        &[(0, &hop), (60, &pre), (43, &route), (60, &pre)],
        6,
        &TCP_HEADER,
    );
    let parsed = parse(&p).unwrap();
    assert_eq!((parsed.protocol, parsed.payload), (6, &p[88..]));
    assert_eq!(parsed.ip.destination, addr(DESTINATION));
    assert!(!parsed.base_layout());
    let chain = parsed.chain;
    let walked: Vec<_> = chain.headers().map(|h| (h.kind, h.offset, h.len)).collect();
    assert_eq!(walked, [(0, 40, 8), (60, 48, 8), (43, 56, 24), (60, 80, 8)]);
    assert_eq!((chain.header_len(), chain.protocol_selector()), (88, 80));
    assert_eq!(chain.completeness(), Completeness::Complete);
    // Unusual order and repetition are accepted as received.
    for headers in [
        vec![
            (43, &route[..]),
            (60, &pre[..]),
            (43, &route[..]),
            (60, &pre[..]),
        ],
        vec![(60, &pre[..]), (60, &pre[..]), (60, &pre[..])],
        vec![(43, &route[..]), (43, &route[..])],
    ] {
        let p = packet(&headers, 6, &TCP_HEADER);
        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.payload, &TCP_HEADER);
        assert_eq!(parsed.chain.headers().count(), headers.len());
    }
    // No Next Header after an extension header hides the declared tail.
    for tail in [0, 1, 13, 4000] {
        let p = packet(&[(60, &pre), (43, &route)], 59, &vec![0xa5; tail]);
        let before = p.clone();
        let parsed = parse(&p).unwrap();
        assert_eq!((parsed.protocol, parsed.payload), (59, &[][..]));
        assert_eq!(parsed.chain.header_len(), 72);
        assert_eq!(parsed.chain.declared_len(), p.len());
        assert_eq!(
            quote_header(&p[..72]).unwrap(),
            (parsed.ip, 72, p.len(), 59)
        );
        assert_eq!(p, before);
    }
}

#[test]
fn padding_and_every_unknown_option_action() {
    // Pad1 and PadN in any mix and length are skipped; PadN data is ignored.
    let padded = [
        options(&[0, 0, 0, 0]),
        options(&[1, 0]),
        options(&[1, 4, 0xff, 0xff, 0xff, 0xff]),
        options(&[0, 1, 1, 0, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        options(
            &[1, 253, 0]
                .iter()
                .copied()
                .chain([0; 252])
                .collect::<Vec<_>>(),
        ),
    ];
    for kind in [0, 60] {
        for body in &padded {
            let p = packet(&[(kind, body)], 6, &TCP_HEADER);
            assert_eq!(parse(&p).unwrap().payload, &TCP_HEADER);
        }
    }
    // An unknown option of action 00 is skipped; the others discard with
    // their report rule, pointing at the Option Type octet.
    for (kind, header) in [(0u8, 40usize), (60, 48)] {
        for (option, action) in [
            (0x1e, None),
            (0x5e, Some(OptionAction::Discard)),
            (0x9e, Some(OptionAction::Report)),
            (0xde, Some(OptionAction::ReportUnlessMulticast)),
        ] {
            let body = options(&[0, 1, 0, option, 2, 0xaa, 0xbb]);
            let mut headers = vec![(kind, &body[..])];
            let lead = options(&[]);
            if kind == 60 {
                headers.insert(0, (0, &lead[..]));
            }
            let p = packet(&headers, 17, &[0; 8]);
            let result = Chain::receive(&p);
            match action {
                None => {
                    assert_eq!(result.unwrap().protocol(), 17);
                    assert!(parse(&p).is_ok());
                }
                Some(action) => {
                    assert_eq!(
                        result.unwrap_err(),
                        Fault::Option {
                            pointer: header + 5,
                            action
                        }
                    );
                    assert_eq!(parse(&p).unwrap_err(), Error::Options);
                    // A quote reports historical options without acting.
                    assert_eq!(Chain::quote(&p).unwrap().protocol(), 17);
                }
            }
        }
    }
    // TLV bounds: a length octet missing, or option data past the header.
    let mut missing = options(&[0, 0, 0, 0, 0, 0]);
    missing[6] = 0x1e;
    let p = packet(&[(60, &missing)], 6, &TCP_HEADER);
    assert_eq!(
        Chain::receive(&p).unwrap_err(),
        Fault::Length { pointer: 47 }
    );
    let mut long = options(&[0x1e, 4, 0, 0, 0, 0]);
    long[2] = 5;
    let p = packet(&[(60, &long)], 6, &TCP_HEADER);
    assert_eq!(
        Chain::receive(&p).unwrap_err(),
        Fault::Length { pointer: 43 }
    );
    assert_eq!(parse(&p).unwrap_err(), Error::Length);
}

#[test]
fn misplaced_hop_by_hop_and_unrecognized_next_header_pointers() {
    let dest = options(&[]);
    let route = routing(253, 0, &[0; 4]);
    for (headers, pointer) in [
        (vec![(60, &dest[..])], 40),
        (vec![(43, &route[..]), (60, &dest[..])], 48),
        (vec![(0, &dest[..]), (60, &dest[..])], 48),
        // Hop-by-Hop directly after the base header is fine; a second one
        // after it is misplaced at its predecessor's selector.
        (vec![(0, &dest[..])], 40),
    ] {
        let mut chain = headers.clone();
        chain.push((0, &dest[..]));
        let p = packet(&chain, 6, &TCP_HEADER);
        let expected = Fault::MisplacedHopByHop { pointer };
        assert_eq!(Chain::receive(&p).unwrap_err(), expected);
        assert_eq!(Chain::quote(&p).unwrap_err(), expected);
        assert_eq!(parse(&p).unwrap_err(), Error::ExtensionsUnsupported);
    }
    // A selector that is no traversed extension ends the chain; the Host
    // rejects it as unrecognized at the octet that names it, not at the
    // purported following header.
    for (headers, selector) in [
        (vec![], 6),
        (vec![(60, &dest[..])], 40),
        (vec![(60, &dest[..]), (43, &route[..])], 48),
    ] {
        for protocol in [50, 51, 135, 139, 140, 253] {
            let p = packet(&headers, protocol, &[0xa5; 24]);
            let chain = Chain::receive(&p).unwrap();
            assert_eq!(
                (chain.protocol(), chain.protocol_selector()),
                (protocol, selector)
            );
            assert_eq!(p[selector], protocol);
            assert_eq!(chain.header_len(), 40 + 8 * headers.len());
        }
    }
}

#[test]
fn every_truncation_boundary_and_length_limit() {
    let dest = options(&[1, 2, 0, 0]);
    let route = srh(0, 1, &[addr("2001:db8::5"), addr("2001:db8::6")], &[]);
    let p = packet(&[(60, &dest), (43, &route), (60, &dest)], 6, &TCP_HEADER);
    let upper = 40 + 8 + 40 + 8;
    assert_eq!(Chain::receive(&p).unwrap().header_len(), upper);
    for cut in 0..p.len() {
        // A received packet shorter than declared is physical truncation,
        // dropped silently before any header can draw an error.
        let short = &p[..cut];
        assert_eq!(Chain::receive(short).unwrap_err(), Fault::Truncated);
        assert_eq!(
            parse(short).unwrap_err(),
            if cut < 40 {
                Error::Truncated
            } else {
                Error::Length
            }
        );
        // A quote must hold every header up to the upper layer.
        let quoted = Chain::quote(short);
        if cut < upper {
            assert_eq!(quoted.unwrap_err(), Fault::Truncated, "cut={cut}");
            assert_eq!(quote_header(short).unwrap_err(), Error::Truncated);
        } else {
            let chain = quoted.unwrap();
            assert_eq!(chain.header_len(), upper);
            assert_eq!(chain.declared_len(), p.len());
            assert_eq!(chain.completeness(), Completeness::Truncated);
        }
    }
    // A header longer than the declared payload is an impossible length at
    // its Hdr Ext Len octet; one that cannot even start there blames the
    // Payload Length.
    let mut long = p.clone();
    long[89] = 3;
    assert_eq!(
        Chain::receive(&long).unwrap_err(),
        Fault::Length { pointer: 89 }
    );
    assert_eq!(
        Chain::quote(&long[..90]).unwrap_err(),
        Fault::Length { pointer: 89 }
    );
    let mut short = packet(&[(60, &dest)], 59, &[]);
    short.truncate(44);
    short[4..6].copy_from_slice(&4u16.to_be_bytes());
    assert_eq!(
        Chain::receive(&short).unwrap_err(),
        Fault::Length { pointer: 4 }
    );
    // The bound is the declared payload, not a header count: 8191 minimal
    // headers (65528 octets) in the largest non-jumbo payload are walked.
    let minimal = options(&[]);
    let mut headers = vec![(60u8, &minimal[..]); 8191];
    headers[0].0 = 0;
    let p = packet(&headers, 59, &[0; 7]);
    assert_eq!(p.len(), 40 + 65535);
    let chain = Chain::receive(&p).unwrap();
    assert_eq!(
        (chain.header_len(), chain.headers().count()),
        (40 + 65528, 8191)
    );
    // Hdr Ext Len 255 is the largest header (2048 octets).
    let large = options(&[0; 2045]);
    assert_eq!(large[0], 255);
    let p = packet(&[(60, &large)], 6, &TCP_HEADER);
    assert_eq!(parse(&p).unwrap().payload, &TCP_HEADER);
}

#[test]
fn routing_headers_are_skipped_without_type_specific_checks_only_when_finished() {
    // Type-specific fields that would be invalid in an active header: RH0
    // with an odd Hdr Ext Len, SRH whose Last Entry overruns the header, an
    // unknown type with arbitrary data.
    let odd_rh0 = routing(0, 0, &[0xff; 12]);
    let bad_srh = routing(4, 0, &[200, 0xff, 0xff, 0xff]);
    let unknown = routing(253, 0, &[0xa5; 20]);
    for (offset, header) in [(40usize, &odd_rh0), (40, &bad_srh), (40, &unknown)] {
        let dest = options(&[]);
        let p = packet(&[(43, header), (60, &dest)], 17, &[0; 8]);
        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.ip.destination, addr(DESTINATION));
        assert_eq!(parsed.chain.final_destination(), Some(addr(DESTINATION)));
        assert_eq!(parsed.payload.len(), 8);
        // Segments Left above zero: this host is no segment endpoint.
        for left in [1, 2, 255] {
            let mut active = p.clone();
            active[offset + 3] = left;
            assert_eq!(
                Chain::receive(&active).unwrap_err(),
                Fault::SegmentsLeft {
                    pointer: offset + 2
                }
            );
            assert_eq!(parse(&active).unwrap_err(), Error::ExtensionsUnsupported);
            assert_eq!(
                parse_fragment(&active).unwrap_err(),
                Error::ExtensionsUnsupported
            );
        }
    }
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= type=test
//# Destination Address 128-bit address of the intended recipient of the
//# packet (possibly not the ultimate recipient, if a Routing header is
//# present). See [RFC4291] and Section 4.4.
#[test]
fn quoted_final_destination_by_routing_type_with_extraction_bounds() {
    let first = addr("2001:db8:a::1");
    let middle = addr("2001:db8:b::1");
    let last = addr("2001:db8:c::1");
    let base = addr("2001:db8:f::1");
    let final_of = |headers: &[Ext]| {
        let p = packet_to(base, headers, 6, &TCP_HEADER);
        let chain = Chain::quote(&p).unwrap();
        assert_eq!(chain.destination(), base);
        (
            chain.final_destination(),
            quote_header(&p).map(|q| q.0.destination),
        )
    };
    // No Routing header, or Segments Left zero: the base destination.
    assert_eq!(final_of(&[]).0, Some(base));
    assert_eq!(final_of(&[(43, &rh0(0, &[first, last]))]).0, Some(base));
    // RH0: the last address for every legal Segments Left; the witness has
    // distinct first and last addresses.
    for left in 1..=3 {
        let header = rh0(left, &[first, middle, last]);
        assert_eq!(final_of(&[(43, &header)]), (Some(last), Ok(last.into())));
    }
    // Segments Left beyond the address count, an odd Hdr Ext Len, or no
    // address at all: unresolved.
    let mut odd = rh0(1, &[first]);
    odd.extend_from_slice(&[0; 8]);
    odd[0] = 3;
    for header in [rh0(4, &[first, middle, last]), odd, routing(0, 1, &[0; 4])] {
        assert_eq!(final_of(&[(43, &header)]), (None, Err(Error::Quote)));
    }
    // SRH: Segment List[0] for a full list, a reduced one (Segments Left =
    // Last Entry + 1) and one followed by TLVs.
    let tlv = [0, 0, 1, 4, 0, 0, 0, 0];
    for header in [
        srh(2, 2, &[last, middle, first], &[]),
        srh(1, 2, &[last, middle, first], &[]),
        srh(3, 2, &[last, middle, first], &[]),
        srh(2, 2, &[last, middle, first], &tlv),
        srh(1, 0, &[last], &[]),
    ] {
        assert_eq!(final_of(&[(43, &header)]), (Some(last), Ok(last.into())));
    }
    // A list overrunning the header or Segments Left past Last Entry + 1.
    let mut overrun = srh(1, 1, &[last, first], &[]);
    overrun[3] = 2;
    for header in [overrun, srh(3, 1, &[last, first], &[])] {
        assert_eq!(final_of(&[(43, &header)]), (None, Err(Error::Quote)));
    }
    // An unknown type with Segments Left above zero is not attributed.
    let unknown = routing(253, 1, &[0; 20]);
    assert_eq!(final_of(&[(43, &unknown)]).0, None);
    // Several Routing headers: a finished one defers to the next; an active
    // earlier one makes the quote ambiguous.
    let finished = rh0(0, &[first]);
    let active = srh(1, 1, &[last, first], &[]);
    let dest = options(&[]);
    assert_eq!(
        final_of(&[(43, &finished), (60, &dest), (43, &active)]).0,
        Some(last)
    );
    assert_eq!(final_of(&[(43, &active), (43, &finished)]).0, None);
    assert_eq!(final_of(&[(43, &active), (43, &active)]).0, None);
    assert_eq!(final_of(&[(43, &finished), (43, &finished)]).0, Some(base));
}

#[test]
fn checksum_uses_the_final_destination_not_the_base_destination() {
    let segment = addr("2001:db8:a::1");
    let final_destination = addr("2001:db8:c::1");
    let mut udp = vec![0; 8 + 12];
    udp[8..].fill(0x5a);
    encode_udp(
        addr(SOURCE).into(),
        final_destination.into(),
        4000,
        53,
        &mut udp,
        12,
    )
    .unwrap();
    let header = srh(1, 1, &[final_destination, segment], &[]);
    let p = packet_to(segment, &[(43, &header)], PROTOCOL_UDP, &udp);
    let chain = Chain::quote(&p).unwrap();
    assert_eq!(chain.destination(), segment);
    let resolved = chain.final_destination().unwrap();
    assert_eq!(resolved, final_destination);
    let upper = &p[chain.header_len()..];
    assert!(parse_udp(addr(SOURCE).into(), resolved.into(), upper).is_ok());
    assert_eq!(
        pseudo_header_checksum(addr(SOURCE).into(), resolved.into(), PROTOCOL_UDP, upper),
        Ok(0)
    );
    assert_eq!(
        parse_udp(addr(SOURCE).into(), segment.into(), upper).unwrap_err(),
        Error::Checksum
    );
}

#[test]
fn fragment_position_boundary_and_later_fragment_opacity() {
    let dest = options(&[]);
    let route = routing(4, 0, &[0; 20]);
    // Unfragmentable part: Destination Options, Routing. Fragmentable part:
    // Destination Options for the final destination, then UDP.
    let first = fragment(0, true, 0x0102_0304);
    let p = packet(
        &[(60, &dest), (43, &route), (44, &first), (60, &dest)],
        17,
        &[0; 8],
    );
    let parsed = parse_fragment(&p).unwrap();
    let f = parsed.chain.fragment().unwrap();
    assert_eq!(
        (f.offset, f.selector, f.next_header, f.data()),
        (72, 48, 60, 80)
    );
    assert_eq!(
        (f.identification, f.more_fragments, f.fragment_offset),
        (0x0102_0304, true, 0)
    );
    assert_eq!(parsed.header, &p[..80]);
    assert_eq!(parsed.payload, &p[80..]);
    assert_eq!(parsed.protocol, 60);
    assert_eq!(
        (parsed.chain.protocol(), parsed.chain.header_len()),
        (17, 88)
    );
    assert_eq!(parsed.chain.completeness(), Completeness::InitialFragment);
    assert!(!parsed.base_layout());
    assert_eq!(parse(&p).unwrap_err(), Error::FragmentationUnsupported);
    // Options after the Fragment header belong to the reassembled packet:
    // they are framed here, not acted on; before it they are processed.
    let report = options(&[0x9e, 0]);
    let p = packet(&[(44, &first), (60, &report)], 17, &[0; 8]);
    assert_eq!(parse_fragment(&p).unwrap().chain.header_len(), 56);
    let p = packet(&[(60, &report), (44, &first)], 17, &[0; 8]);
    assert_eq!(
        Chain::receive(&p).unwrap_err(),
        Fault::Option {
            pointer: 42,
            action: OptionAction::Report
        }
    );
    // RFC 7112: in a complete initial fragment a post-Fragment header must
    // lie within it; an atomic fragment overrunning is just impossible.
    let mut cut = packet(&[(44, &first), (60, &options(&[0; 13]))], 59, &[]);
    cut.truncate(56);
    cut[4..6].copy_from_slice(&16u16.to_be_bytes());
    assert_eq!(Chain::receive(&cut).unwrap_err(), Fault::IncompleteChain);
    cut[43] &= !1;
    assert_eq!(
        Chain::receive(&cut).unwrap_err(),
        Fault::Length { pointer: 49 }
    );
    // A later fragment's data is opaque, whatever it looks like.
    let later = fragment(1232, false, 7);
    for next in [0, 43, 44, 60, 6, 17] {
        let p = packet(&[(60, &dest), (44, &later)], next, &[0xff; 3]);
        let parsed = parse_fragment(&p).unwrap();
        assert_eq!(parsed.chain.completeness(), Completeness::LaterFragment);
        assert_eq!((parsed.protocol, parsed.chain.protocol()), (next, next));
        assert_eq!(
            (parsed.chain.header_len(), parsed.payload),
            (56, &[0xff; 3][..])
        );
        assert_eq!(Chain::quote(&p[..56]).unwrap().header_len(), 56);
        assert_eq!(Chain::quote(&p[..55]).unwrap_err(), Fault::Truncated);
    }
}

// A refused chain's Fragment header is still found by generic framing (so a
// fragment of an abandoned datagram can be identified before its headers
// are processed); a broken length before it, or none at all, finds nothing.
#[test]
fn fragment_headers_are_located_by_framing_alone() {
    let first = fragment(0, true, 0x0102_0304);
    let report = options(&[0x9e, 0]);
    let segments = routing(4, 1, &[0; 4]);
    let pad = [0; 7];
    for (headers, offset) in [
        (vec![(60, &report[..]), (44, &first[..])], 48),
        (vec![(43, &segments[..]), (44, &first[..])], 48),
        (vec![(60, &pad[..]), (0, &pad[..]), (44, &first[..])], 56),
    ] {
        let p = packet(&headers, 17, &[0; 8]);
        assert!(Chain::receive(&p).is_err());
        let f = FragmentHeader::locate(&p).unwrap();
        assert_eq!(
            (f.offset, f.selector, f.identification, f.more_fragments),
            (offset, offset - 8, 0x0102_0304, true)
        );
    }
    let mut cut = packet(&[(44, &first), (60, &options(&[0; 13]))], 59, &[]);
    cut.truncate(56);
    cut[4..6].copy_from_slice(&16u16.to_be_bytes());
    assert_eq!(Chain::receive(&cut).unwrap_err(), Fault::IncompleteChain);
    assert_eq!(FragmentHeader::locate(&cut).unwrap().offset, 40);
    let mut broken = packet(&[(60, &report), (44, &first)], 17, &[0; 8]);
    broken[41] = 9;
    assert_eq!(FragmentHeader::locate(&broken), None);
    assert_eq!(FragmentHeader::locate(&broken[..47]), None);
    let unfragmented = packet(&[(60, &report)], 17, &[0; 8]);
    assert_eq!(FragmentHeader::locate(&unfragmented), None);
}
