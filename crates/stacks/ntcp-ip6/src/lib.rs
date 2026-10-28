#![no_std]
use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;

pub use ntcp_ip_common::Error;
pub const IPV6_HEADER: usize = 40;

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub payload: &'a [u8],
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= reason=Live parse rejects Hop Limit zero as Invalid although the destination rule says to process it normally; checked quote parsing accepts zero. Tests pin zero rejection and positive 1/64/255 preservation. The whole receive obligation remains unresolved; forwarding/decrement behavior is outside the base endpoint codec and does not excuse the destination difference. Encoding also rejects zero; no production fix is authorized.
//# Hop Limit 8-bit unsigned integer. Decremented by 1 by each node that
//# forwards the packet. When forwarding, the packet is discarded if Hop
//# Limit was zero when received or is decremented to zero. A node that is
//# the destination of a packet should not discard a packet with Hop Limit
//# equal to zero; it should process the packet normally.
pub fn parse(bytes: &[u8]) -> Result<Packet<'_>, Error> {
    let total = ipv6_bounds(bytes)?;
    if bytes[7] == 0 {
        return Err(Error::Invalid);
    }
    if total != bytes.len() {
        return Err(Error::Length);
    }
    Ok(Packet {
        ip: IpMetadata {
            source: v6(&bytes[8..24]).into(),
            destination: v6(&bytes[24..40]).into(),
        },
        traffic_class: (bytes[0] << 4) | (bytes[1] >> 4),
        hop_limit: bytes[7],
        protocol: bytes[6],
        payload: &bytes[40..],
    })
}
fn v6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0; 16];
    a.copy_from_slice(b);
    a.into()
}
// Validate a complete header; declared packet length may exceed the supplied
// bytes for ICMP quotes. Callers must check it before slicing packet data.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Version 4-bit Internet Protocol version number = 6.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= reason=Positive lengths through 65535 and checked truncated quotes are implemented, but ipv6_bounds rejects every zero Payload Length as JumbogramsUnsupported, including a bare No Next Header packet without a Jumbo Payload option. Zero alone is not evidence of a jumbogram. Preserve the entire field definition including its extension-header qualification; extension processing remains an explicit unsupported boundary, not a justification for rejecting legal empty base packets.
//# Payload Length 16-bit unsigned integer. Length of the IPv6 payload,
//# i.e., the rest of the packet following this IPv6 header, in octets.
//# (Note that any extension headers (see Section 4) present are considered
//# part of the payload, i.e., included in the length count.)
//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= reason=A zero-length base packet with selector 59 is rejected as JumbogramsUnsupported. With a positive length, the codec exposes selector 59 and uninterpreted trailing bytes; this alone does not establish the entire ignore obligation. Tests pin both boundaries. Extension-header traversal and forwarding are outside this endpoint codec, but legal empty base packets remain a selected-scope gap.
//# The value 59 in the Next Header field of an IPv6 header or any
//# extension header indicates that there is nothing following that
//# header. If the Payload Length field of the IPv6 header indicates the
//# presence of octets past the end of a header whose Next Header field
//# contains 59, those octets must be ignored and passed on unchanged if
//# the packet is forwarded.
pub fn ipv6_bounds(b: &[u8]) -> Result<usize, Error> {
    if b.len() < 40 {
        return Err(Error::Truncated);
    }
    if b[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    let payload = usize::from(u16::from_be_bytes([b[4], b[5]]));
    if payload == 0 {
        return Err(Error::JumbogramsUnsupported);
    }
    match b[6] {
        44 => return Err(Error::FragmentationUnsupported),
        0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 => return Err(Error::ExtensionsUnsupported),
        _ => {}
    }
    Ok(40 + payload)
}

pub fn encode(packet: &mut [u8], transmit: ntcp::Transmit) -> Result<usize, Error> {
    encode_present(packet, transmit, transmit.len)
}

// Encode only the resident header. Payload ranges remain owned by PacketIo.
pub fn encode_shared_header(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    present_tcp_len: usize,
) -> Result<usize, Error> {
    if !(20..=60).contains(&present_tcp_len)
        || !present_tcp_len.is_multiple_of(4)
        || present_tcp_len > transmit.len
    {
        return Err(Error::Length);
    }
    encode_present(packet, transmit, present_tcp_len)
}
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Traffic Class 8-bit Traffic Class field. See Section 7.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Flow Label 20-bit flow label. See Section 6.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Source Address 128-bit address of the originator of the packet. See
//# [RFC4291].
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Destination Address 128-bit address of the intended recipient of the
//# packet (possibly not the ultimate recipient, if a Routing header is
//# present). See [RFC4291] and Section 4.4.
fn encode_present(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    present_tcp_len: usize,
) -> Result<usize, Error> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) =
        (transmit.ip.source, transmit.ip.destination)
    else {
        return Err(Error::Version);
    };
    transmit.len.checked_add(IPV6_HEADER).ok_or(Error::Length)?;
    if transmit.len > usize::from(u16::MAX)
        || present_tcp_len > transmit.len
        || present_tcp_len
            .checked_add(IPV6_HEADER)
            .is_none_or(|n| n > packet.len())
        || transmit.len == 0
        || transmit.hop_limit == 0
        || transmit.dscp > 63
        || transmit.ecn > 3
        || transmit.ipv4_options != ntcp::OutgoingIpv4Options::default()
    {
        return Err(Error::Invalid);
    }
    let header = &mut packet[..IPV6_HEADER];
    header.fill(0);
    let class = (transmit.dscp << 2) | transmit.ecn;
    header[0] = 0x60 | (class >> 4);
    header[1] = class << 4;
    header[4..6].copy_from_slice(&(transmit.len as u16).to_be_bytes());
    header[6] = 6;
    header[7] = transmit.hop_limit;
    header[8..24].copy_from_slice(&source.octets());
    header[24..40].copy_from_slice(&destination.octets());
    Ok(IPV6_HEADER + present_tcp_len)
}

// Checked quoted header: returns metadata, header length, original packet
// length, and protocol. Expired hop limits are valid in error quotes.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Next Header 8-bit selector. Identifies the type of header immediately
//# following the IPv6 header. Uses the same values as the IPv4 Protocol
//# field [IANA-PN].
pub fn quote_header(b: &[u8]) -> Result<(IpMetadata, usize, usize, u8), Error> {
    let total = ipv6_bounds(b)?;
    Ok((
        IpMetadata {
            source: v6(&b[8..24]).into(),
            destination: v6(&b[24..40]).into(),
        },
        40,
        total,
        b[6],
    ))
}
