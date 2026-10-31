#![no_std]
use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;

pub use ntcp_ip_common::{Error, PROTOCOL_TCP, PROTOCOL_UDP, UDP_HEADER};
pub const IPV6_HEADER: usize = 40;

/// Per-packet IPv6 send parameters shared by every upper-layer protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub ip: IpMetadata,
    pub hop_limit: u8,
    pub dscp: u8,
    pub ecn: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub payload: &'a [u8],
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= reason=For base selector 59, empty and positive-length packets expose no transport payload after exact declared-bound checks; the borrowed input bytes and quoted length/protocol remain intact. Extension traversal and forwarding remain outside the existing endpoint scope.
//# The value 59 in the Next Header field of an IPv6 header or any
//# extension header indicates that there is nothing following that
//# header. If the Payload Length field of the IPv6 header indicates the
//# presence of octets past the end of a header whose Next Header field
//# contains 59, those octets must be ignored and passed on unchanged if
//# the packet is forwarded.

//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//= reason=This destination codec preserves all Hop Limit values, including zero, while checking structure and declared length. Forwarding and decrement rules remain outside the existing endpoint scope; originating parameter policy is unchanged.
//# Hop Limit 8-bit unsigned integer. Decremented by 1 by each node that
//# forwards the packet. When forwarding, the packet is discarded if Hop
//# Limit was zero when received or is decremented to zero. A node that is
//# the destination of a packet should not discard a packet with Hop Limit
//# equal to zero; it should process the packet normally.
pub fn parse(bytes: &[u8]) -> Result<Packet<'_>, Error> {
    let total = ipv6_bounds(bytes)?;
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
        // No Next Header hides the declared tail from transport consumers.
        // The borrowed input and its declared bounds remain intact.
        payload: if bytes[6] == 59 {
            &bytes[40..40]
        } else {
            &bytes[40..]
        },
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
//= reason=Declared base-packet length is 40 plus the full unsigned 16-bit field, including zero; complete frames require exact bounds and checked quotes retain the original length when truncated. Extension headers, including Jumbo Payload options, remain explicitly unsupported under the existing scope.
//# Payload Length 16-bit unsigned integer. Length of the IPv6 payload,
//# i.e., the rest of the packet following this IPv6 header, in octets.
//# (Note that any extension headers (see Section 4) present are considered
//# part of the payload, i.e., included in the length count.)
pub fn ipv6_bounds(b: &[u8]) -> Result<usize, Error> {
    if b.len() < 40 {
        return Err(Error::Truncated);
    }
    if b[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    let payload = usize::from(u16::from_be_bytes([b[4], b[5]]));
    // Zero is also the length of a legal empty base packet. Jumbo Payload
    // options require Hop-by-Hop processing, which remains unsupported below.
    upper_layer(b[6])?;
    Ok(40 + payload)
}

// This codec neither traverses nor emits extension headers.
fn upper_layer(next_header: u8) -> Result<(), Error> {
    match next_header {
        44 => Err(Error::FragmentationUnsupported),
        0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 => Err(Error::ExtensionsUnsupported),
        _ => Ok(()),
    }
}

pub fn encode(packet: &mut [u8], transmit: ntcp::Transmit) -> Result<usize, Error> {
    encode_tcp(packet, transmit, transmit.len)
}

/// Encode the base header for `len` upper-layer bytes of `next_header` already
/// resident at `packet[IPV6_HEADER..]`. Extension header selectors are refused
/// because none is emitted. Returns the packet length.
pub fn encode_datagram(
    packet: &mut [u8],
    header: Header,
    next_header: u8,
    len: usize,
) -> Result<usize, Error> {
    upper_layer(next_header).map_err(|_| Error::Invalid)?;
    encode_present(packet, header, next_header, len, len)
}

/// Encode a checksummed UDP datagram whose `payload_len` data bytes are
/// resident at `packet[IPV6_HEADER + UDP_HEADER..]`. Returns the packet length.
/// The payload is never modified; on error only header bytes may be.
pub fn encode_udp(
    packet: &mut [u8],
    header: Header,
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
) -> Result<usize, Error> {
    let len = ntcp_ip_common::encode_udp(
        header.ip.source,
        header.ip.destination,
        source_port,
        destination_port,
        packet.get_mut(IPV6_HEADER..).ok_or(Error::Length)?,
        payload_len,
    )?;
    encode_datagram(packet, header, PROTOCOL_UDP, len)
}

// TCP compatibility: a Transmit has no IPv6 meaning for IPv4 options or for an
// empty segment, so both remain invalid exactly as before.
fn encode_tcp(packet: &mut [u8], transmit: ntcp::Transmit, present: usize) -> Result<usize, Error> {
    if !transmit.ip.source.is_ipv6() || !transmit.ip.destination.is_ipv6() {
        return Err(Error::Version);
    }
    transmit.len.checked_add(IPV6_HEADER).ok_or(Error::Length)?;
    if transmit.len == 0 || transmit.ipv4_options != ntcp::OutgoingIpv4Options::default() {
        return Err(Error::Invalid);
    }
    let header = Header {
        ip: transmit.ip,
        hop_limit: transmit.hop_limit,
        dscp: transmit.dscp,
        ecn: transmit.ecn,
    };
    encode_present(packet, header, PROTOCOL_TCP, transmit.len, present)
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
    encode_tcp(packet, transmit, present_tcp_len)
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
    params: Header,
    next_header: u8,
    len: usize,
    present: usize,
) -> Result<usize, Error> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (params.ip.source, params.ip.destination)
    else {
        return Err(Error::Version);
    };
    if len > usize::from(u16::MAX)
        || present > len
        || present
            .checked_add(IPV6_HEADER)
            .is_none_or(|n| n > packet.len())
        || params.hop_limit == 0
        || params.dscp > 63
        || params.ecn > 3
    {
        return Err(Error::Invalid);
    }
    let header = &mut packet[..IPV6_HEADER];
    header.fill(0);
    let class = (params.dscp << 2) | params.ecn;
    header[0] = 0x60 | (class >> 4);
    header[1] = class << 4;
    header[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    header[6] = next_header;
    header[7] = params.hop_limit;
    header[8..24].copy_from_slice(&source.octets());
    header[24..40].copy_from_slice(&destination.octets());
    Ok(IPV6_HEADER + present)
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
