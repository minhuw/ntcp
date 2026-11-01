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

// The atomic codec neither traverses nor emits extension headers; only the
// fragment API below handles a Fragment header after the base header.
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

/// Length of the Fragment header (RFC 8200 section 4.5).
pub const FRAGMENT_HEADER: usize = 8;
const NEXT_HEADER_FRAGMENT: u8 = 44;

/// Fields of an IPv6 Fragment header (RFC 8200 section 4.5). Its reserved
/// field and bits are ignored on receive and sent as zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragment {
    /// The Fragment header's Next Header. It selects the reconstructed upper
    /// layer only in the fragment at offset zero; in a later fragment it is
    /// opaque and may differ (RFC 8200 section 4.5).
    pub next_header: u8,
    pub identification: u32,
    pub more_fragments: bool,
    /// Position of this fragment's data in octets (a multiple of 8).
    pub offset: u16,
}

/// One received IPv6 packet: base header, optionally followed by a Fragment
/// header. Without one, it equals `parse`. With one, `protocol` is the
/// Fragment header's Next Header and `payload` the fragment's data, which is
/// opaque unless `fragment.offset` is zero. `header` is the unfragmentable
/// part plus the Fragment header, as received.
#[derive(Clone, Copy, Debug)]
pub struct FragmentPacket<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub fragment: Option<Fragment>,
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

/// Parse base -> Fragment -> upper layer. Only fragment zero names the
/// upper layer, which, like `parse`, must not be an extension header; other
/// extension chains remain unsupported.
pub fn parse_fragment(bytes: &[u8]) -> Result<FragmentPacket<'_>, Error> {
    let (total, fragment) = fragment_bounds(bytes)?;
    if total != bytes.len() {
        return Err(Error::Length);
    }
    let Some(fragment) = fragment else {
        let packet = parse(bytes)?;
        return Ok(FragmentPacket {
            ip: packet.ip,
            traffic_class: packet.traffic_class,
            hop_limit: packet.hop_limit,
            protocol: packet.protocol,
            fragment: None,
            header: &bytes[..IPV6_HEADER],
            payload: packet.payload,
        });
    };
    let header = IPV6_HEADER + FRAGMENT_HEADER;
    Ok(FragmentPacket {
        ip: IpMetadata {
            source: v6(&bytes[8..24]).into(),
            destination: v6(&bytes[24..40]).into(),
        },
        traffic_class: (bytes[0] << 4) | (bytes[1] >> 4),
        hop_limit: bytes[7],
        protocol: fragment.next_header,
        fragment: Some(fragment),
        header: &bytes[..header],
        payload: &bytes[header..],
    })
}

// Validate the base header and, when present, the Fragment header; returns
// the declared packet length. Fragment zero's Next Header follows the same
// selector rule as the base header (an atomic fragment's data is the whole
// datagram); a later fragment's is not interpreted.
/// `ipv6_bounds` for a base header optionally followed by a Fragment header:
/// the complete packet length. Link framing uses it to delimit packets that
/// reassembly accepts.
pub fn ipv6_fragment_bounds(b: &[u8]) -> Result<usize, Error> {
    Ok(fragment_bounds(b)?.0)
}

fn fragment_bounds(b: &[u8]) -> Result<(usize, Option<Fragment>), Error> {
    if b.len() < IPV6_HEADER {
        return Err(Error::Truncated);
    }
    if b[6] != NEXT_HEADER_FRAGMENT {
        return Ok((ipv6_bounds(b)?, None));
    }
    if b[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    let payload = usize::from(u16::from_be_bytes([b[4], b[5]]));
    if payload < FRAGMENT_HEADER {
        return Err(Error::Length);
    }
    let f = b
        .get(IPV6_HEADER..IPV6_HEADER + FRAGMENT_HEADER)
        .ok_or(Error::Truncated)?;
    let field = u16::from_be_bytes([f[2], f[3]]);
    let fragment = Fragment {
        next_header: f[0],
        identification: u32::from_be_bytes([f[4], f[5], f[6], f[7]]),
        more_fragments: field & 1 != 0,
        offset: field & !7,
    };
    if fragment.offset == 0 {
        upper_layer(fragment.next_header).map_err(|_| Error::ExtensionsUnsupported)?;
    }
    Ok((IPV6_HEADER + payload, Some(fragment)))
}

/// `quote_header` for a quoted packet that may carry a Fragment header; the
/// header length then includes it and the protocol is its Next Header.
pub fn quote_fragment_header(
    b: &[u8],
) -> Result<(IpMetadata, usize, usize, u8, Option<Fragment>), Error> {
    let (total, fragment) = fragment_bounds(b)?;
    let (header, protocol) = match fragment {
        Some(f) => (IPV6_HEADER + FRAGMENT_HEADER, f.next_header),
        None => (IPV6_HEADER, b[6]),
    };
    Ok((
        IpMetadata {
            source: v6(&b[8..24]).into(),
            destination: v6(&b[24..40]).into(),
        },
        header,
        total,
        protocol,
        fragment,
    ))
}

/// Source fragmentation of one complete IPv6 packet into base -> Fragment ->
/// fragment data (RFC 8200 section 4.5). The unfragmentable part is the base
/// header alone: no Routing header is emitted, so the destination is both the
/// header and the final destination and the upper-layer checksum the caller
/// computed over the complete datagram stays valid. The fragmentable part's
/// header must be the upper layer itself.
#[derive(Clone, Copy, Debug)]
pub struct Fragmenter {
    header: Header,
    next_header: u8,
    identification: u32,
    data_len: u16,
}

impl Fragmenter {
    /// `data_len` is the complete upper-layer length; the original packet's
    /// Payload Length is limited to 65535 like any non-jumbo packet.
    pub fn new(
        header: Header,
        next_header: u8,
        identification: u32,
        data_len: usize,
    ) -> Result<Self, Error> {
        let (IpAddr::V6(_), IpAddr::V6(_)) = (header.ip.source, header.ip.destination) else {
            return Err(Error::Version);
        };
        upper_layer(next_header).map_err(|_| Error::Invalid)?;
        if header.hop_limit == 0 || header.dscp > 63 || header.ecn > 3 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            header,
            next_header,
            identification,
            data_len: u16::try_from(data_len).map_err(|_| Error::Length)?,
        })
    }

    /// Data octets of the fragment starting at `offset` within packets of at
    /// most `packet_limit` octets: all remaining data if it fits, otherwise
    /// the largest multiple of 8.
    pub fn fragment_len(&self, offset: usize, packet_limit: usize) -> Result<usize, Error> {
        let remaining = usize::from(self.data_len)
            .checked_sub(offset)
            .filter(|n| *n != 0 && offset.is_multiple_of(8))
            .ok_or(Error::Invalid)?;
        let room = packet_limit
            .checked_sub(IPV6_HEADER + FRAGMENT_HEADER)
            .ok_or(Error::Length)?;
        if remaining <= room {
            return Ok(remaining);
        }
        match room & !7 {
            0 => Err(Error::Length),
            len => Ok(len),
        }
    }

    /// Write the fragment holding `data`, the complete upper-layer bytes at
    /// `offset`, into `packet`; returns the packet length. Atomic fragments
    /// (one fragment holding everything) are never originated (RFC 8021,
    /// adopted by RFC 8200 section 5): such a packet is sent unfragmented.
    pub fn encode(&self, packet: &mut [u8], offset: usize, data: &[u8]) -> Result<usize, Error> {
        let end = offset.checked_add(data.len()).ok_or(Error::Length)?;
        let total = usize::from(self.data_len);
        let more = end < total;
        if data.is_empty()
            || end > total
            || !offset.is_multiple_of(8)
            || (more && !data.len().is_multiple_of(8))
            || (offset == 0 && !more)
        {
            return Err(Error::Invalid);
        }
        let header = IPV6_HEADER + FRAGMENT_HEADER;
        let len = header + data.len();
        if len > packet.len() {
            return Err(Error::Length);
        }
        encode_present(
            packet,
            self.header,
            NEXT_HEADER_FRAGMENT,
            FRAGMENT_HEADER + data.len(),
            0,
        )?;
        let f = &mut packet[IPV6_HEADER..header];
        f[0] = self.next_header;
        f[1] = 0;
        f[2..4].copy_from_slice(&(offset as u16 | u16::from(more)).to_be_bytes());
        f[4..8].copy_from_slice(&self.identification.to_be_bytes());
        packet[header..len].copy_from_slice(data);
        Ok(len)
    }
}
