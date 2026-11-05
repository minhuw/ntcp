#![no_std]
use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;

pub use ntcp_ip_common::ipv6::{
    Chain, Completeness, ExtensionHeader, Fault, FragmentHeader, OptionAction,
};
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

/// A received packet whose extension headers, if any, passed receive
/// processing (`Chain::receive`). `ip.destination` is the base Destination
/// Address, which is also the final destination: a Routing header with
/// Segments Left above zero is refused.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub chain: Chain<'a>,
}

impl Packet<'_> {
    /// True when the upper layer directly follows the base header, the only
    /// layout accepted by receivers without extension header processing.
    pub fn base_layout(&self) -> bool {
        self.chain.header_len() == IPV6_HEADER && upper_layer(self.protocol).is_ok()
    }
}

//= https://www.rfc-editor.org/rfc/rfc8200#section-4.7
//= reason=Selector 59 in the base header or any traversed extension header ends the chain after exact declared-bound checks: no transport payload is exposed and the borrowed input bytes and quoted length/protocol remain intact. Forwarding remains outside the existing endpoint scope.
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
    let chain = receive(bytes)?;
    if chain.fragment().is_some() {
        return Err(Error::FragmentationUnsupported);
    }
    let upper = chain.header_len();
    Ok(Packet {
        ip: metadata(bytes),
        traffic_class: (bytes[0] << 4) | (bytes[1] >> 4),
        hop_limit: bytes[7],
        protocol: chain.protocol(),
        // No Next Header hides the declared tail from transport consumers.
        // The borrowed input and its declared bounds remain intact.
        payload: if chain.protocol() == ntcp_ip_common::ipv6::NO_NEXT_HEADER {
            &bytes[upper..upper]
        } else {
            &bytes[upper..]
        },
        chain,
    })
}

// A complete received packet: exactly the declared length, then the chain
// with its receive processing.
fn receive(bytes: &[u8]) -> Result<Chain<'_>, Error> {
    if bytes.len() < IPV6_HEADER {
        return Err(Error::Truncated);
    }
    if bytes[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    if IPV6_HEADER + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) != bytes.len() {
        return Err(Error::Length);
    }
    Ok(Chain::receive(bytes)?)
}

fn metadata(bytes: &[u8]) -> IpMetadata {
    IpMetadata {
        source: v6(&bytes[8..24]).into(),
        destination: v6(&bytes[24..40]).into(),
    }
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
//= reason=Declared packet length is 40 plus the full unsigned 16-bit field, including zero, and bounds every extension header, which is counted inside it; complete frames require exact bounds and checked quotes retain the original length when truncated. Jumbo Payload options remain unsupported and are refused as unrecognized options.
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

// The upper layer an encoder places after the base header, or after the
// Segment Routing Header of `encode_routed` (the only extension header
// originated besides the Fragmenter's); this link framing passes only the
// base layout (with at most a direct Fragment header below); `parse`
// traverses received chains.
fn upper_layer(next_header: u8) -> Result<(), Error> {
    match next_header {
        44 => Err(Error::FragmentationUnsupported),
        0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 => Err(Error::ExtensionsUnsupported),
        _ => Ok(()),
    }
}

pub fn encode(packet: &mut [u8], transmit: ntcp::Transmit) -> Result<usize, Error> {
    encode_tcp(packet, transmit, &[], transmit.len)
}

/// `encode` (`present == transmit.len`) or `encode_shared_header` over an SR
/// route of `segments` (see `encode_routed`): the `present` TCP octets,
/// checksummed with the final destination `transmit.ip.destination`, are
/// resident at `packet[header_len(segments)..]`.
pub fn encode_tcp_routed(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    segments: &[Ipv6Addr],
    present: usize,
) -> Result<usize, Error> {
    if present != transmit.len {
        shared_header(transmit, present)?;
    }
    encode_tcp(packet, transmit, segments, present)
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
    encode_routed(packet, header, &[], next_header, len)
}

// Most segments an originated Segment Routing Header lists besides the
// final destination: its 8-bit Hdr Ext Len counts the 16-octet entries in
// 8-octet units after the first 8 octets (RFC 8200 4.4), so 2(n + 1) <= 255.
// Route configuration enforces the same bound (`ntcp_path::check_segment_route`).
const MAX_SEGMENTS: usize = 126;

/// The complete IPv6 header length H of a packet sent over `segments`
/// S1..Sn: the base header alone without segments, else the base header
/// plus a Segment Routing Header of n + 1 entries (8 + 16(n + 1) octets).
pub fn header_len(segments: &[Ipv6Addr]) -> Result<usize, Error> {
    match segments.len() {
        0 => Ok(IPV6_HEADER),
        n if n <= MAX_SEGMENTS => Ok(IPV6_HEADER + srh_len(n)),
        _ => Err(Error::Length),
    }
}

fn srh_len(segments: usize) -> usize {
    8 + 16 * (segments + 1)
}

/// `encode_datagram` over an SR route of `segments` S1..Sn (none: no
/// extension header): `header.ip.destination` is the final destination D,
/// the `len` upper-layer bytes are resident at `packet[header_len(segments)..]`
/// and checksummed with D. The base Destination Address is S1 and a
/// Segment Routing Header follows the base header (`write_srh`). Returns
/// the packet length.
pub fn encode_routed(
    packet: &mut [u8],
    header: Header,
    segments: &[Ipv6Addr],
    next_header: u8,
    len: usize,
) -> Result<usize, Error> {
    upper_layer(next_header).map_err(|_| Error::Invalid)?;
    encode_unfragmentable(packet, header, segments, next_header, len, len)
}

// The base header and any Segment Routing Header, for `len` octets after
// them of which `present` are resident.
fn encode_unfragmentable(
    packet: &mut [u8],
    header: Header,
    segments: &[Ipv6Addr],
    next_header: u8,
    len: usize,
    present: usize,
) -> Result<usize, Error> {
    let srh = header_len(segments)? - IPV6_HEADER;
    if srh == 0 {
        return encode_present(packet, header, next_header, len, present);
    }
    let IpAddr::V6(destination) = header.ip.destination else {
        return Err(Error::Version);
    };
    let (Some(payload), Some(resident)) = (len.checked_add(srh), present.checked_add(srh)) else {
        return Err(Error::Invalid);
    };
    let base = Header {
        ip: IpMetadata {
            destination: IpAddr::V6(segments[0]),
            ..header.ip
        },
        ..header
    };
    encode_present(packet, base, ntcp_ip_common::ipv6::ROUTING, payload, resident)?;
    write_srh(&mut packet[IPV6_HEADER..IPV6_HEADER + srh], next_header, segments, destination);
    Ok(IPV6_HEADER + resident)
}

// The SR source node's header for segments S1..Sn and final destination D
// (RFC 8754 2, 4.1 and 6.1): Routing Type 4, the full list of m = n + 1
// entries in reverse order (Segment List[0] = D, Segment List[i] =
// S(n + 1 - i)), Segments Left and Last Entry n, so the base Destination
// Address S1 is Segment List[Segments Left]; Flags and Tag zero, no TLVs.
fn write_srh(srh: &mut [u8], next_header: u8, segments: &[Ipv6Addr], destination: Ipv6Addr) {
    let n = segments.len();
    srh[0] = next_header;
    srh[1] = (2 * (n + 1)) as u8;
    srh[2] = 4;
    srh[3] = n as u8;
    srh[4] = n as u8;
    srh[5..8].fill(0);
    srh[8..24].copy_from_slice(&destination.octets());
    for (i, segment) in segments.iter().rev().enumerate() {
        let at = 24 + 16 * i;
        srh[at..at + 16].copy_from_slice(&segment.octets());
    }
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
    encode_udp_routed(packet, header, &[], source_port, destination_port, payload_len)
}

/// `encode_udp` over an SR route of `segments` (see `encode_routed`): the
/// payload is resident at `packet[header_len(segments) + UDP_HEADER..]` and
/// the checksum covers the final destination `header.ip.destination`.
pub fn encode_udp_routed(
    packet: &mut [u8],
    header: Header,
    segments: &[Ipv6Addr],
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
) -> Result<usize, Error> {
    let len = ntcp_ip_common::encode_udp(
        header.ip.source,
        header.ip.destination,
        source_port,
        destination_port,
        packet.get_mut(header_len(segments)?..).ok_or(Error::Length)?,
        payload_len,
    )?;
    encode_routed(packet, header, segments, PROTOCOL_UDP, len)
}

// TCP compatibility: a Transmit has no IPv6 meaning for IPv4 options or for an
// empty segment, so both remain invalid exactly as before.
fn encode_tcp(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    segments: &[Ipv6Addr],
    present: usize,
) -> Result<usize, Error> {
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
    encode_unfragmentable(packet, header, segments, PROTOCOL_TCP, transmit.len, present)
}

// Encode only the resident header. Payload ranges remain owned by PacketIo.
pub fn encode_shared_header(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    present_tcp_len: usize,
) -> Result<usize, Error> {
    shared_header(transmit, present_tcp_len)?;
    encode_tcp(packet, transmit, &[], present_tcp_len)
}

// A resident TCP header without its shared payload.
fn shared_header(transmit: ntcp::Transmit, present_tcp_len: usize) -> Result<(), Error> {
    if !(20..=60).contains(&present_tcp_len)
        || !present_tcp_len.is_multiple_of(4)
        || present_tcp_len > transmit.len
    {
        return Err(Error::Length);
    }
    Ok(())
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

// Checked quoted header of an unfragmented packet: returns metadata with the
// final destination, the complete header chain length, the original packet
// length, and the upper-layer protocol. Expired hop limits are valid in error
// quotes.
//= https://www.rfc-editor.org/rfc/rfc8200#section-3
//# Next Header 8-bit selector. Identifies the type of header immediately
//# following the IPv6 header. Uses the same values as the IPv4 Protocol
//# field [IANA-PN].
pub fn quote_header(b: &[u8]) -> Result<(IpMetadata, usize, usize, u8), Error> {
    let (ip, chain) = quote_fragment_header(b)?;
    if chain.fragment().is_some() {
        return Err(Error::FragmentationUnsupported);
    }
    Ok((ip, chain.header_len(), chain.declared_len(), chain.protocol()))
}

pub use ntcp_ip_common::ipv6::FRAGMENT_HEADER;
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

/// One received IPv6 packet, possibly a fragment. Without a Fragment header
/// it equals `parse`, and `header` is the complete header chain. With one,
/// only the unfragmentable part (the headers before the Fragment header)
/// has had receive processing; `protocol` is the Fragment header's Next
/// Header, `header` the unfragmentable part plus the Fragment header, and
/// `payload` the fragment's data, which is opaque unless `fragment.offset`
/// is zero. Fragment zero's headers after the Fragment header are framed by
/// `chain` and must lie within it (RFC 7112).
#[derive(Clone, Copy, Debug)]
pub struct FragmentPacket<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub fragment: Option<Fragment>,
    pub header: &'a [u8],
    pub payload: &'a [u8],
    pub chain: Chain<'a>,
}

impl FragmentPacket<'_> {
    /// True for the base layout, optionally with a Fragment header directly
    /// after the base header whose fragment at offset zero continues with
    /// the upper layer: the only layout accepted by receivers without
    /// extension header processing.
    pub fn base_layout(&self) -> bool {
        let fragment = if self.fragment.is_some() {
            FRAGMENT_HEADER
        } else {
            0
        };
        self.header.len() == IPV6_HEADER + fragment
            && self.chain.header_len() == self.header.len()
            && (self.chain.completeness() == Completeness::LaterFragment
                || upper_layer(self.chain.protocol()).is_ok())
    }
}

/// Parse a received packet whose chain may hold a Fragment header.
pub fn parse_fragment(bytes: &[u8]) -> Result<FragmentPacket<'_>, Error> {
    let chain = receive(bytes)?;
    let Some(f) = chain.fragment() else {
        let packet = parse(bytes)?;
        return Ok(FragmentPacket {
            ip: packet.ip,
            traffic_class: packet.traffic_class,
            hop_limit: packet.hop_limit,
            protocol: packet.protocol,
            fragment: None,
            header: &bytes[..chain.header_len()],
            payload: packet.payload,
            chain,
        });
    };
    Ok(FragmentPacket {
        ip: metadata(bytes),
        traffic_class: (bytes[0] << 4) | (bytes[1] >> 4),
        hop_limit: bytes[7],
        protocol: f.next_header,
        fragment: Some(fragment(f)),
        header: &bytes[..f.data()],
        payload: &bytes[f.data()..],
        chain,
    })
}

fn fragment(f: FragmentHeader) -> Fragment {
    Fragment {
        next_header: f.next_header,
        identification: f.identification,
        more_fragments: f.more_fragments,
        offset: f.fragment_offset,
    }
}

/// Physical framing of one IPv6 packet for a receiver with extension header
/// and fragment processing: the base header's version and the complete
/// packet length. The header chain is not examined here, so a complete
/// packet whose extension headers are malformed or refused still reaches
/// the receiver, which owns their receive actions and errors (RFC 8200
/// section 4); only a packet shorter than its base header is refused.
pub fn ipv6_fragment_bounds(b: &[u8]) -> Result<usize, Error> {
    if b.len() < IPV6_HEADER {
        return Err(Error::Truncated);
    }
    if b[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    Ok(IPV6_HEADER + usize::from(u16::from_be_bytes([b[4], b[5]])))
}

/// A quoted packet's chain (`Chain::quote`) with its source and final
/// destination. A quote whose final destination is unresolved cannot be
/// attributed and is refused.
pub fn quote_fragment_header(b: &[u8]) -> Result<(IpMetadata, Chain<'_>), Error> {
    let chain = Chain::quote(b)?;
    let destination = chain.final_destination().ok_or(Error::Quote)?;
    Ok((
        IpMetadata {
            source: v6(&b[8..24]).into(),
            destination: destination.into(),
        },
        chain,
    ))
}

/// Source fragmentation of one complete IPv6 packet (RFC 8200 section 4.5).
/// The unfragmentable part is the base header, followed on an SR route by
/// its Segment Routing Header (`encode_routed`), and every fragment repeats
/// it before the Fragment header; `header.ip.destination` is the final
/// destination, so the upper-layer checksum the caller computed over the
/// complete datagram stays valid. The fragmentable part's header must be
/// the upper layer itself, entirely in the first fragment's data.
#[derive(Clone, Copy, Debug)]
pub struct Fragmenter<'a> {
    header: Header,
    segments: &'a [Ipv6Addr],
    next_header: u8,
    identification: u32,
    data_len: u16,
}

impl Fragmenter<'static> {
    /// `data_len` is the complete upper-layer length; the original packet's
    /// Payload Length is limited to 65535 like any non-jumbo packet.
    pub fn new(
        header: Header,
        next_header: u8,
        identification: u32,
        data_len: usize,
    ) -> Result<Self, Error> {
        Fragmenter::routed(header, &[], next_header, identification, data_len)
    }
}

impl<'a> Fragmenter<'a> {
    /// `new` over an SR route of `segments` S1..Sn; the original packet's
    /// Payload Length, which counts its Segment Routing Header, is limited
    /// to 65535.
    pub fn routed(
        header: Header,
        segments: &'a [Ipv6Addr],
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
        let srh = header_len(segments)? - IPV6_HEADER;
        data_len
            .checked_add(srh)
            .filter(|n| *n <= usize::from(u16::MAX))
            .ok_or(Error::Length)?;
        Ok(Self {
            header,
            segments,
            next_header,
            identification,
            data_len: u16::try_from(data_len).map_err(|_| Error::Length)?,
        })
    }

    /// Octets before each fragment's data: the unfragmentable part and the
    /// Fragment header.
    pub fn header_len(&self) -> usize {
        // `routed` checked the segment count.
        header_len(self.segments).unwrap_or(IPV6_HEADER) + FRAGMENT_HEADER
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
            .checked_sub(self.header_len())
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
        let header = self.header_len();
        let len = header + data.len();
        if len > packet.len() {
            return Err(Error::Length);
        }
        let unfragmentable = header - FRAGMENT_HEADER;
        encode_unfragmentable(
            packet,
            self.header,
            self.segments,
            NEXT_HEADER_FRAGMENT,
            FRAGMENT_HEADER + data.len(),
            0,
        )?;
        let f = &mut packet[unfragmentable..header];
        f[0] = self.next_header;
        f[1] = 0;
        f[2..4].copy_from_slice(&(offset as u16 | u16::from(more)).to_be_bytes());
        f[4..8].copy_from_slice(&self.identification.to_be_bytes());
        packet[header..len].copy_from_slice(data);
        Ok(len)
    }
}
