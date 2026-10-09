#![no_std]
mod ethernet;
mod ipv4;
mod ipv6;
pub mod path_mtu;

use core::net::IpAddr;
pub use ethernet::{
    ETHERNET_HEADER, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Ethernet, encode_ethernet, parse_ethernet,
};
pub use ipv6::icmpv6_checksum;
use ntcp::{IpMetadata, Ipv4Options, Transmit};

pub const IPV4_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Length,
    Version,
    Checksum,
    FragmentationUnsupported,
    ExtensionsUnsupported,
    JumbogramsUnsupported,
    Options,
    Invalid,
    VlanUnsupported,
    EtherTypeUnsupported,
    ProtocolUnsupported,
    Quote,
}

// Folding each word avoids overflow even for caller-provided large slices.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub ipv4_options: Ipv4Options,
    pub payload: &'a [u8],
}

// Complete IP frames only: no trailing bytes, reassembly, IPv6 extensions or
// jumbograms. Address/interface policy and recording options belong to callers.
pub fn parse(bytes: &[u8], source_routes_enabled: bool) -> Result<Packet<'_>, Error> {
    match bytes.first().ok_or(Error::Truncated)? >> 4 {
        4 => ipv4::parse(bytes, source_routes_enabled),
        6 => ipv6::parse(bytes),
        _ => Err(Error::Version),
    }
}

// TCP payload must already occupy bytes[20..] or bytes[40..]. IPv4 options
// shift it in-place; TCP's checksum uses Transmit.ip's logical final destination,
// not the first source-route hop encoded in the wire IP header.
pub fn encode(bytes: &mut [u8], transmit: Transmit, timestamp: u32) -> Result<usize, Error> {
    match transmit.ip.source {
        IpAddr::V4(_) => ipv4::encode_ipv4(bytes, transmit, timestamp),
        IpAddr::V6(_) => ipv6::encode_ipv6(bytes, transmit),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackKind {
    DestinationUnreachable,
    TimeExceeded,
    ParameterProblem,
    PacketTooBig,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpQuote {
    pub ip: IpMetadata,
    pub ip_packet_len: u32,
    pub ip_header_len: u16,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback {
    pub outer: IpMetadata,
    pub kind: FeedbackKind,
    pub code: u8,
    // Untrusted candidate only; caller must correlate tuple/sequence with a
    // live transmission and apply path policy. This is not autonomous PMTUD.
    pub candidate_mtu: Option<u32>,
    pub quoted: TcpQuote,
}

// Decode a complete outer IP frame; the inner IP frame may be a partial quote,
// but must contain its entire header and at least TCP's ports and sequence.
//= https://www.rfc-editor.org/rfc/rfc1191#section-4
//= reason=Decoded quote length is complete original IP length, not quoted byte count or Ethernet frame size; no router-generation claim.
//# The size includes the IP header and IP data, and does not include any lower-level
//# headers.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.3
//= reason=Informational rationale: outer source may be a router, not the peer. Runtime fixture sends PTB from10.73.0.1 for peer10.73.0.3; quoted tuple/live sequence and checksums still gate acceptance.
//# The source address of ICMP error messages does not need to be spoofed to perform the
//# attacks described in this document, as the ICMP error messages might legitimately come
//# from an intermediate system.
pub fn decode_icmp(bytes: &[u8]) -> Result<Feedback, Error> {
    let outer = parse(bytes, false)?;
    let icmp = outer.payload;
    if icmp.len() < 8 {
        return Err(Error::Truncated);
    }
    let ipv6 = outer.ip.source.is_ipv6();
    if outer.protocol != if ipv6 { 58 } else { 1 } {
        return Err(Error::ProtocolUnsupported);
    }
    if if ipv6 {
        icmpv6_checksum(outer.ip, icmp)?
    } else {
        checksum(icmp)
    } != 0
    {
        return Err(Error::Checksum);
    }
    let (kind, candidate_mtu) = if ipv6 {
        ipv6::icmp_feedback(icmp)?
    } else {
        ipv4::icmp_feedback(icmp)?
    };
    let quoted = quote(&icmp[8..], ipv6)?;
    // Error must be addressed back to the sender of the quoted transmission.
    if outer.ip.destination != quoted.ip.source {
        return Err(Error::Quote);
    }
    Ok(Feedback {
        outer: outer.ip,
        kind,
        code: icmp[1],
        candidate_mtu,
        quoted,
    })
}
fn quote(b: &[u8], ipv6: bool) -> Result<TcpQuote, Error> {
    let (ip, header, total, protocol) = if ipv6 {
        ipv6::quote_header(b)?
    } else {
        ipv4::quote_header(b)?
    };
    if protocol != 6 || total < header + 20 || b.len() < header + 8 || b.len() > total {
        return Err(Error::Quote);
    }
    let tcp = &b[header..];
    let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if source_port == 0 || destination_port == 0 {
        return Err(Error::Quote);
    }
    Ok(TcpQuote {
        ip,
        ip_packet_len: total as u32,
        ip_header_len: header as u16,
        source_port,
        destination_port,
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}
