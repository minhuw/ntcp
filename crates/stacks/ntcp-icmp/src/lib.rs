#![no_std]
use core::net::IpAddr;
use ntcp::IpMetadata;
pub use ntcp_ip_common::{Error, checksum};

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
    let (outer, protocol, icmp) = parse_outer(bytes)?;
    if icmp.len() < 8 {
        return Err(Error::Truncated);
    }
    let ipv6 = outer.source.is_ipv6();
    if protocol != if ipv6 { 58 } else { 1 } {
        return Err(Error::ProtocolUnsupported);
    }
    if if ipv6 {
        icmpv6_checksum(outer, icmp)?
    } else {
        checksum(icmp)
    } != 0
    {
        return Err(Error::Checksum);
    }
    let (kind, candidate_mtu) = if ipv6 {
        icmpv6_feedback(icmp)?
    } else {
        icmpv4_feedback(icmp)?
    };
    let quoted = quote(&icmp[8..], ipv6)?;
    // Error must be addressed back to the sender of the quoted transmission.
    if outer.destination != quoted.ip.source {
        return Err(Error::Quote);
    }
    Ok(Feedback {
        outer,
        kind,
        code: icmp[1],
        candidate_mtu,
        quoted,
    })
}
fn quote(b: &[u8], ipv6: bool) -> Result<TcpQuote, Error> {
    let (ip, header, total, protocol) = quote_header(b, ipv6)?;
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

fn quote_header(b: &[u8], ipv6: bool) -> Result<(IpMetadata, usize, usize, u8), Error> {
    let _ = b;
    match ipv6 {
        #[cfg(feature = "ipv6")]
        true => ntcp_ip6::quote_header(b),
        #[cfg(feature = "ipv4")]
        false => ntcp_ip::quote_header(b),
        #[allow(unreachable_patterns)]
        _ => Err(Error::Version),
    }
}

fn parse_outer(bytes: &[u8]) -> Result<(IpMetadata, u8, &[u8]), Error> {
    match bytes.first().ok_or(Error::Truncated)? >> 4 {
        #[cfg(feature = "ipv4")]
        4 => {
            let p = ntcp_ip::parse(bytes, false)?;
            Ok((p.ip, p.protocol, p.payload))
        }
        #[cfg(feature = "ipv6")]
        6 => {
            let p = ntcp_ip6::parse(bytes)?;
            Ok((p.ip, p.protocol, p.payload))
        }
        _ => Err(Error::Version),
    }
}

fn icmpv4_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
    Ok(match (icmp[0], icmp[1]) {
        (3, 4) => (
            FeedbackKind::PacketTooBig,
            match u16::from_be_bytes([icmp[6], icmp[7]]) {
                0 => None,
                mtu => Some(u32::from(mtu)),
            },
        ),
        (3, 0..=15) => (FeedbackKind::DestinationUnreachable, None),
        (11, 0..=1) => (FeedbackKind::TimeExceeded, None),
        (12, 0..=2) => (FeedbackKind::ParameterProblem, None),
        _ => return Err(Error::ProtocolUnsupported),
    })
}

fn icmpv6_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
    Ok(match (icmp[0], icmp[1]) {
        (1, 0..=7) => (FeedbackKind::DestinationUnreachable, None),
        (3, 0..=1) => (FeedbackKind::TimeExceeded, None),
        (4, 0..=2) => (FeedbackKind::ParameterProblem, None),
        (2, 0) => (
            FeedbackKind::PacketTooBig,
            Some(u32::from_be_bytes(
                icmp[4..8].try_into().map_err(|_| Error::Truncated)?,
            )),
        ),
        _ => return Err(Error::ProtocolUnsupported),
    })
}

pub fn icmpv6_checksum(ip: IpMetadata, bytes: &[u8]) -> Result<u16, Error> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (ip.source, ip.destination) else {
        return Err(Error::Version);
    };
    let len = u32::try_from(bytes.len()).map_err(|_| Error::Length)?;
    let mut pseudo = [0; 40];
    pseudo[..16].copy_from_slice(&source.octets());
    pseudo[16..32].copy_from_slice(&destination.octets());
    pseudo[32..36].copy_from_slice(&len.to_be_bytes());
    pseudo[39] = 58;
    let mut sum = u32::from(!checksum(&pseudo)) + u32::from(!checksum(bytes));
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Ok(!(sum as u16))
}
