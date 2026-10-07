#![no_std]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ntcp::{IpMetadata, Ipv4Options, Transmit};

pub const IPV4_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;
const IP_HEADER: usize = IPV4_HEADER;

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
        4 => {
            let (header, total) = ipv4_bounds(bytes)?;
            if bytes[8] == 0 {
                return Err(Error::Invalid);
            }
            if total != bytes.len() {
                return Err(Error::Length);
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
            //# When received options are passed up to TCP from the IP layer, a TCP
            //# implementation MUST ignore options that it does not understand (MUST-
            //# 50).
            let options = Ipv4Options::parse(&bytes[20..header], source_routes_enabled)
                .map_err(|_| Error::Options)?;
            Ok(Packet {
                ip: IpMetadata {
                    source: v4(&bytes[12..16]).into(),
                    destination: v4(&bytes[16..20]).into(),
                },
                traffic_class: bytes[1],
                hop_limit: bytes[8],
                protocol: bytes[9],
                ipv4_options: options,
                payload: &bytes[header..],
            })
        }
        6 => {
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
                ipv4_options: Ipv4Options::default(),
                payload: &bytes[40..],
            })
        }
        _ => Err(Error::Version),
    }
}
fn v4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}
fn v6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0; 16];
    a.copy_from_slice(b);
    a.into()
}
fn ipv4_bounds(b: &[u8]) -> Result<(usize, usize), Error> {
    if b.len() < 20 {
        return Err(Error::Truncated);
    }
    if b[0] >> 4 != 4 {
        return Err(Error::Version);
    }
    let header = usize::from(b[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if header < 20 || total < header {
        return Err(Error::Length);
    }
    if b.len() < header {
        return Err(Error::Truncated);
    }
    if u16::from_be_bytes([b[6], b[7]]) & !0x4000 != 0 {
        return Err(Error::FragmentationUnsupported);
    }
    if checksum(&b[..header]) != 0 {
        return Err(Error::Checksum);
    }
    // ICMP quotes can contain the expired packet that triggered the error.
    // Live-packet hop-limit policy is enforced by parse, not structural bounds.
    Ok((header, total))
}
fn ipv6_bounds(b: &[u8]) -> Result<usize, Error> {
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

// TCP payload must already occupy bytes[20..] or bytes[40..]. IPv4 options
// shift it in-place; TCP's checksum uses Transmit.ip's logical final destination,
// not the first source-route hop encoded in the wire IP header.
pub fn encode(bytes: &mut [u8], transmit: Transmit, timestamp: u32) -> Result<usize, Error> {
    match transmit.ip.source {
        IpAddr::V4(_) => encode_ipv4(bytes, transmit, timestamp),
        IpAddr::V6(_) => encode_ipv6(bytes, transmit),
    }
}
fn encode_ipv4(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    timestamp: u32,
) -> Result<usize, Error> {
    let ntcp::Transmit {
        ip,
        len: tcp_len,
        hop_limit,
        dscp,
        ecn,
        ipv4_options,
        ..
    } = transmit;
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
        return Err(Error::Version);
    };
    let mut options = [0; 40];
    let (destination, option_len) = ipv4_options
        .encode(source, destination, timestamp, &mut options)
        .map_err(|_| Error::Options)?;
    let header_len = IP_HEADER + option_len;
    let total_len = tcp_len.checked_add(header_len).ok_or(Error::Length)?;
    if total_len > usize::from(u16::MAX) || total_len > packet.len() {
        return Err(Error::Length);
    }
    if hop_limit == 0 || dscp > 63 || ecn > 3 {
        return Err(Error::Invalid);
    }
    packet.copy_within(IP_HEADER..IP_HEADER + tcp_len, header_len);
    let header = &mut packet[..header_len];
    header.fill(0);
    header[0] = 0x40 | (header_len / 4) as u8;
    header[IP_HEADER..].copy_from_slice(&options[..option_len]);
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
    //# RFC 1122 allows that if a retransmitted packet is identical to the
    //# original packet (which implies not only that the data boundaries have
    //# not changed, but also that none of the headers have changed), then
    //# the same IPv4 Identification field MAY be used (see Section 3.2.1.5
    //# of RFC 1122) (MAY-4).
    // Atomic IPv4 datagrams need no unique ID (RFC 6864); ID remains zero.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
    //= reason=IPv4 example sets DF for all packets; ECN/DSCP matrix explicitly asserts DF and no fragment offset, including both ECT codepoints.
    //# ECN-capable packets MAY have the DF (Don't Fragment) bit set.
    header[6] = 0x40; // DF: this codec never fragments.

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
    //# configurable (MUST-49).
    header[8] = hop_limit;
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //# TCP implementations
    //# SHOULD pass the current Differentiated Services field value without
    //# change to the IP layer, when it sends segments on the connection
    //# (SHLD-22).
    header[1] = (dscp << 2) | (ecn & 3);
    header[9] = 6;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());
    let sum = checksum(header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(total_len)
}

fn encode_ipv6(packet: &mut [u8], transmit: ntcp::Transmit) -> Result<usize, Error> {
    let (IpAddr::V6(source), IpAddr::V6(destination)) =
        (transmit.ip.source, transmit.ip.destination)
    else {
        return Err(Error::Version);
    };
    let total = transmit.len.checked_add(IPV6_HEADER).ok_or(Error::Length)?;
    if transmit.len > usize::from(u16::MAX)
        || total > packet.len()
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
    Ok(total)
}

pub const ETHERNET_HEADER: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
#[derive(Clone, Copy, Debug)]
pub struct Ethernet<'a> {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: u16,
    pub payload: &'a [u8],
}
fn ethernet_payload(ether_type: u16, payload: &[u8]) -> Result<usize, Error> {
    match ether_type {
        ETHERTYPE_IPV4 => Ok(ipv4_bounds(payload)?.1),
        ETHERTYPE_IPV6 => ipv6_bounds(payload),
        0x8100 | 0x88a8 | 0x9100 => Err(Error::VlanUnsupported),
        _ => Err(Error::EtherTypeUnsupported),
    }
}
// Accept exact IP bounds or minimum-size Ethernet padding; caller strips FCS.
pub fn parse_ethernet(bytes: &[u8]) -> Result<Ethernet<'_>, Error> {
    if bytes.len() < ETHERNET_HEADER {
        return Err(Error::Truncated);
    }
    let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let payload = &bytes[14..];
    let total = ethernet_payload(ether_type, payload)?;
    if payload.len() < total {
        return Err(Error::Truncated);
    }
    if payload.len() != total && bytes.len() != (ETHERNET_HEADER + total).max(60) {
        return Err(Error::Length);
    }
    let payload = &payload[..total];
    let mut source = [0; 6];
    let mut destination = [0; 6];
    source.copy_from_slice(&bytes[6..12]);
    destination.copy_from_slice(&bytes[..6]);
    Ok(Ethernet {
        source,
        destination,
        ether_type,
        payload,
    })
}
pub fn encode_ethernet(
    out: &mut [u8],
    source: [u8; 6],
    destination: [u8; 6],
    ether_type: u16,
    payload: &[u8],
) -> Result<usize, Error> {
    if ethernet_payload(ether_type, payload)? != payload.len() {
        return Err(Error::Length);
    }
    let ip_end = payload
        .len()
        .checked_add(ETHERNET_HEADER)
        .ok_or(Error::Length)?;
    let total = ip_end.max(60);
    if out.len() < total {
        return Err(Error::Truncated);
    }
    out[..6].copy_from_slice(&destination);
    out[6..12].copy_from_slice(&source);
    out[12..14].copy_from_slice(&ether_type.to_be_bytes());
    out[ETHERNET_HEADER..ip_end].copy_from_slice(payload);
    out[ip_end..total].fill(0);
    Ok(total)
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
    let (kind, candidate_mtu) = match (ipv6, icmp[0], icmp[1]) {
        (false, 3, 4) => (
            FeedbackKind::PacketTooBig,
            match u16::from_be_bytes([icmp[6], icmp[7]]) {
                0 => None,
                mtu => Some(u32::from(mtu)),
            },
        ),
        (false, 3, 0..=15) | (true, 1, 0..=7) => (FeedbackKind::DestinationUnreachable, None),
        (false, 11, 0..=1) | (true, 3, 0..=1) => (FeedbackKind::TimeExceeded, None),
        (false, 12, 0..=2) | (true, 4, 0..=2) => (FeedbackKind::ParameterProblem, None),
        (true, 2, 0) => (
            FeedbackKind::PacketTooBig,
            Some(u32::from_be_bytes(
                icmp[4..8].try_into().map_err(|_| Error::Truncated)?,
            )),
        ),
        _ => return Err(Error::ProtocolUnsupported),
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
fn quote(b: &[u8], ipv6: bool) -> Result<TcpQuote, Error> {
    let (ip, header, total, protocol) = if ipv6 {
        let total = ipv6_bounds(b)?;
        (
            IpMetadata {
                source: v6(&b[8..24]).into(),
                destination: v6(&b[24..40]).into(),
            },
            40,
            total,
            b[6],
        )
    } else {
        let (header, total) = ipv4_bounds(b)?;
        let mut destination = v4(&b[16..20]);
        // Quotes can catch source-routed datagrams before their final hop. Core
        // options parse intentionally rejects unfinished routes, so validate a
        // bounded copy with its pointer completed and recover logical destination.
        let mut options = [0; 40];
        options[..header - 20].copy_from_slice(&b[20..header]);
        let mut offset = 0;
        while offset < header - 20 {
            let kind = options[offset];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                offset += 1;
                continue;
            }
            let len = usize::from(*options.get(offset + 1).ok_or(Error::Options)?);
            if len < 2 || len > header - 20 - offset {
                return Err(Error::Options);
            }
            if matches!(kind, 131 | 137) {
                if len < 3 || (len - 3) % 4 != 0 {
                    return Err(Error::Options);
                }
                let pointer = usize::from(options[offset + 2]);
                if pointer < 4 || (pointer <= len && (pointer - 4) % 4 != 0) {
                    return Err(Error::Options);
                }
                if pointer <= len {
                    destination = v4(&options[offset + len - 4..offset + len]);
                }
                options[offset + 2] = (len + 1) as u8;
            }
            offset += len;
        }
        Ipv4Options::parse(&options[..header - 20], true).map_err(|_| Error::Options)?;
        (
            IpMetadata {
                source: v4(&b[12..16]).into(),
                destination: destination.into(),
            },
            header,
            total,
            b[9],
        )
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
        source_port,
        destination_port,
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}
