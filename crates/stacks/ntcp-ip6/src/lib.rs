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
