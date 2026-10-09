use core::net::{IpAddr, Ipv6Addr};
use ntcp::{IpMetadata, Ipv4Options};

use crate::{Error, FeedbackKind, IPV6_HEADER, Packet, checksum};

pub(super) fn parse(bytes: &[u8]) -> Result<Packet<'_>, Error> {
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
fn v6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0; 16];
    a.copy_from_slice(b);
    a.into()
}
pub(super) fn ipv6_bounds(b: &[u8]) -> Result<usize, Error> {
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

pub(super) fn encode_ipv6(packet: &mut [u8], transmit: ntcp::Transmit) -> Result<usize, Error> {
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
pub(super) fn quote_header(b: &[u8]) -> Result<(IpMetadata, usize, usize, u8), Error> {
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

pub(super) fn icmp_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
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
