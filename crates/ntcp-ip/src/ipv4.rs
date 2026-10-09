use core::net::{IpAddr, Ipv4Addr};
use ntcp::{IpMetadata, Ipv4Options};

use crate::{Error, FeedbackKind, IPV4_HEADER, Packet, checksum};

const IP_HEADER: usize = IPV4_HEADER;

pub(super) fn parse(bytes: &[u8], source_routes_enabled: bool) -> Result<Packet<'_>, Error> {
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
fn v4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}
pub(super) fn ipv4_bounds(b: &[u8]) -> Result<(usize, usize), Error> {
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
//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= reason=The IPv4 codec always sets DF; its ECN/DSCP matrix asserts 0x4000 with no fragment offset. Keeping DF is the selected TCP behavior, not optional clear-DF termination.
//# and sends all datagrams on that path with the DF bit set.

//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= reason=Enabled IPv4 PMTUD retains DF in the codec and reacts to validated lower-MTU feedback; zero-MTU and family-floor tests exercise decrease and bounded repair. This is not a claim about arbitrary external embeddings.
//# Normally, the host continues to set DF in all datagrams, so that if the route
//# changes and the new PMTU is lower, it will be discovered.

pub(super) fn encode_ipv4(
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

pub(super) fn quote_header(b: &[u8]) -> Result<(IpMetadata, usize, usize, u8), Error> {
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
    Ok((
        IpMetadata {
            source: v4(&b[12..16]).into(),
            destination: destination.into(),
        },
        header,
        total,
        b[9],
    ))
}

pub(super) fn icmp_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
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
