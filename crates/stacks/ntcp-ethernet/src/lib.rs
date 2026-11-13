#![no_std]
use core::net::Ipv6Addr;
pub use ntcp_ip_common::Error;

pub const ETHERNET_HEADER: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// The Address Resolution Protocol (RFC 826). The IP parsers above refuse
/// it; `parse_ethernet_arp` and `encode_ethernet_arp` carry its frames.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// The broadcast Ethernet address, to which ARP requests are sent.
pub const BROADCAST: [u8; 6] = [0xff; 6];
#[derive(Clone, Copy, Debug)]
pub struct Ethernet<'a> {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: u16,
    pub payload: &'a [u8],
}
fn ethernet_payload(ether_type: u16, payload: &[u8]) -> Result<usize, Error> {
    ip_payload(ether_type, payload, false)
}
// The IP packet's length; `fragments` also delimits IPv4 fragments and any
// physically complete IPv6 packet, whose extension headers (a Fragment
// header included) the receiving host processes. The receiving host's IP
// layer verifies the IPv4 header checksum (`ntcp_ip::parse_fragment`),
// once per packet as Linux's ip_rcv_core, so its framing does not.
fn ip_payload(ether_type: u16, payload: &[u8], fragments: bool) -> Result<usize, Error> {
    let _ = (payload, fragments);
    match ether_type {
        #[cfg(feature = "ipv4")]
        ETHERTYPE_IPV4 if fragments => Ok(ntcp_ip::ipv4_received_bounds(payload)?.1),
        #[cfg(feature = "ipv4")]
        ETHERTYPE_IPV4 => Ok(ntcp_ip::ipv4_bounds(payload)?.1),
        #[cfg(feature = "ipv6")]
        ETHERTYPE_IPV6 if fragments => ntcp_ip6::ipv6_fragment_bounds(payload),
        #[cfg(feature = "ipv6")]
        ETHERTYPE_IPV6 => ntcp_ip6::ipv6_bounds(payload),
        0x8100 | 0x88a8 | 0x9100 => Err(Error::VlanUnsupported),
        _ => Err(Error::EtherTypeUnsupported),
    }
}
// Accept exact IP bounds or minimum-size Ethernet padding; caller strips FCS.
pub fn parse_ethernet(bytes: &[u8]) -> Result<Ethernet<'_>, Error> {
    frame(bytes, false)
}
/// `parse_ethernet` for a host that reassembles: the IP packet may also be
/// a fragment, which the IP layer validates, its IPv4 header checksum
/// included, and reassembles. IPv6 packets
/// are framed by their base header alone, so extension headers that carry
/// policy or length faults reach the host's receive processing and its
/// errors; only physical truncation is refused here.
pub fn parse_ethernet_fragment(bytes: &[u8]) -> Result<Ethernet<'_>, Error> {
    frame(bytes, true)
}
fn frame(bytes: &[u8], fragments: bool) -> Result<Ethernet<'_>, Error> {
    if bytes.len() < ETHERNET_HEADER {
        return Err(Error::Truncated);
    }
    let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let payload = &bytes[14..];
    let total = ip_payload(ether_type, payload, fragments)?;
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
    write_frame(out, source, destination, ether_type, payload)
}

/// An untagged ARP frame: its addresses and everything after the header.
/// The payload keeps any minimum-frame padding, which the ARP body's own
/// fixed layout delimits; this layer knows no ARP hardware or protocol
/// lengths. A VLAN tag is unsupported here as on the IP path.
pub fn parse_ethernet_arp(bytes: &[u8]) -> Result<Ethernet<'_>, Error> {
    if bytes.len() < ETHERNET_HEADER {
        return Err(Error::Truncated);
    }
    let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    match ether_type {
        ETHERTYPE_ARP => {}
        0x8100 | 0x88a8 | 0x9100 => return Err(Error::VlanUnsupported),
        _ => return Err(Error::EtherTypeUnsupported),
    }
    let mut source = [0; 6];
    let mut destination = [0; 6];
    source.copy_from_slice(&bytes[6..12]);
    destination.copy_from_slice(&bytes[..6]);
    Ok(Ethernet {
        source,
        destination,
        ether_type,
        payload: &bytes[ETHERNET_HEADER..],
    })
}

/// An ARP frame carrying the encoded ARP body `payload`, padded to the
/// 60-octet minimum as `encode_ethernet` pads.
pub fn encode_ethernet_arp(
    out: &mut [u8],
    source: [u8; 6],
    destination: [u8; 6],
    payload: &[u8],
) -> Result<usize, Error> {
    write_frame(out, source, destination, ETHERTYPE_ARP, payload)
}

fn write_frame(
    out: &mut [u8],
    source: [u8; 6],
    destination: [u8; 6],
    ether_type: u16,
    payload: &[u8],
) -> Result<usize, Error> {
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

/// The link-local all-nodes multicast group, ff02::1 (RFC 4291 section
/// 2.7.1), to which Neighbor Discovery sends advertisements answering a
/// solicitation from the unspecified address (RFC 4861 section 7.2.4).
pub const IPV6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// The solicited-node multicast group of `address` (RFC 4291 section
/// 2.7.1): ff02::1:ff00:0/104 followed by the address's low-order 24 bits.
/// Address resolution solicits it (RFC 4861 section 7.2.2) and every node
/// joins it for each of its unicast addresses, tentative ones included
/// (RFC 4862 section 5.4.2).
pub fn solicited_node(address: Ipv6Addr) -> Ipv6Addr {
    let [.., a, b, c] = address.octets();
    Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a, b, c])
}

/// The Ethernet destination of an IPv6 multicast packet: 33:33 followed by
/// the group's low-order 32 bits (RFC 2464 section 7); None for a
/// non-multicast address, which needs a resolved neighbor instead.
pub fn ipv6_multicast_mac(group: Ipv6Addr) -> Option<[u8; 6]> {
    let [.., a, b, c, d] = group.octets();
    group.is_multicast().then_some([0x33, 0x33, a, b, c, d])
}
