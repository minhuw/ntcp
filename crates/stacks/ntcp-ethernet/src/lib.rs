#![no_std]
pub use ntcp_ip_common::Error;

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
    ip_payload(ether_type, payload, false)
}
// The IP packet's length; `fragments` also delimits IPv4 fragments and any
// physically complete IPv6 packet, whose extension headers (a Fragment
// header included) the receiving host processes.
fn ip_payload(ether_type: u16, payload: &[u8], fragments: bool) -> Result<usize, Error> {
    let _ = (payload, fragments);
    match ether_type {
        #[cfg(feature = "ipv4")]
        ETHERTYPE_IPV4 if fragments => Ok(ntcp_ip::ipv4_fragment_bounds(payload)?.1),
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
/// a fragment, which the IP layer validates and reassembles. IPv6 packets
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
