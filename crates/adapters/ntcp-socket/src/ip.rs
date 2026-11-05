// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use std::net::{IpAddr, Ipv6Addr};
pub(crate) fn header_len(ip: IpAddr) -> usize {
    if ip.is_ipv4() { 20 } else { 40 }
}
pub(crate) fn family(ip: IpAddr) -> i32 {
    if ip.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    }
}
pub(crate) fn ether_type(ip: IpAddr) -> u16 {
    if ip.is_ipv4() {
        ntcp_ethernet::ETHERTYPE_IPV4
    } else {
        ntcp_ethernet::ETHERTYPE_IPV6
    }
}
pub(crate) fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets()[0] != 0 && v.octets()[0] < 224 && !v.is_loopback(),
        IpAddr::V6(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_loopback()
                && !v.is_unicast_link_local()
                && v.to_ipv4_mapped().is_none()
        }
    }
}
pub(crate) fn network(ip: IpAddr, prefix: u8) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v) if prefix <= 32 => Some(
            std::net::Ipv4Addr::from(
                u32::from(v) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0),
            )
            .into(),
        ),
        IpAddr::V6(v) if prefix <= 128 => Some(
            std::net::Ipv6Addr::from(
                u128::from(v) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0),
            )
            .into(),
        ),
        _ => None,
    }
}
// IPv4 /31 and /32 subnets have no network or broadcast address to reserve.
pub(crate) fn network_or_broadcast(ip: IpAddr, prefix: u8) -> bool {
    match ip {
        IpAddr::V4(v) if prefix <= 30 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            let network = u32::from(v) & mask;
            u32::from(v) == network || u32::from(v) == network | !mask
        }
        _ => false,
    }
}
#[derive(Debug)]
pub(crate) struct Packet<'a> {
    pub ip: ntcp::IpMetadata,
    pub traffic_class: u8,
    pub protocol: u8,
    pub ipv4_options: ntcp::Ipv4Options,
    pub payload: &'a [u8],
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Packet<'_>, ntcp_ip_common::Error> {
    match bytes.first().ok_or(ntcp_ip_common::Error::Truncated)? >> 4 {
        4 => {
            let p = ntcp_ip::parse(bytes, false)?;
            Ok(Packet {
                ip: p.ip,
                traffic_class: p.traffic_class,
                protocol: p.protocol,
                // Every option except NOP and EOL reaches TCP as received.
                // This stateless parser serves host-less fixtures and does
                // no destination processing; source routes are rejected by
                // the codec above.
                ipv4_options: p.ipv4_options,
                payload: p.payload,
            })
        }
        6 => {
            let p = ntcp_ip6::parse(bytes)?;
            // Like the IPv4 branch, no destination processing happens here,
            // so only the base layout is accepted.
            if !p.base_layout() {
                return Err(ntcp_ip_common::Error::ExtensionsUnsupported);
            }
            Ok(Packet {
                ip: p.ip,
                traffic_class: p.traffic_class,
                protocol: p.protocol,
                ipv4_options: ntcp::Ipv4Options::default(),
                payload: p.payload,
            })
        }
        _ => Err(ntcp_ip_common::Error::Version),
    }
}
// `segments` S1..Sn of the IPv6 path's SR route (`Host::header_plan`) put
// a Segment Routing Header before the `present` resident TCP octets.
pub(crate) fn encode(
    bytes: &mut [u8],
    tx: ntcp::Transmit,
    segments: &[Ipv6Addr],
    timestamp: u32,
    present: usize,
) -> Result<usize, ntcp_ip_common::Error> {
    match (tx.ip.source.is_ipv4(), present == tx.len) {
        (true, true) => ntcp_ip::encode(bytes, tx, timestamp),
        (true, false) => ntcp_ip::encode_shared_header(bytes, tx, timestamp, present),
        (false, _) => ntcp_ip6::encode_tcp_routed(bytes, tx, segments, present),
    }
}

#[cfg(test)]
mod tests {
    // The codec walks extension chains, but this parser does no destination
    // processing: only the base layout passes.
    #[test]
    fn hostless_parser_refuses_extension_bearing_ipv6() {
        let mut base = vec![0; 60];
        base[..8].copy_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        base[23] = 1;
        base[39] = 2;
        assert_eq!(super::parse(&base).unwrap().payload.len(), 20);
        let mut extended = base[..40].to_vec();
        extended.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
        extended.extend_from_slice(&base[40..]);
        extended[5] = 28;
        extended[6] = 60;
        assert!(ntcp_ip6::parse(&extended).is_ok());
        assert_eq!(
            super::parse(&extended).unwrap_err(),
            ntcp_ip_common::Error::ExtensionsUnsupported
        );
    }
}
