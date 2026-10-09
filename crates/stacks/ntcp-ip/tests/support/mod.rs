#![allow(dead_code)]
use ntcp::{IpMetadata, OutgoingIpv4Options, Transmit};
use ntcp_ip_common::{Error, checksum};
pub fn tx(v6: bool, len: usize) -> Transmit {
    Transmit {
        connection: None,
        tx_timestamp: None,
        ip: IpMetadata {
            source: if v6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if v6 { "2001:db8::2" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
        },
        len,
        hop_limit: 64,
        dscp: 37,
        ecn: 3,
        ipv4_options: OutgoingIpv4Options::default(),
    }
}
pub fn seal(b: &mut [u8]) {
    b[10..12].fill(0);
    let sum = checksum(&b[..usize::from(b[0] & 15) * 4]);
    b[10..12].copy_from_slice(&sum.to_be_bytes());
}

pub fn encode(bytes: &mut [u8], t: Transmit, timestamp: u32) -> Result<usize, Error> {
    if t.ip.source.is_ipv6() {
        ntcp_ip6::encode(bytes, t)
    } else {
        ntcp_ip::encode(bytes, t, timestamp)
    }
}
// Test-only projection lets the original mixed-family assertions stay intact.
pub fn parse(bytes: &[u8], source_routes: bool) -> Result<ntcp_ip::Packet<'_>, Error> {
    if bytes.first().ok_or(Error::Truncated)? >> 4 == 6 {
        let p = ntcp_ip6::parse(bytes)?;
        Ok(ntcp_ip::Packet {
            ip: p.ip,
            traffic_class: p.traffic_class,
            hop_limit: p.hop_limit,
            protocol: p.protocol,
            ipv4_options: ntcp::Ipv4Options::default(),
            payload: p.payload,
        })
    } else {
        ntcp_ip::parse(bytes, source_routes)
    }
}
