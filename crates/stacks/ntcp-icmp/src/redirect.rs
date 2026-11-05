// ICMP Redirect reception (RFC 792; RFC 1122 section 3.2.2.2) and ICMPv6
// Redirect reception (RFC 4861 sections 4.5, 4.6.3 and 8.1) for Ethernet
// links. Redirects are only ever received: nothing here encodes one.
use crate::{Error, ND_HOP_LIMIT, Quote, checksum, icmpv6_checksum, quote};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ntcp::IpMetadata;

const IPV4_REDIRECT: u8 = 5;
const IPV6_REDIRECT: u8 = 137;
const TARGET_LINK_LAYER: u8 = 2;
const REDIRECTED_HEADER: u8 = 4;
// Type, code, checksum, reserved, Target and Destination Address.
const IPV6_FIXED: usize = 40;
// A link-layer address option on Ethernet: type, length 1 and a 6-octet MAC.
const LINK_LAYER_OPTION: usize = 8;
// The Redirected Header option's type, length and six reserved octets
// precede the quoted packet.
const REDIRECTED_PREFIX: usize = 8;
const IPV6_HEADER: usize = 40;

/// The four IPv4 Redirect codes (RFC 792).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectCode {
    Network,
    Host,
    NetworkAndTos,
    HostAndTos,
}

impl RedirectCode {
    /// Whether the Redirect applies only to traffic with the quoted
    /// datagram's type of service.
    pub const fn type_of_service(self) -> bool {
        matches!(self, Self::NetworkAndTos | Self::HostAndTos)
    }
}

/// A validated IPv4 Redirect: its code, the new gateway and the quoted
/// datagram, which was sent by the Redirect's destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Redirect {
    pub code: RedirectCode,
    pub gateway: Ipv4Addr,
    pub quoted: Quote,
}

/// A validated ICMPv6 Redirect. `redirected` is a usable Redirected Header
/// option: its quote, sent by the Redirect's destination, and the option
/// itself, whose quoted packet starts at offset 8 as an ICMP error's does
/// (any padding after that packet removed). It is None when the option is absent or its quote is unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Redirect<'a> {
    pub target: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub target_link_layer: Option<[u8; 6]>,
    pub redirected: Option<(Quote, &'a [u8])>,
}

/// Validate a complete ICMP message received for `outer.destination` as an
/// IPv4 Redirect: at least the 8-octet header, a valid checksum, one of the
/// four codes, and a quote of a datagram sent from the Redirect's
/// destination. Any other ICMP type is ProtocolUnsupported.
pub fn decode_ipv4_redirect(outer: IpMetadata, message: &[u8]) -> Result<Ipv4Redirect, Error> {
    if !outer.source.is_ipv4() || !outer.destination.is_ipv4() {
        return Err(Error::Version);
    }
    if *message.first().ok_or(Error::Truncated)? != IPV4_REDIRECT {
        return Err(Error::ProtocolUnsupported);
    }
    if message.len() < 8 {
        return Err(Error::Truncated);
    }
    if checksum(message) != 0 {
        return Err(Error::Checksum);
    }
    let code = match message[1] {
        0 => RedirectCode::Network,
        1 => RedirectCode::Host,
        2 => RedirectCode::NetworkAndTos,
        3 => RedirectCode::HostAndTos,
        _ => return Err(Error::Invalid),
    };
    let quoted = quote(&message[8..], false)?;
    if quoted.ip.source != outer.destination {
        return Err(Error::Quote);
    }
    Ok(Ipv4Redirect {
        code,
        gateway: Ipv4Addr::from(<[u8; 4]>::try_from(&message[4..8]).unwrap()),
        quoted,
    })
}

/// Validate a complete ICMPv6 message received from `ip.source` for
/// `ip.destination` with IP Hop Limit `hop_limit` as a Redirect (RFC 4861
/// section 8.1): a link-local source, Hop Limit 255, a valid checksum, code
/// 0, at least the fixed 40 octets, a non-multicast Destination Address, a
/// Target Address that is link-local or the Destination Address, and
/// options of positive length within the message. The Target Link-Layer
/// Address option must have the Ethernet length and appear at most once;
/// other options are ignored except the Redirected Header, which may appear
/// at most once. The target is not checked against any on-link prefix.
/// Any other ICMPv6 type is ProtocolUnsupported.
pub fn decode_ipv6_redirect(
    ip: IpMetadata,
    hop_limit: u8,
    message: &[u8],
) -> Result<Ipv6Redirect<'_>, Error> {
    let IpAddr::V6(source) = ip.source else {
        return Err(Error::Version);
    };
    if !ip.destination.is_ipv6() {
        return Err(Error::Version);
    }
    if *message.first().ok_or(Error::Truncated)? != IPV6_REDIRECT {
        return Err(Error::ProtocolUnsupported);
    }
    if message.len() < IPV6_FIXED {
        return Err(Error::Truncated);
    }
    if hop_limit != ND_HOP_LIMIT || message[1] != 0 || !source.is_unicast_link_local() {
        return Err(Error::Invalid);
    }
    if icmpv6_checksum(ip, message)? != 0 {
        return Err(Error::Checksum);
    }
    let address = |at: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&message[at..at + 16]).unwrap());
    let (target, destination) = (address(8), address(24));
    if destination.is_multicast() || !(target.is_unicast_link_local() || target == destination) {
        return Err(Error::Invalid);
    }
    let (mut target_link_layer, mut header) = (None, None);
    let mut options = &message[IPV6_FIXED..];
    while !options.is_empty() {
        let len = usize::from(*options.get(1).ok_or(Error::Options)?) * 8;
        if len == 0 || len > options.len() {
            return Err(Error::Options);
        }
        match options[0] {
            TARGET_LINK_LAYER => {
                if len != LINK_LAYER_OPTION || target_link_layer.is_some() {
                    return Err(Error::Options);
                }
                target_link_layer = Some(<[u8; 6]>::try_from(&options[2..8]).unwrap());
            }
            REDIRECTED_HEADER => {
                if header.is_some() {
                    return Err(Error::Options);
                }
                header = Some(&options[..len]);
            }
            _ => {}
        }
        options = &options[len..];
    }
    // A quote that cannot be parsed, or of a packet another node sent,
    // names no submission of this receiver. A sender may zero-pad a quoted
    // packet that does not end on the option's 8-octet boundary (BSD
    // routers do; the original size is the quoted header's), so fewer than
    // 8 octets beyond the quoted packet's declared length are padding.
    let redirected = header.and_then(|option| {
        let option = match option.get(REDIRECTED_PREFIX + 4..REDIRECTED_PREFIX + 6) {
            Some(payload) if option[REDIRECTED_PREFIX] >> 4 == 6 => {
                let declared = REDIRECTED_PREFIX
                    + IPV6_HEADER
                    + usize::from(u16::from_be_bytes([payload[0], payload[1]]));
                if declared < option.len() && option.len() - declared < 8 {
                    &option[..declared]
                } else {
                    option
                }
            }
            _ => option,
        };
        let quoted = quote(&option[REDIRECTED_PREFIX..], true).ok()?;
        (quoted.ip.source == ip.destination).then_some((quoted, option))
    });
    Ok(Ipv6Redirect {
        target,
        destination,
        target_link_layer,
        redirected,
    })
}
