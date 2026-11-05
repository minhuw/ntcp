// Neighbor Solicitation and Advertisement (RFC 4861 sections 4.3, 4.4, 4.6.1
// and 7.1) for Ethernet links, whose link-layer address options are 8 octets
// (RFC 2464 section 6).
use crate::{Error, icmpv6_checksum};
use core::net::{IpAddr, Ipv6Addr};
use ntcp::IpMetadata;

/// Every Neighbor Discovery message is sent, and accepted, with this Hop
/// Limit: a received one proves it was not forwarded (RFC 4861 section 3.1).
pub const ND_HOP_LIMIT: u8 = 255;
const SOLICITATION: u8 = 135;
const ADVERTISEMENT: u8 = 136;
const SOURCE_LINK_LAYER: u8 = 1;
const TARGET_LINK_LAYER: u8 = 2;
// Type, code, checksum, a 32-bit flags or reserved word and the target.
const FIXED: usize = 24;
// A link-layer address option on Ethernet: type, length 1 and a 6-octet MAC.
const LINK_LAYER_OPTION: usize = 8;

/// A validated Neighbor Solicitation. `source_link_layer` is its Source
/// Link-Layer Address option; one from the unspecified address (Duplicate
/// Address Detection) never carries one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborSolicitation {
    pub target: Ipv6Addr,
    pub source_link_layer: Option<[u8; 6]>,
}

/// A validated Neighbor Advertisement; `solicited` is never set on one sent
/// to a multicast destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborAdvertisement {
    pub router: bool,
    pub solicited: bool,
    pub override_: bool,
    pub target: Ipv6Addr,
    pub target_link_layer: Option<[u8; 6]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborMessage {
    Solicitation(NeighborSolicitation),
    Advertisement(NeighborAdvertisement),
}

fn v6(address: IpAddr) -> Result<Ipv6Addr, Error> {
    match address {
        IpAddr::V6(address) => Ok(address),
        IpAddr::V4(_) => Err(Error::Version),
    }
}

fn solicited_node_group(address: Ipv6Addr) -> bool {
    address.octets()[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
}

/// Validate a complete ICMPv6 message received from `ip.source` for
/// `ip.destination` with IP Hop Limit `hop_limit` as a Neighbor Solicitation
/// or Advertisement (RFC 4861 sections 7.1.1 and 7.1.2): Hop Limit 255, a
/// valid checksum, code 0, at least the fixed length, a non-multicast target
/// and options of positive length within the message. A solicitation from
/// the unspecified address must be sent to a solicited-node group without a
/// Source Link-Layer Address option; an advertisement to a multicast
/// destination must not be solicited. Reserved fields and options this
/// message does not use are ignored (RFC 4861 section 4.6), while the one
/// it uses must have the Ethernet length, and may appear at most once since
/// two would state contradictory mappings. Any other ICMPv6 type is
/// ProtocolUnsupported.
pub fn decode_neighbor(
    ip: IpMetadata,
    hop_limit: u8,
    message: &[u8],
) -> Result<NeighborMessage, Error> {
    let (source, destination) = (v6(ip.source)?, v6(ip.destination)?);
    let kind = *message.first().ok_or(Error::Truncated)?;
    if kind != SOLICITATION && kind != ADVERTISEMENT {
        return Err(Error::ProtocolUnsupported);
    }
    if message.len() < FIXED {
        return Err(Error::Truncated);
    }
    if hop_limit != ND_HOP_LIMIT || message[1] != 0 {
        return Err(Error::Invalid);
    }
    if icmpv6_checksum(ip, message)? != 0 {
        return Err(Error::Checksum);
    }
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&message[8..FIXED]).unwrap());
    if target.is_multicast() {
        return Err(Error::Invalid);
    }
    let used = if kind == SOLICITATION {
        SOURCE_LINK_LAYER
    } else {
        TARGET_LINK_LAYER
    };
    let mut link_layer = None;
    let mut options = &message[FIXED..];
    while !options.is_empty() {
        let len = usize::from(*options.get(1).ok_or(Error::Options)?) * 8;
        if len == 0 || len > options.len() {
            return Err(Error::Options);
        }
        if options[0] == used {
            if len != LINK_LAYER_OPTION || link_layer.is_some() {
                return Err(Error::Options);
            }
            link_layer = Some(<[u8; 6]>::try_from(&options[2..8]).unwrap());
        }
        options = &options[len..];
    }
    if kind == SOLICITATION {
        if source.is_unspecified() && (!solicited_node_group(destination) || link_layer.is_some()) {
            return Err(Error::Invalid);
        }
        return Ok(NeighborMessage::Solicitation(NeighborSolicitation {
            target,
            source_link_layer: link_layer,
        }));
    }
    let flags = message[4];
    let solicited = flags & 0x40 != 0;
    if solicited && destination.is_multicast() {
        return Err(Error::Invalid);
    }
    Ok(NeighborMessage::Advertisement(NeighborAdvertisement {
        router: flags & 0x80 != 0,
        solicited,
        override_: flags & 0x20 != 0,
        target,
        target_link_layer: link_layer,
    }))
}

fn encode(
    ip: IpMetadata,
    kind: u8,
    flags: u8,
    target: Ipv6Addr,
    option: Option<(u8, [u8; 6])>,
    out: &mut [u8],
) -> Result<usize, Error> {
    v6(ip.source)?;
    v6(ip.destination)?;
    let len = FIXED + option.map_or(0, |_| LINK_LAYER_OPTION);
    let message = out.get_mut(..len).ok_or(Error::Length)?;
    message.fill(0);
    message[0] = kind;
    message[4] = flags;
    message[8..FIXED].copy_from_slice(&target.octets());
    if let Some((option, address)) = option {
        message[FIXED] = option;
        message[FIXED + 1] = 1;
        message[FIXED + 2..].copy_from_slice(&address);
    }
    let sum = icmpv6_checksum(ip, message)?;
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}

/// Encode a Neighbor Solicitation for `target` into `out`, returning its
/// length; the caller sends it with Hop Limit 255. A solicitation from the
/// unspecified address (Duplicate Address Detection) carries no Source
/// Link-Layer Address option and goes to a solicited-node group.
pub fn encode_solicitation(
    ip: IpMetadata,
    solicitation: NeighborSolicitation,
    out: &mut [u8],
) -> Result<usize, Error> {
    let source = v6(ip.source)?;
    if solicitation.target.is_multicast()
        || source.is_unspecified()
            && (solicitation.source_link_layer.is_some()
                || !solicited_node_group(v6(ip.destination)?))
    {
        return Err(Error::Invalid);
    }
    let option = solicitation
        .source_link_layer
        .map(|address| (SOURCE_LINK_LAYER, address));
    encode(ip, SOLICITATION, 0, solicitation.target, option, out)
}

/// Encode a Neighbor Advertisement into `out`, returning its length; the
/// caller sends it with Hop Limit 255. A solicited advertisement is unicast.
pub fn encode_advertisement(
    ip: IpMetadata,
    advertisement: NeighborAdvertisement,
    out: &mut [u8],
) -> Result<usize, Error> {
    if advertisement.target.is_multicast()
        || advertisement.solicited && v6(ip.destination)?.is_multicast()
    {
        return Err(Error::Invalid);
    }
    let flags = u8::from(advertisement.router) << 7
        | u8::from(advertisement.solicited) << 6
        | u8::from(advertisement.override_) << 5;
    let option = advertisement
        .target_link_layer
        .map(|address| (TARGET_LINK_LAYER, address));
    encode(ip, ADVERTISEMENT, flags, advertisement.target, option, out)
}
