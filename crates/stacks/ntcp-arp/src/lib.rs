//! The Address Resolution Protocol (RFC 826) for IPv4 over Ethernet: a
//! borrowed-input codec and an I/O-free, bounded resolution cache.
#![no_std]

extern crate alloc;

mod cache;

pub use cache::{
    AddressKind, ArpCache, ArpCounters, ArpLimits, ArpState, ArpTimers, Control, ControlOutcome,
    ControlToken, Event, Mapping, Resolution, Wake,
};

use core::net::Ipv4Addr;

/// The ARP body length for Ethernet hardware and IPv4 protocol addresses.
pub const ARP_LEN: usize = 28;
/// ares_hrd$Ethernet.
pub const HARDWARE_ETHERNET: u16 = 1;
/// The protocol address space of IPv4: its Ethernet type field.
pub const PROTOCOL_IPV4: u16 = 0x0800;

/// Faults of the codec and of the cache. ARP has its own type because its
/// rejections (hardware and protocol spaces and lengths, opcodes) and the
/// cache's configuration faults have no counterpart in the shared IP error,
/// and ntcp-ethernet stays independent of this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fewer than 28 octets to parse, or too little output space.
    Truncated,
    /// ar$hrd is not Ethernet.
    HardwareType,
    /// ar$pro is not IPv4.
    ProtocolType,
    /// ar$hln is not 6.
    HardwareLength,
    /// ar$pln is not 4.
    ProtocolLength,
    /// ar$op is neither REQUEST nor REPLY.
    Operation,
    /// A fixed table is full; nothing changed.
    Capacity,
    /// Storage could not be allocated at construction.
    Allocation,
    /// The caller's entropy source failed; nothing changed.
    Entropy,
    /// The link is not registered.
    UnknownLink,
    /// The link, address or entry is already registered.
    Duplicate,
    /// The address is not resolved by ARP: unspecified, limited broadcast,
    /// multicast, or one this cache answers for itself.
    Address,
    /// The link has no local address to send requests from.
    NoSource,
    /// The configuration cannot work (no broadcast request, or no time
    /// units).
    Config,
    /// The Ethernet frame is not untagged ARP.
    EtherType,
}

/// ar$op.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//# ares_op$REQUEST (= 1, high byte transmitted first) and
//# ares_op$REPLY   (= 2),
//# and
//# ares_hrd$Ethernet (= 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Request,
    Reply,
}
impl Operation {
    pub const fn code(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
        }
    }
}

/// One ARP packet for Ethernet hardware and IPv4 protocol addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arp {
    pub operation: Operation,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Parse the ARP body at the front of `bytes`. Octets after its 28 are
/// ignored: Ethernet minimum-frame padding follows a received body.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//# Ethernet packet data:
//# 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
//# Packet Radio Net.)
//# 16.bit: (ar$pro) Protocol address space.  For Ethernet
//# hardware, this is from the set of type
//# fields ether_typ$<protocol>.
//# 8.bit: (ar$hln) byte length of each hardware address
//# 8.bit: (ar$pln) byte length of each protocol address
//# 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
//# nbytes: (ar$sha) Hardware address of sender of this
//# packet, n from the ar$hln field.
//# mbytes: (ar$spa) Protocol address of sender of this
//# packet, m from the ar$pln field.
//# nbytes: (ar$tha) Hardware address of target of this
//# packet (if known).
//# mbytes: (ar$tpa) Protocol address of target.
//
// The optional length checks are made: this cache speaks only <1, 6> and
// IPv4, so any other combination is discarded with its own error.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//# ?Do I have the hardware type in ar$hrd?
//# Yes: (almost definitely)
//# [optionally check the hardware length ar$hln]
//# ?Do I speak the protocol in ar$pro?
//# Yes:
//# [optionally check the protocol length ar$pln]
pub fn parse(bytes: &[u8]) -> Result<Arp, Error> {
    let body = bytes.get(..ARP_LEN).ok_or(Error::Truncated)?;
    let word = |at: usize| u16::from_be_bytes([body[at], body[at + 1]]);
    if word(0) != HARDWARE_ETHERNET {
        return Err(Error::HardwareType);
    }
    if body[4] != 6 {
        return Err(Error::HardwareLength);
    }
    if word(2) != PROTOCOL_IPV4 {
        return Err(Error::ProtocolType);
    }
    if body[5] != 4 {
        return Err(Error::ProtocolLength);
    }
    let operation = match word(6) {
        1 => Operation::Request,
        2 => Operation::Reply,
        _ => return Err(Error::Operation),
    };
    let mac = |at: usize| <[u8; 6]>::try_from(&body[at..at + 6]).unwrap();
    let ip = |at: usize| Ipv4Addr::new(body[at], body[at + 1], body[at + 2], body[at + 3]);
    Ok(Arp {
        operation,
        sender_mac: mac(8),
        sender_ip: ip(14),
        target_mac: mac(18),
        target_ip: ip(24),
    })
}

/// Write `arp`'s 28-octet body to the front of `out`.
//= https://www.rfc-editor.org/rfc/rfc826#name-abstract
//# There are no padding bytes between addresses.  The packet data
//# should be viewed as a byte stream in which only 3 byte pairs are
//# defined to be words (ar$hrd, ar$pro and ar$op) which are sent
//# most significant byte first (Ethernet/PDP-10 byte style).
pub fn encode(out: &mut [u8], arp: &Arp) -> Result<usize, Error> {
    let body = out.get_mut(..ARP_LEN).ok_or(Error::Truncated)?;
    body[0..2].copy_from_slice(&HARDWARE_ETHERNET.to_be_bytes());
    body[2..4].copy_from_slice(&PROTOCOL_IPV4.to_be_bytes());
    body[4] = 6;
    body[5] = 4;
    body[6..8].copy_from_slice(&arp.operation.code().to_be_bytes());
    body[8..14].copy_from_slice(&arp.sender_mac);
    body[14..18].copy_from_slice(&arp.sender_ip.octets());
    body[18..24].copy_from_slice(&arp.target_mac);
    body[24..28].copy_from_slice(&arp.target_ip.octets());
    Ok(ARP_LEN)
}

/// Write `arp` in an Ethernet frame from `source` to `destination`, padded
/// to the 60-octet minimum.
pub fn encode_frame(
    out: &mut [u8],
    source: [u8; 6],
    destination: [u8; 6],
    arp: &Arp,
) -> Result<usize, Error> {
    let mut body = [0; ARP_LEN];
    encode(&mut body, arp)?;
    ntcp_ethernet::encode_ethernet_arp(out, source, destination, &body)
        .map_err(|_| Error::Truncated)
}

/// Parse an untagged Ethernet ARP frame: its destination and source
/// addresses and ARP body (padding ignored).
pub fn parse_frame(bytes: &[u8]) -> Result<([u8; 6], [u8; 6], Arp), Error> {
    let frame = ntcp_ethernet::parse_ethernet_arp(bytes).map_err(|error| match error {
        ntcp_ethernet::Error::Truncated => Error::Truncated,
        _ => Error::EtherType,
    })?;
    Ok((frame.destination, frame.source, parse(frame.payload)?))
}
