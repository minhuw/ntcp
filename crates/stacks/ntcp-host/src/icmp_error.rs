//! ICMP errors the Host originates about packets it could not reassemble,
//! whose IPv6 extension headers its receive processing refused, or that no
//! transport protocol or port of it takes: family-specific suppression,
//! Linux's rate limits (which also bound Echo Replies whose type a mask
//! names), and message construction.
//!
//! `Host::receive` (module `ingress`) and transport input feed this engine
//! and queue its errors for the Host ICMP output.

use alloc::vec::Vec;
use core::hash::Hasher;
use core::net::IpAddr;
use ntcp::{Instant, IpMetadata};
use ntcp_icmp::ErrorMessage;
use ntcp_path::LinkId;

use crate::reassembly::{Arrival, Discard, admissible_source};
use ntcp_ip6::{Fault, OptionAction};

/// The rate limits on ICMP messages this Host originates, Linux's (6.12)
/// with its sysctl defaults. A message whose type its family's mask names
/// needs a token from a bucket shared by every such message of both
/// families (icmp_global_allow, net/ipv4/icmp.c:232-261) and then one from
/// its destination's own bucket (inet_peer_xrlim_allow,
/// net/ipv4/inetpeer.c:266-288); a message whose type the mask does not
/// name, Echo Replies by default, is not limited (icmpv4_mask_allow,
/// icmp.c:276-285; icmpv6_mask_allow, net/ipv6/icmp.c:166-176). Linux's
/// defaults limit ICMPv4 Destination Unreachable (but Fragmentation
/// Needed), Source Quench, Time Exceeded and Parameter Problem, and every
/// ICMPv6 error but Packet Too Big. RFC 4443 section 2.4(f) requires ICMPv6
/// errors to be rate limited; this is its token-bucket method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpRateLimits {
    /// Tokens the shared bucket gains per second: net.ipv4.icmp_msgs_per_sec,
    /// 1000. It refills at most once per 20 ms, as Linux's (icmp.c:247), so
    /// below 50 per second no limited message is sent.
    pub per_second: u32,
    /// The shared bucket's depth: net.ipv4.icmp_msgs_burst, 50. Each message
    /// that passes both buckets takes 0, 1 or 2 tokens from it, uniformly at
    /// random (icmp_global_consume, icmp.c:264-272), so that its level tells
    /// an observer nothing exact about the errors other parties drew.
    pub burst: u32,
    /// A destination's bucket gains one message per interval, in
    /// milliseconds, and holds six (XRLIM_BURST_FACTOR):
    /// net.ipv4.icmp_ratelimit, 1000. Zero leaves destinations unlimited.
    pub ipv4_interval_ms: u32,
    /// Bit n limits ICMPv4 type n: net.ipv4.icmp_ratemask, 0x1818 (types 3,
    /// 4, 11 and 12). Types above 18 and Fragmentation Needed are never
    /// limited.
    pub ipv4_mask: u32,
    /// net.ipv6.icmp.ratelimit, 1000, shortened for a destination reached
    /// through a route of prefix length p below 128 by a factor of
    /// 2^((128 - p) / 32), as Linux's icmpv6_xrlim_allow
    /// (net/ipv6/icmp.c:218-223) does for its route's rt6i_dst.plen.
    pub ipv6_interval_ms: u32,
    /// Bit n (of word n / 128) limits ICMPv6 type n: net.ipv6.icmp.ratemask,
    /// 0-1,3-127 (net/ipv6/af_inet6.c:970-971).
    pub ipv6_mask: [u128; 2],
    /// Destinations whose buckets are kept at once. Linux keeps one
    /// inet_peer per destination, freed by age (net/ipv4/inetpeer.c), and
    /// sends without one when it cannot allocate it (inetpeer.c:272-273):
    /// here a destination whose bucket refilled (six intervals idle) gives
    /// its entry up, and a destination that finds no free entry is limited
    /// by the shared bucket alone. Entries are kept in sets of four, by a
    /// keyed hash of the address, so that a sender cannot choose which
    /// destination's entry it takes. Storage, about 40 bytes an entry, is
    /// allocated at the first limited message; 0 keeps none.
    pub destinations: usize,
}

impl Default for IcmpRateLimits {
    fn default() -> Self {
        Self {
            per_second: 1000,
            burst: 50,
            ipv4_interval_ms: 1000,
            ipv4_mask: 0x1818,
            ipv6_interval_ms: 1000,
            ipv6_mask: [!(1 << 2), 0],
            destinations: 256,
        }
    }
}

impl IcmpRateLimits {
    // Whether a message of `kind` (type, code) is limited.
    fn limited(&self, ipv6: bool, (kind, code): (u8, u8)) -> bool {
        if ipv6 {
            self.ipv6_mask[usize::from(kind >> 7)] >> (kind & 127) & 1 != 0
        } else {
            // NR_ICMP_TYPES, and ICMP_FRAG_NEEDED (icmp.c:276-285).
            kind <= 18 && !(kind == 3 && code == 4) && self.ipv4_mask >> kind & 1 != 0
        }
    }
}

// Linux's XRLIM_BURST_FACTOR (net/ipv4/inetpeer.c).
const BURST_FACTOR: u64 = 6;

// One destination's bucket: inet_peer's rate_tokens and rate_last.
#[derive(Clone, Copy, Debug)]
struct Peer {
    address: [u8; 16],
    ipv6: bool,
    tokens: u64,
    last: Instant,
}

pub(crate) struct RateLimiter {
    limits: IcmpRateLimits,
    units_per_second: u64,
    key: [u8; 16],
    // The shared bucket: icmp_global_credit and icmp_global_stamp.
    credit: i64,
    stamp: Option<Instant>,
    debits: u64,
    // Sets of `ways` entries; empty until the first limited message.
    peers: Vec<Option<Peer>>,
    // Messages the shared bucket and a destination's bucket refused:
    // Linux's ICMP_MIB_RATELIMITGLOBAL and ICMP_MIB_RATELIMITHOST.
    pub limited_global: u64,
    pub limited_host: u64,
}

impl RateLimiter {
    // `key` keys the hash that places destinations and the draw of the
    // shared bucket's debits: confidential and unpredictable.
    pub fn new(limits: IcmpRateLimits, units_per_second: u64, key: [u8; 16]) -> Self {
        Self {
            limits,
            units_per_second,
            key,
            credit: 0,
            stamp: None,
            debits: 0,
            peers: Vec::new(),
            limited_global: 0,
            limited_host: 0,
        }
    }

    // Bytes of storage held.
    #[inline]
    pub fn memory(&self) -> usize {
        self.peers.capacity() * core::mem::size_of::<Option<Peer>>()
    }

    /// Whether a message of `kind` (ICMP type and code) to `destination`
    /// may be sent at `now`, taking its tokens if so. `prefix` gives the
    /// prefix length of the route an IPv6 message takes; it is read only
    /// for a limited IPv6 message. In Linux's order (__icmp_send,
    /// icmp.c:690-751; icmp6_send, net/ipv6/icmp.c:545-585): the type's
    /// mask, then the shared bucket, then the destination's, and only a
    /// message both pass debits the shared one.
    pub fn allow(
        &mut self,
        now: Instant,
        ipv6: bool,
        kind: (u8, u8),
        destination: IpAddr,
        prefix: impl FnOnce() -> u8,
    ) -> bool {
        if !self.limits.limited(ipv6, kind) {
            return true;
        }
        if !self.shared(now) {
            self.limited_global += 1;
            return false;
        }
        let interval = if ipv6 {
            self.limits.ipv6_interval_ms
        } else {
            self.limits.ipv4_interval_ms
        };
        let mut timeout = u64::from(interval) * self.units_per_second / 1000;
        if ipv6 {
            let prefix = prefix();
            if prefix < 128 {
                timeout >>= (128 - u32::from(prefix)) >> 5;
            }
        }
        if !self.destination(now, destination, timeout) {
            self.limited_host += 1;
            return false;
        }
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.key);
        hash.write(b"icmp debit");
        hash.write_u64(self.debits);
        self.debits = self.debits.wrapping_add(1);
        self.credit -= (hash.finish() % 3) as i64;
        true
    }

    // icmp_global_allow (icmp.c:232-261): a positive credit admits;
    // otherwise, at least 20 ms after the last refill, the bucket gains
    // `per_second` tokens a second for the time since (at most a second's
    // worth), up to `burst`, and the message is admitted.
    fn shared(&mut self, now: Instant) -> bool {
        if self.credit > 0 {
            return true;
        }
        let second = self.units_per_second;
        let delta = self
            .stamp
            .map_or(second, |stamp| now.saturating_sub(stamp))
            .min(second);
        if delta < second / 50 {
            return false;
        }
        let gained = u64::from(self.limits.per_second) * delta / second;
        if gained == 0 {
            return false;
        }
        self.stamp = Some(now);
        self.credit = (self.credit + gained as i64).min(i64::from(self.limits.burst));
        true
    }

    // inet_peer_xrlim_allow (inetpeer.c:266-288): a destination's tokens
    // are time, gained at one unit per unit, capped at six timeouts; a
    // message takes one timeout's worth. A new destination starts with a
    // full bucket (inet_getpeer sets rate_last 60 s back, inetpeer.c:222).
    fn destination(&mut self, now: Instant, destination: IpAddr, timeout: u64) -> bool {
        let Some(index) = self.entry(now, destination) else {
            return true;
        };
        let cap = timeout.saturating_mul(BURST_FACTOR);
        let peer = self.peers[index].as_mut().unwrap();
        let tokens = peer
            .tokens
            .saturating_add(now.saturating_sub(peer.last))
            .min(cap);
        peer.last = peer.last.max(now);
        let allowed = tokens >= timeout;
        peer.tokens = if allowed { tokens - timeout } else { tokens };
        allowed
    }

    // The entry of `destination`, taking an idle one of its set for a new
    // destination; None when every entry of the set is in use (or none is
    // kept).
    fn entry(&mut self, now: Instant, destination: IpAddr) -> Option<usize> {
        let count = self.limits.destinations;
        if count == 0 {
            return None;
        }
        if self.peers.is_empty() {
            self.peers.try_reserve_exact(count).ok()?;
            self.peers.resize(count, None);
        }
        let (address, ipv6) = match destination {
            IpAddr::V4(a) => (a.to_ipv6_mapped().octets(), false),
            IpAddr::V6(a) => (a.octets(), true),
        };
        let ways = count.min(4);
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.key);
        hash.write(b"icmp peer");
        hash.write_u8(u8::from(ipv6));
        hash.write(&address);
        let set = (hash.finish() % (count / ways) as u64) as usize * ways;
        let slots = set..set + ways;
        if let Some(index) = slots
            .clone()
            .find(|&i| self.peers[i].is_some_and(|p| p.address == address && p.ipv6 == ipv6))
        {
            return Some(index);
        }
        // A bucket idle for six of the longer interval is full, as a new
        // destination's is: its entry is free to take.
        let interval = self
            .limits
            .ipv4_interval_ms
            .max(self.limits.ipv6_interval_ms);
        let full =
            (u64::from(interval) * self.units_per_second / 1000).saturating_mul(BURST_FACTOR);
        let index = slots
            .clone()
            .find(|&i| self.peers[i].is_none_or(|p| now.saturating_sub(p.last) >= full))?;
        let second = self.units_per_second;
        self.peers[index] = Some(Peer {
            address,
            ipv6,
            tokens: 60 * second,
            last: now,
        });
        Some(index)
    }
}

/// An error about one invoking packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReassemblyError {
    /// The assembly expired after its fragment zero arrived (RFC 1122
    /// section 3.3.2: ICMPv4 Time Exceeded code 1; RFC 8200 section 4.5:
    /// ICMPv6 Time Exceeded code 1). The invoking packet is fragment zero.
    TimeExceeded,
    /// ICMPv6 Parameter Problem about one discarded fragment or packet.
    ParameterProblem { code: u8, pointer: u32 },
    /// Parameter Problem Code 2 for an unrecognized option whose action is
    /// 10: the one error here that RFC 4443 section 2.4(e.3) and (e.4) let
    /// a packet sent as a link-layer multicast or broadcast draw.
    ReportedOption { pointer: u32 },
}

impl ReassemblyError {
    /// RFC 8200 section 4.5's errors for a discarded IPv6 fragment whose
    /// Fragment header is at `fragment`: a non-final length not a multiple
    /// of 8 (code 0 at the Payload Length field), a reassembled Payload
    /// Length beyond 65535 (code 0 at the Fragment Offset field) and a first
    /// fragment without the complete header chain (code 3, pointer 0).
    /// Overlap is silent, and IPv4 defines no error for these cases.
    pub fn for_discard(ipv6: bool, discard: Discard, fragment: usize) -> Option<Self> {
        if !ipv6 {
            return None;
        }
        let (code, pointer) = match discard {
            Discard::Misaligned => (0, 4),
            Discard::Oversize => (0, u32::try_from(fragment + 2).ok()?),
            Discard::IncompleteHeader => (3, 0),
            _ => return None,
        };
        Some(Self::ParameterProblem { code, pointer })
    }

    /// The Parameter Problem for a header chain that receive processing
    /// refused (RFC 8200 section 4, RFC 4443 section 3.4): code 0 for an
    /// impossible length or a Routing header with Segments Left above zero,
    /// code 1 for a misplaced Hop-by-Hop Options header, code 2 for an
    /// unrecognized option whose action reports it, code 3 for a first
    /// fragment whose chain continues past it (RFC 7112). Physical
    /// truncation and options whose action discards silently draw none.
    pub fn for_fault(fault: Fault) -> Option<Self> {
        let (code, pointer) = match fault {
            Fault::Truncated | Fault::Version => return None,
            Fault::Length { pointer } | Fault::SegmentsLeft { pointer } => (0, pointer),
            Fault::MisplacedHopByHop { pointer } => (1, pointer),
            Fault::Option { pointer, action } => match action {
                OptionAction::Discard => return None,
                OptionAction::Report => {
                    return Some(Self::ReportedOption {
                        pointer: u32::try_from(pointer).ok()?,
                    });
                }
                OptionAction::ReportUnlessMulticast => (2, pointer),
            },
            Fault::IncompleteChain => (3, 0),
        };
        Some(Self::ParameterProblem {
            code,
            pointer: u32::try_from(pointer).ok()?,
        })
    }

    /// RFC 8200 section 4: code 1 at `selector`, the Next Header octet that
    /// names a header or protocol this host does not process.
    pub fn unrecognized(selector: usize) -> Option<Self> {
        Some(Self::ParameterProblem {
            code: 1,
            pointer: u32::try_from(selector).ok()?,
        })
    }
}

/// An originated error message from the invoking packet's local
/// destination to its source, which a link-local destination limits to the
/// arrival link; `build` writes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginatedError {
    pub ip: IpMetadata,
    pub link: LinkId,
    pub kind: ErrorMessage,
}

impl ReassemblyError {
    /// The message, and whether it is the one error RFC 4443 section
    /// 2.4(e.3) and (e.4) let a link-layer multicast or broadcast draw.
    pub fn message(self) -> (ErrorMessage, bool) {
        match self {
            Self::TimeExceeded => (ErrorMessage::ReassemblyTimeExceeded, false),
            Self::ParameterProblem { code, pointer } => {
                (ErrorMessage::Ipv6ParameterProblem { code, pointer }, false)
            }
            Self::ReportedOption { pointer } => (
                ErrorMessage::Ipv6ParameterProblem { code: 2, pointer },
                true,
            ),
        }
    }
}

/// The error `kind` about `invoking` (the packet as it arrived, or the
/// datagram a transport protocol refused), unless the family's rules
/// suppress it or the rate limits refuse it (`RateLimiter::allow`, whose
/// tokens it takes). `multicast_exception`: `kind` is the error a
/// link-layer multicast or broadcast may draw (`ReassemblyError::message`).
/// `prefix` gives the prefix length of the route the error takes
/// (`RateLimiter::allow`).
pub(crate) fn originate(
    limiter: &mut RateLimiter,
    now: Instant,
    kind: ErrorMessage,
    multicast_exception: bool,
    arrival: Arrival,
    invoking: &[u8],
    prefix: impl FnOnce(IpMetadata) -> u8,
) -> Option<OriginatedError> {
    let ip = invoking_addresses(invoking)?;
    let allowed = match ip.source {
        IpAddr::V4(_) => ipv4_allowed(invoking),
        IpAddr::V6(_) => ipv6_allowed(invoking),
    };
    // RFC 4443 section 2.4(e.4): a link-layer multicast or broadcast draws
    // only the Code 2 error for an option whose action is 10.
    if !allowed || (arrival.link_multicast && !multicast_exception) || !admissible_source(ip.source)
    {
        return None;
    }
    // The invoking destination is a unicast address this Host owns: the
    // Host admits no other destination (a multicast one is refused by
    // `ipv6_allowed` as well), so the error's source is that address
    // (RFC 4443 section 2.2(a)).
    let reply = IpMetadata {
        source: ip.destination,
        destination: ip.source,
    };
    let ipv6 = reply.source.is_ipv6();
    let (kind_type, code, _) = kind.header(ipv6)?;
    if !limiter.allow(now, ipv6, (kind_type, code), reply.destination, || {
        prefix(reply)
    }) {
        return None;
    }
    Some(OriginatedError {
        ip: reply,
        link: arrival.link,
        kind,
    })
}

/// The ICMP message of `error` about `invoking`, quoting as much of it as
/// an extension-free outer header allows, in storage of its length; the
/// output sizes the quote again for the header actually selected
/// (`Host::icmp_output`). None if the quote cannot be built or the
/// allocator refuses the storage.
pub(crate) fn build(error: OriginatedError, invoking: &[u8]) -> Option<Vec<u8>> {
    let (outer_header, limit) = match error.ip.source {
        IpAddr::V4(_) => (ntcp_ip::IPV4_HEADER, ntcp_icmp::ICMPV4_ERROR_LIMIT),
        IpAddr::V6(_) => (ntcp_ip6::IPV6_HEADER, ntcp_icmp::ICMPV6_ERROR_LIMIT),
    };
    let mut message = Vec::new();
    let len = invoking.len().saturating_add(8).min(limit);
    message.try_reserve_exact(len).ok()?;
    message.resize(len, 0);
    let len =
        ntcp_icmp::encode_error(error.ip, error.kind, invoking, outer_header, &mut message).ok()?;
    message.truncate(len);
    Some(message)
}

fn invoking_addresses(b: &[u8]) -> Option<IpMetadata> {
    let address = |bytes: &[u8]| -> Option<IpAddr> {
        Some(match bytes.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
            _ => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        })
    };
    match b.first()? >> 4 {
        4 => Some(IpMetadata {
            source: address(b.get(12..16)?)?,
            destination: address(b.get(16..20)?)?,
        }),
        6 => Some(IpMetadata {
            source: address(b.get(8..24)?)?,
            destination: address(b.get(24..40)?)?,
        }),
        _ => None,
    }
}

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.2
//# An ICMP error message MUST NOT be sent as the result of
//# receiving:
//#
//# *    an ICMP error message, or
//#
//# *    a datagram destined to an IP broadcast or IP multicast
//#      address, or
//#
//# *    a datagram sent as a link-layer broadcast, or
//#
//# *    a non-initial fragment, or
//#
//# *    a datagram whose source address does not define a single
//#      host -- e.g., a zero address, a loopback address, a
//#      broadcast address, a multicast address, or a Class E
//#      address.
// An ICMP error message, a datagram to an IP broadcast or multicast address
// or sent as a link-layer broadcast, a non-initial fragment, or one whose
// source is not a single host. An ICMP datagram whose type is missing or
// unknown cannot be shown not to be an error and gets none either.
fn ipv4_allowed(b: &[u8]) -> bool {
    let Some(header) = b.first().map(|v| usize::from(v & 15) * 4) else {
        return false;
    };
    let (Some(flags), Some(protocol), Some(destination)) = (b.get(6..8), b.get(9), b.get(16..20))
    else {
        return false;
    };
    let destination = core::net::Ipv4Addr::new(
        destination[0],
        destination[1],
        destination[2],
        destination[3],
    );
    if u16::from_be_bytes([flags[0], flags[1]]) & 0x1fff != 0
        || destination.is_multicast()
        || destination.is_broadcast()
        || destination.is_unspecified()
    {
        return false;
    }
    match (*protocol, b.get(header)) {
        // Echo Reply/Request, Timestamp, Information and Address Mask
        // queries and replies are queries, not errors.
        (1, Some(kind)) => matches!(kind, 0 | 8 | 13..=18),
        (1, None) => false,
        _ => true,
    }
}

// RFC 4443 section 2.4:
//   (e) An ICMPv6 error message MUST NOT be originated as a result of
//   receiving the following:
// An ICMPv6 error or Redirect, a packet to a multicast address or sent as a
// link-layer multicast or broadcast (`originate` applies the code 2
// exception; this Host originates no Packet Too Big), or a source that is
// not a single node. The upper layer is found by generic framing alone, as
// Linux's is_ineligible does with ipv6_skip_exthdr: the refusal being
// answered may be a placement or option rule, so no such rule may hide an
// ICMPv6 error behind it. A chain whose framing overruns the Payload Length
// before an upper layer is not shown to be an ICMPv6 message. There is no
// IPv6 rule for non-initial fragments; but data of a non-initial fragment
// is opaque, so one whose Fragment header names ICMPv6 cannot be classified
// and gets no error, nor does an ICMPv6 message without its type.
fn ipv6_allowed(b: &[u8]) -> bool {
    let (Some(destination), Some(payload)) = (b.get(24..40), b.get(4..6)) else {
        return false;
    };
    if destination[0] == 0xff {
        return false;
    }
    let declared =
        ntcp_ip6::IPV6_HEADER + usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    let mut kind = b[6];
    let mut offset = ntcp_ip6::IPV6_HEADER;
    loop {
        let len = match kind {
            0 | 43 | 60 => match b.get(offset + 1) {
                Some(&units) => (usize::from(units) + 1) * 8,
                None => return false,
            },
            44 => match b.get(offset..offset + 4) {
                Some(f) if u16::from_be_bytes([f[2], f[3]]) & !7 != 0 => return f[0] != 58,
                Some(_) => ntcp_ip6::FRAGMENT_HEADER,
                None => return false,
            },
            58 => {
                return match b.get(offset).filter(|_| offset < declared) {
                    Some(&kind) => kind >= 128 && kind != 137,
                    None => false,
                };
            }
            _ => return true,
        };
        // Every framed header occupies at least eight octets.
        if offset + len > declared {
            return true;
        }
        let Some(&next) = b.get(offset) else {
            return false;
        };
        kind = next;
        offset += len;
    }
}
