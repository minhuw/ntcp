//! ICMP errors the Host originates about datagrams it could not reassemble:
//! family-specific suppression, one burst-capable rate limiter for every
//! originated error, and message construction.
//!
//! `Host::receive` (module `ingress`) feeds this engine and queues its
//! errors for the Host ICMP output.

use core::net::IpAddr;
use ntcp::{Instant, IpMetadata};
use ntcp_icmp::ErrorMessage;
use ntcp_path::LinkId;

use crate::reassembly::{Arrival, Discard, admissible_source};

/// Token bucket for every ICMP error this Host originates: up to `burst`
/// errors at once, refilled at `per_second`. RFC 4443 section 2.4(f)
/// requires rate limiting ICMPv6 errors; its token-bucket example (B=10,
/// N=10 per second) is the default, and IPv4 errors share the same bucket.
/// A zero burst originates no errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpErrorLimits {
    pub burst: u32,
    pub per_second: u32,
}

impl Default for IcmpErrorLimits {
    fn default() -> Self {
        Self {
            burst: 10,
            per_second: 10,
        }
    }
}

// Credit in token-time units: one token is `units_per_second` units, and
// each unit of caller time adds `per_second` units, so a second refills
// `per_second` tokens without rounding.
pub(crate) struct ErrorLimiter {
    limits: IcmpErrorLimits,
    units_per_second: u64,
    credit: u128,
    last: Option<Instant>,
}

impl ErrorLimiter {
    pub fn new(limits: IcmpErrorLimits, units_per_second: u64) -> Self {
        Self {
            limits,
            units_per_second,
            credit: u128::from(limits.burst) * u128::from(units_per_second),
            last: None,
        }
    }

    // Refill to `now` and report whether a token is available. Time that
    // runs backwards adds nothing.
    fn available(&mut self, now: Instant) -> bool {
        let token = u128::from(self.units_per_second);
        let capacity = u128::from(self.limits.burst) * token;
        if let Some(last) = self.last {
            let elapsed = u128::from(now.saturating_sub(last));
            self.credit = capacity.min(self.credit + elapsed * u128::from(self.limits.per_second));
        }
        self.last = Some(self.last.map_or(now, |last| last.max(now)));
        self.credit >= token && token != 0
    }

    // Take one token if available.
    pub fn admit(&mut self, now: Instant) -> bool {
        if !self.available(now) {
            return false;
        }
        self.credit -= u128::from(self.units_per_second);
        true
    }
}

/// An error about one invoking packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReassemblyError {
    /// The assembly expired after its fragment zero arrived (RFC 1122
    /// section 3.3.2: ICMPv4 Time Exceeded code 1; RFC 8200 section 4.5:
    /// ICMPv6 Time Exceeded code 1). The invoking packet is fragment zero.
    TimeExceeded,
    /// ICMPv6 Parameter Problem about one discarded fragment.
    ParameterProblem { code: u8, pointer: u32 },
}

impl ReassemblyError {
    /// RFC 8200 section 4.5's errors for a discarded IPv6 fragment, pointing
    /// into the base -> Fragment layout this Host accepts: a non-final
    /// length not a multiple of 8 (code 0 at the Payload Length field), a
    /// reassembled Payload Length beyond 65535 (code 0 at the Fragment
    /// Offset field, octet 42) and a first fragment without the complete
    /// header chain (code 3, pointer 0). Overlap is silent, and IPv4 defines
    /// no error for these cases.
    pub fn for_discard(ipv6: bool, discard: Discard) -> Option<Self> {
        if !ipv6 {
            return None;
        }
        let (code, pointer) = match discard {
            Discard::Misaligned => (0, 4),
            Discard::Oversize => (0, 42),
            Discard::IncompleteHeader => (3, 0),
            _ => return None,
        };
        Some(Self::ParameterProblem { code, pointer })
    }
}

/// An originated error message from the invoking packet's local
/// destination to its source, which a link-local destination limits to the
/// arrival link. `len` octets of ICMP message were written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginatedError {
    pub ip: IpMetadata,
    pub link: LinkId,
    pub len: usize,
}

/// Build `error` about `invoking` (the packet as it arrived) into `message`
/// unless the family's rules suppress it or the limiter refuses it. The
/// limiter is charged only for a message that was built and would be sent,
/// and `message` is written only for a message returned: it may be the
/// storage of a held queued message that the new one displaces.
pub(crate) fn originate(
    limiter: &mut ErrorLimiter,
    now: Instant,
    error: ReassemblyError,
    arrival: Arrival,
    invoking: &[u8],
    message: &mut [u8],
) -> Option<OriginatedError> {
    let ip = invoking_addresses(invoking)?;
    let allowed = match ip.source {
        IpAddr::V4(_) => ipv4_allowed(invoking),
        IpAddr::V6(_) => ipv6_allowed(invoking),
    };
    if !allowed || arrival.link_multicast || !admissible_source(ip.source) {
        return None;
    }
    let reply = IpMetadata {
        source: ip.destination,
        destination: ip.source,
    };
    let kind = match error {
        ReassemblyError::TimeExceeded => ErrorMessage::ReassemblyTimeExceeded,
        ReassemblyError::ParameterProblem { code, pointer } => {
            ErrorMessage::Ipv6ParameterProblem { code, pointer }
        }
    };
    // encode_error writes only once it succeeds.
    if !limiter.available(now) {
        return None;
    }
    let len = ntcp_icmp::encode_error(reply, kind, invoking, message).ok()?;
    limiter.admit(now);
    Some(OriginatedError {
        ip: reply,
        link: arrival.link,
        len,
    })
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

// RFC 1122 section 3.2.2:
//   An ICMP error message MUST NOT be sent as the result of
//   receiving:
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
// link-layer multicast or broadcast (the Packet Too Big and code 2
// exceptions do not apply to reassembly errors), or a source that is not a
// single node. There is no IPv6 rule for non-initial fragments; but data of
// a non-initial fragment is opaque, so one whose Fragment header names
// ICMPv6 cannot be classified and gets no error.
fn ipv6_allowed(b: &[u8]) -> bool {
    let (Some(&next), Some(destination)) = (b.get(6), b.get(24..40)) else {
        return false;
    };
    if destination[0] == 0xff {
        return false;
    }
    let (protocol, first, data) = if next == 44 {
        let Some(fragment) = b.get(40..48) else {
            return false;
        };
        let offset = u16::from_be_bytes([fragment[2], fragment[3]]) & !7;
        (fragment[0], offset == 0, b.get(48..))
    } else {
        (next, true, b.get(40..))
    };
    if protocol != 58 {
        return true;
    }
    match (first, data.and_then(|d| d.first())) {
        (true, Some(&kind)) => kind >= 128 && kind != 137,
        _ => false,
    }
}
