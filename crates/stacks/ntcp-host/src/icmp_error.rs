//! ICMP errors the Host originates about packets it could not reassemble or
//! whose IPv6 extension headers its receive processing refused:
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
use ntcp_ip6::{Fault, OptionAction};

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
/// arrival link. `len` octets of ICMP message were written, quoting as much
/// of the invoking packet as an extension-free outer header allows; `kind`
/// lets the output size the quote again for the header actually selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OriginatedError {
    pub ip: IpMetadata,
    pub link: LinkId,
    pub len: usize,
    pub kind: ErrorMessage,
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
    // RFC 4443 section 2.4(e.4): a link-layer multicast or broadcast draws
    // only the Code 2 error for an option whose action is 10.
    let multicast_exception = matches!(error, ReassemblyError::ReportedOption { .. });
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
    let kind = match error {
        ReassemblyError::TimeExceeded => ErrorMessage::ReassemblyTimeExceeded,
        ReassemblyError::ParameterProblem { code, pointer } => {
            ErrorMessage::Ipv6ParameterProblem { code, pointer }
        }
        ReassemblyError::ReportedOption { pointer } => {
            ErrorMessage::Ipv6ParameterProblem { code: 2, pointer }
        }
    };
    // encode_error writes only once it succeeds.
    if !limiter.available(now) {
        return None;
    }
    // The largest quote, for the minimal outer header; the output sizes it
    // again for the header of the route it selects (`Host::icmp_output`).
    let outer_header = match reply.source {
        IpAddr::V4(_) => ntcp_ip::IPV4_HEADER,
        IpAddr::V6(_) => ntcp_ip6::IPV6_HEADER,
    };
    let len = ntcp_icmp::encode_error(reply, kind, invoking, outer_header, message).ok()?;
    limiter.admit(now);
    Some(OriginatedError {
        ip: reply,
        link: arrival.link,
        len,
        kind,
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
