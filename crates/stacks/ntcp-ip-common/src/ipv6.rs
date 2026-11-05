//! Bounded IPv6 extension header chain (RFC 8200 section 4).
//!
//! One walker frames every header from the base header to the upper layer.
//! Generic framing (Next Header, Hdr Ext Len, the fixed Fragment length) is
//! separate from type-specific work: receive actions for options and Routing
//! headers apply only when walking a received packet, and the Routing-header
//! final destination is extracted only from quotes. Work and storage are
//! bounded by bytes, not by a header count: every extension header occupies
//! at least eight octets and every option at least one, and no header may
//! extend past the declared Payload Length or the bytes physically present.

use core::net::Ipv6Addr;

use crate::Error;

pub const BASE_HEADER: usize = 40;
pub const HOP_BY_HOP: u8 = 0;
pub const ROUTING: u8 = 43;
pub const FRAGMENT: u8 = 44;
pub const NO_NEXT_HEADER: u8 = 59;
pub const DESTINATION_OPTIONS: u8 = 60;
/// Length of the Fragment header (RFC 8200 section 4.5).
pub const FRAGMENT_HEADER: usize = 8;
const PAYLOAD_LENGTH_FIELD: usize = 4;
const PAD1: u8 = 0;
const PADN: u8 = 1;
const ROUTING_TYPE_0: u8 = 0;
const ROUTING_TYPE_SRH: u8 = 4;

/// What an unrecognized option requires (RFC 8200 section 4.2, the two
/// high-order bits of its Option Type). Action 00 (skip) is not a fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionAction {
    /// 01: discard silently.
    Discard,
    /// 10: discard and send Parameter Problem Code 2, even to a multicast
    /// destination.
    Report,
    /// 11: discard and send Parameter Problem Code 2 only when the
    /// destination is not multicast.
    ReportUnlessMulticast,
}

/// Why a chain was not accepted. Pointers are octet offsets from the start
/// of the base header, ready for a Parameter Problem (RFC 4443 section 3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// Fewer bytes are present than the base header or a header the walk
    /// needs: physical truncation, or a quote too short to attribute.
    Truncated,
    Version,
    /// An impossible length in the supplied bytes: a header or option that
    /// extends past its container. `pointer` names the length field (the
    /// Payload Length when the declared payload cannot hold the header).
    Length { pointer: usize },
    /// A Hop-by-Hop Options header not immediately after the base header;
    /// `pointer` names the Next Header octet that selected it (Code 1).
    MisplacedHopByHop { pointer: usize },
    /// An unrecognized option whose action discards the packet; `pointer`
    /// names its Option Type octet.
    Option { pointer: usize, action: OptionAction },
    /// A Routing header with Segments Left above zero at a node that is not
    /// a segment endpoint; `pointer` names its Routing Type (Code 0).
    SegmentsLeft { pointer: usize },
    /// RFC 7112: a physically complete initial fragment whose header chain
    /// continues past the fragment (Code 3, pointer zero).
    IncompleteChain,
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Truncated => Error::Truncated,
            Fault::Version => Error::Version,
            Fault::Length { .. } | Fault::IncompleteChain => Error::Length,
            Fault::MisplacedHopByHop { .. } | Fault::SegmentsLeft { .. } => {
                Error::ExtensionsUnsupported
            }
            Fault::Option { .. } => Error::Options,
        }
    }
}

/// One extension header in wire order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionHeader {
    /// The selector that named it.
    pub kind: u8,
    pub offset: usize,
    pub len: usize,
}

/// The first Fragment header of a chain and its fields. Reserved fields are
/// ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentHeader {
    /// Offset of the Fragment header: the end of the unfragmentable part.
    pub offset: usize,
    /// Offset of the Next Header octet that selected it.
    pub selector: usize,
    pub next_header: u8,
    pub identification: u32,
    pub more_fragments: bool,
    /// Position of this fragment's data in octets (a multiple of 8).
    pub fragment_offset: u16,
}

impl FragmentHeader {
    /// Offset of the first fragment data octet.
    pub fn data(&self) -> usize {
        self.offset + FRAGMENT_HEADER
    }

    /// The first Fragment header of a packet found by generic framing
    /// alone, within the declared and present bytes: no option action,
    /// routing policy or header placement rule applies, so it identifies a
    /// fragment whose chain receive processing would refuse.
    pub fn locate(bytes: &[u8]) -> Option<Self> {
        let payload = u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]);
        let declared = BASE_HEADER
            .checked_add(usize::from(payload))?
            .min(bytes.len());
        let mut selector = 6;
        let mut offset = BASE_HEADER;
        loop {
            let kind = *bytes.get(selector)?;
            if !is_extension(kind) {
                return None;
            }
            let end = offset.checked_add(framed_len(kind, bytes, offset)?)?;
            let header = bytes.get(offset..end).filter(|_| end <= declared)?;
            if kind == FRAGMENT {
                return Some(fragment_fields(header, offset, selector));
            }
            selector = offset;
            offset = end;
        }
    }
}

// The fields of the Fragment header `header` at `offset`, selected by the
// Next Header octet at `selector`.
fn fragment_fields(header: &[u8], offset: usize, selector: usize) -> FragmentHeader {
    let field = u16::from_be_bytes([header[2], header[3]]);
    FragmentHeader {
        offset,
        selector,
        next_header: header[0],
        identification: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        more_fragments: field & 1 != 0,
        fragment_offset: field & !7,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completeness {
    /// Every declared octet is present and no fragment data follows.
    Complete,
    /// The physically complete fragment at offset zero of a larger packet.
    InitialFragment,
    /// A fragment at a nonzero offset: its data is opaque.
    LaterFragment,
    /// A quote shorter than the declared packet.
    Truncated,
}

/// A validated chain. Only the walker constructs one.
#[derive(Clone, Copy, Debug)]
pub struct Chain<'a> {
    bytes: &'a [u8],
    declared: usize,
    upper: usize,
    selector: usize,
    protocol: u8,
    fragment: Option<FragmentHeader>,
    final_destination: Option<Ipv6Addr>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Receive,
    Quote,
}

impl<'a> Chain<'a> {
    /// Walk a received packet whose declared octets are all present. Options
    /// and Routing headers before any Fragment header are processed: unknown
    /// options apply their action, and a Routing header of any type with
    /// Segments Left zero is skipped while one above zero is refused, since
    /// no local address is a segment endpoint (RFC 8200 section 4.4,
    /// RFC 5095 section 3, RFC 8754 section 4.3.2). Headers after a Fragment
    /// header belong to the reassembled packet and are only framed.
    pub fn receive(bytes: &'a [u8]) -> Result<Self, Fault> {
        walk(bytes, Mode::Receive)
    }

    /// Walk a packet quoted by an ICMP error. The quote may stop before the
    /// declared end, but every header up to the upper layer (or, in a later
    /// fragment, up to the Fragment header) must be present. No option
    /// action or routing policy is applied to this historical packet.
    pub fn quote(bytes: &'a [u8]) -> Result<Self, Fault> {
        walk(bytes, Mode::Quote)
    }

    /// The base header's length plus the Payload Length.
    pub fn declared_len(&self) -> usize {
        self.declared
    }

    /// Offset of the upper-layer header, or of the opaque data of a later
    /// fragment: the validated extent of the header chain.
    pub fn header_len(&self) -> usize {
        self.upper
    }

    /// The selector that ends the chain: the upper-layer protocol, No Next
    /// Header, or a later fragment's opaque Next Header.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Offset of the Next Header octet holding `protocol`.
    pub fn protocol_selector(&self) -> usize {
        self.selector
    }

    pub fn fragment(&self) -> Option<FragmentHeader> {
        self.fragment
    }

    pub fn completeness(&self) -> Completeness {
        match self.fragment {
            Some(f) if f.fragment_offset != 0 => Completeness::LaterFragment,
            _ if self.bytes.len() < self.declared => Completeness::Truncated,
            Some(f) if f.more_fragments => Completeness::InitialFragment,
            _ => Completeness::Complete,
        }
    }

    /// The Destination Address field of the base header.
    pub fn destination(&self) -> Ipv6Addr {
        address(&self.bytes[24..40])
    }

    /// The final destination of a quoted packet, used for transport
    /// pseudo-headers and to correlate feedback. With no Routing header, or
    /// when the last one has Segments Left zero, it is the base Destination
    /// Address. Otherwise the type of that Routing header decides (RFC 8754
    /// section 5.4 walks to the header before the upper layer): the last
    /// address of a well-formed Type 0 header (RFC 8201 section 5.2, written
    /// for it), Segment List[0] of a Segment Routing Header (RFC 8754
    /// section 2 stores the list in reverse). An unknown type, malformed
    /// type-specific fields, or an earlier Routing header that still has
    /// Segments Left above zero leave it unresolved: attribution is declined
    /// rather than guessed. A received packet resolves to its base
    /// destination unless a Routing header follows its Fragment header,
    /// because active Routing headers before it are refused.
    //= https://www.rfc-editor.org/rfc/rfc8201#section-5.2
    //= reason=Quote decoding walks the bounded quoted chain and locates the destination from the Routing header before the upper layer (ntcp_ip_common Chain::final_destination): with no Routing header or Segments Left equal to zero, the Destination Address field of the IPv6 header; with Segments Left greater than zero, by Routing type, the user's recorded disposition (decision A, D8) of this note, written for the Type 0 header: a Type 0 header's last address Address[n] (even Hdr Ext Len, 1 <= Segments Left <= n), and a Segment Routing Header's Segment List[0], its final segment (RFC 8754 section 2 stores the list in reverse; 2(Last Entry + 1) <= Hdr Ext Len and Segments Left <= Last Entry + 1); an unknown type, or an earlier Routing header still active, declines attribution rather than guessing. Type 0 evidence is quote-decoder evidence only: no Type 0 header is ever originated. A PTB quoting the Host's own SRH output is correlated only after the quoted list is validated against the route generation that authorized the submission (Segments Left and the base Destination Address may advance in flight). ntcp-icmp's extension_quote tests (an SRH and a Type 0 header whose first and last addresses differ, advanced and finished SRHs, unknown and ambiguous declines), the Host segment_routes PTB tests and the integration/rfc_host srh tun_echo case, in which a kernel PTB quotes Segments Left 1 with a base Destination Address S1 different from the final destination, verify it.
    //# Note: if the original packet contained a Routing header, the Routing header should be used to determine the location of the destination address within the original packet. If Segments Left is equal to zero, the destination address is in the Destination Address field in the IPv6 header. If Segments Left is greater than zero, the destination address is the last address (Address[n]) in the Routing header.
    pub fn final_destination(&self) -> Option<Ipv6Addr> {
        self.final_destination
    }

    /// Every traversed extension header in wire order.
    pub fn headers(&self) -> Headers<'a> {
        Headers {
            bytes: self.bytes,
            kind: self.bytes[6],
            offset: BASE_HEADER,
            end: self.upper,
        }
    }
}

/// Iterator over a validated chain's extension headers.
#[derive(Clone, Debug)]
pub struct Headers<'a> {
    bytes: &'a [u8],
    kind: u8,
    offset: usize,
    end: usize,
}

impl Iterator for Headers<'_> {
    type Item = ExtensionHeader;

    fn next(&mut self) -> Option<ExtensionHeader> {
        if self.offset >= self.end {
            return None;
        }
        let len = framed_len(self.kind, self.bytes, self.offset)?;
        let header = ExtensionHeader {
            kind: self.kind,
            offset: self.offset,
            len,
        };
        self.kind = self.bytes[self.offset];
        self.offset += len;
        Some(header)
    }
}

fn address(b: &[u8]) -> Ipv6Addr {
    let mut a = [0; 16];
    a.copy_from_slice(b);
    a.into()
}

fn is_extension(selector: u8) -> bool {
    matches!(
        selector,
        HOP_BY_HOP | ROUTING | FRAGMENT | DESTINATION_OPTIONS
    )
}

// Generic length of the header at `offset`, if its length field is present.
fn framed_len(kind: u8, bytes: &[u8], offset: usize) -> Option<usize> {
    match kind {
        FRAGMENT => Some(FRAGMENT_HEADER),
        _ => Some((usize::from(*bytes.get(offset + 1)?) + 1) * 8),
    }
}

// Final-destination state while walking Routing headers.
#[derive(Clone, Copy)]
enum Route {
    Base,
    Active(usize),
    Ambiguous,
}

fn walk(bytes: &[u8], mode: Mode) -> Result<Chain<'_>, Fault> {
    if bytes.len() < BASE_HEADER {
        return Err(Fault::Truncated);
    }
    if bytes[0] >> 4 != 6 {
        return Err(Fault::Version);
    }
    let declared = BASE_HEADER + usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    // A physically truncated packet is dropped before any of its headers
    // can draw an error.
    if mode == Mode::Receive && bytes.len() < declared {
        return Err(Fault::Truncated);
    }
    let mut selector = 6;
    let mut offset = BASE_HEADER;
    let mut fragment: Option<FragmentHeader> = None;
    let mut route = Route::Base;
    loop {
        let kind = bytes[selector];
        if !is_extension(kind) {
            break;
        }
        if kind == HOP_BY_HOP && offset != BASE_HEADER {
            return Err(Fault::MisplacedHopByHop { pointer: selector });
        }
        // A header after the Fragment header of an initial fragment must lie
        // within that fragment (RFC 7112 section 5); elsewhere a header past
        // the declared payload is an impossible length.
        let continued = fragment.is_some_and(|f| f.more_fragments);
        let beyond = |pointer| {
            if continued && bytes.len() >= declared {
                Fault::IncompleteChain
            } else {
                Fault::Length { pointer }
            }
        };
        // Every extension header occupies at least eight octets.
        if offset + FRAGMENT_HEADER > declared {
            return Err(beyond(PAYLOAD_LENGTH_FIELD));
        }
        let len_field = match kind {
            FRAGMENT => PAYLOAD_LENGTH_FIELD,
            _ => offset + 1,
        };
        let len = framed_len(kind, bytes, offset).ok_or(Fault::Truncated)?;
        let end = offset + len;
        if end > declared {
            return Err(beyond(len_field));
        }
        let header = bytes.get(offset..end).ok_or(Fault::Truncated)?;
        // Receive actions apply to the unfragmentable part only; the rest
        // is processed once the packet is reassembled.
        let act = mode == Mode::Receive && fragment.is_none();
        match kind {
            HOP_BY_HOP | DESTINATION_OPTIONS if act => options(header, offset)?,
            ROUTING => {
                if act && header[3] != 0 {
                    return Err(Fault::SegmentsLeft {
                        pointer: offset + 2,
                    });
                }
                route = match route {
                    Route::Active(_) => Route::Ambiguous,
                    Route::Base if header[3] != 0 => Route::Active(offset),
                    other => other,
                };
            }
            FRAGMENT if fragment.is_none() => {
                let f = fragment_fields(header, offset, selector);
                fragment = Some(f);
                if f.fragment_offset != 0 {
                    return Ok(chain(bytes, declared, end, offset, fragment, route));
                }
            }
            _ => {}
        }
        selector = offset;
        offset = end;
    }
    Ok(chain(bytes, declared, offset, selector, fragment, route))
}

fn chain(
    bytes: &[u8],
    declared: usize,
    upper: usize,
    selector: usize,
    fragment: Option<FragmentHeader>,
    route: Route,
) -> Chain<'_> {
    let final_destination = match route {
        Route::Base => Some(address(&bytes[24..40])),
        Route::Active(offset) => routed_destination(&bytes[offset..]),
        Route::Ambiguous => None,
    };
    Chain {
        bytes,
        declared,
        upper,
        selector,
        protocol: bytes[selector],
        fragment,
        final_destination,
    }
}

// Type-specific final destination of a framed Routing header whose Segments
// Left is above zero; `header` starts at the Routing header and holds all of
// it.
fn routed_destination(header: &[u8]) -> Option<Ipv6Addr> {
    let hdr_ext_len = usize::from(header[1]);
    let segments_left = usize::from(header[3]);
    match header[2] {
        ROUTING_TYPE_0 => {
            // Hdr Ext Len counts two units per address (RFC 5095 keeps the
            // RFC 2460 layout); Segments Left cannot exceed the addresses.
            let addresses = hdr_ext_len / 2;
            if hdr_ext_len % 2 != 0 || segments_left > addresses {
                return None;
            }
            let last = 8 + 16 * (addresses - 1);
            Some(address(header.get(last..last + 16)?))
        }
        ROUTING_TYPE_SRH => {
            // RFC 8754 section 2: Last Entry indexes the final element of a
            // list that must fit the header (TLVs may follow it), and
            // Segments Left equal to Last Entry + 1 is a reduced SRH.
            let entries = usize::from(header[4]) + 1;
            if 2 * entries > hdr_ext_len || segments_left > entries {
                return None;
            }
            Some(address(header.get(8..24)?))
        }
        _ => None,
    }
}

// Options of a Hop-by-Hop or Destination Options header at `offset`
// (RFC 8200 section 4.2). Pad1 and PadN are skipped; any other option is
// unrecognized here and its action applies.
fn options(header: &[u8], offset: usize) -> Result<(), Fault> {
    let mut p = 2;
    while p < header.len() {
        let kind = header[p];
        if kind == PAD1 {
            p += 1;
            continue;
        }
        let len = *header.get(p + 1).ok_or(Fault::Length {
            pointer: offset + p,
        })?;
        let end = p + 2 + usize::from(len);
        if end > header.len() {
            return Err(Fault::Length {
                pointer: offset + p + 1,
            });
        }
        if kind != PADN {
            let action = match kind >> 6 {
                0 => None,
                1 => Some(OptionAction::Discard),
                2 => Some(OptionAction::Report),
                _ => Some(OptionAction::ReportUnlessMulticast),
            };
            if let Some(action) = action {
                return Err(Fault::Option {
                    pointer: offset + p,
                    action,
                });
            }
        }
        p = end;
    }
    Ok(())
}
