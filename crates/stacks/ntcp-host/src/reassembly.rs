//! Bounded IPv4/IPv6 fragment reassembly: one engine per Host context, run on
//! arriving fragments after physical framing and local destination authority
//! are validated and before protocol demultiplexing.
//!
//! All storage is allocated fallibly once, from `ReassemblyLimits`: assembly
//! slots, fragment descriptors, one shared pool holding fragment data (and
//! each first fragment's header, retained for quoting), compaction scratch
//! and the output buffer for one reconstructed datagram. Network input has no
//! backpressure, so exhaustion of any bound discards the arriving fragment
//! and is counted; live assemblies are never evicted for newcomers.
//!
//! `Host::receive` (module `ingress`) feeds this engine and queues its
//! errors for the Host ICMP output.

use alloc::vec::Vec;
use core::net::IpAddr;
use ntcp::Instant;
use ntcp_path::{LinkId, SourceId};

use crate::Error;

/// Host reassembly configuration. Zero assemblies disables reassembly:
/// fragments are then discarded as before. Enabled reassembly must be able
/// to reconstruct at least an IPv4 datagram of 576 octets (RFC 1122 section
/// 3.3.2) and an IPv6 packet of 1500 octets (RFC 8200 section 5) under the
/// worst conforming fragmentation, so these limits are validated together.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReassemblyLimits {
    /// Concurrent datagrams under reassembly, IPv6 rejection markers
    /// included. Fragments of further datagrams are discarded.
    pub assemblies: usize,
    /// Distinct fragments one assembly holds (exact duplicates take none).
    pub fragments: usize,
    /// Octets buffered across all assemblies: every held fragment's data
    /// plus the header of each first fragment. One datagram may use all of
    /// it; physical input limits apply to each fragment separately.
    pub buffered_bytes: usize,
    /// Largest reconstructed IPv4 datagram, header included (Total Length,
    /// at most 65535).
    pub ipv4_datagram: usize,
    /// Largest reconstructed IPv6 packet, the 40-octet header included
    /// (Payload Length at most 65535, so at most 65575).
    pub ipv6_datagram: usize,
    /// Fixed IPv4 reassembly timeout in seconds, at least 1. RFC 1122
    /// section 3.3.2 recommends a fixed value between 60 and 120 seconds;
    /// Linux uses 30. The TTL of arriving fragments is never used.
    pub ipv4_timeout_seconds: u64,
}

/// RFC 8200 section 4.5: reassembly must complete within 60 seconds of the
/// first-arriving fragment.
const IPV6_TIMEOUT_SECONDS: u64 = 60;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
// Every fragment but the last carries a multiple of 8 data octets (RFC 791
// section 3.2, RFC 8200 section 4.5), so 8 is the smallest conforming
// non-final fragment: capacity is promised only as far as descriptors cover
// a datagram split into such fragments.
const MIN_FRAGMENT: usize = 8;

impl ReassemblyLimits {
    pub fn enabled(&self) -> bool {
        self.assemblies != 0
    }

    /// Largest complete IP datagram of the family that every configured
    /// bound admits under the worst conforming fragmentation: the
    /// reconstructed maximum, the buffered bytes (an IPv6 first fragment
    /// also stores its 8-octet Fragment header) and the descriptors at 8
    /// data octets each. None when disabled.
    pub fn datagram_capacity(&self, ipv6: bool) -> Option<usize> {
        if !self.enabled() {
            return None;
        }
        let (configured, header, stored_extra) = if ipv6 {
            (self.ipv6_datagram, IPV6_HEADER, ntcp_ip6::FRAGMENT_HEADER)
        } else {
            (self.ipv4_datagram, IPV4_HEADER, 0)
        };
        let descriptors = self
            .fragments
            .saturating_mul(MIN_FRAGMENT)
            .saturating_add(header);
        Some(
            configured
                .min(self.buffered_bytes.saturating_sub(stored_extra))
                .min(descriptors),
        )
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !self.enabled() {
            return Ok(());
        }
        let descriptors = self.assemblies.checked_mul(self.fragments);
        // The IPv4 timeout is the embedding's policy, RFC 1122's range only a
        // recommendation. A zero timeout would expire every assembly on its
        // first fragment; no value overflows, as deadlines saturate.
        if !(576..=65535).contains(&self.ipv4_datagram)
            || !(1500..=65575).contains(&self.ipv6_datagram)
            || self.ipv4_timeout_seconds == 0
            || descriptors.is_none_or(|n| n > u32::MAX as usize)
            || self.buffered_bytes > u32::MAX as usize
            || self.datagram_capacity(false).is_none_or(|n| n < 576)
            || self.datagram_capacity(true).is_none_or(|n| n < 1500)
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Counters for every reassembly outcome; each discard reason separately.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReassemblyCounters {
    pub held: u64,
    pub completed: u64,
    pub duplicates: u64,
    /// Assemblies discarded at their deadline.
    pub expired: u64,
    /// Assemblies discarded because their local address or link was retired.
    pub retired: u64,
    pub discarded: DiscardCounters,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscardCounters {
    pub source: u64,
    pub empty: u64,
    pub misaligned: u64,
    pub oversize: u64,
    pub capacity: u64,
    pub incomplete_header: u64,
    pub late: u64,
    pub rejected: u64,
    pub overlap: u64,
    pub conflict: u64,
    pub contradiction: u64,
    pub options: u64,
    pub ecn: u64,
    pub assemblies: u64,
    pub fragments: u64,
    pub bytes: u64,
}

/// Why an arriving fragment (or, for the last five reasons that invalidate
/// it, its whole assembly) was discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Discard {
    /// RFC 1122 section 3.2.1.3 / RFC 4291 section 2.7: the source cannot
    /// name a single host; checked before any state is allocated.
    Source,
    /// A non-final fragment without data.
    Empty,
    /// A non-final fragment whose data is not a multiple of 8 octets.
    Misaligned,
    /// The fragment ends beyond the largest datagram of its family: IPv4
    /// Total Length 65535, IPv6 Payload Length 65535.
    Oversize,
    /// The reconstructed datagram would exceed this Host's capacity.
    Capacity,
    /// An IPv6 first fragment without the whole header chain through the
    /// upper-layer header (RFC 7112, RFC 8200 section 4.5).
    IncompleteHeader,
    /// Its assembly's deadline has passed; the next expiry pass discards it.
    Late,
    /// An IPv6 rejection marker for this datagram is live.
    Rejected,
    /// IPv6 overlap other than an exact duplicate: the assembly is abandoned
    /// and leaves a rejection marker.
    Overlap,
    /// IPv4 overlap with different octets: the assembly is discarded.
    Conflict,
    /// Final boundaries disagree, or data lies beyond the final length or,
    /// once IPv6 fragment zero supplies the unfragmentable part, beyond the
    /// largest Payload Length.
    Contradiction,
    /// IPv4 copied options differ from the assembly's.
    Options,
    /// At completion, a CE fragment together with a Not-ECT fragment.
    Ecn,
    Assemblies,
    Fragments,
    Bytes,
}

/// Admission evidence from the Host: the arrival link, the local source
/// registration owning the destination there, and whether the link layer
/// addressed the frame to a multicast or broadcast destination (which
/// suppresses ICMP errors, RFC 1122 section 3.2.2 and RFC 4443 2.4(e)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Arrival {
    pub link: LinkId,
    pub local: SourceId,
    pub link_multicast: bool,
}

/// One arriving packet, normalized from either family's fragment parser.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Piece<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    /// IPv4 Protocol, or the IPv6 Fragment header's Next Header, which only
    /// fragment zero's selects the header that follows the unfragmentable
    /// part in the reconstructed packet.
    pub protocol: u8,
    /// IPv6: offset of the Next Header octet that selected the Fragment
    /// header (the base header's or the last unfragmentable extension's).
    pub selector: usize,
    /// IPv6 fragment zero: the protocol ending its header chain and that
    /// header's offset within `data` (after any extension headers that
    /// follow the Fragment header).
    pub upper_protocol: u8,
    pub upper: usize,
    pub identification: u32,
    pub offset: u32,
    pub more: bool,
    pub ecn: u8,
    /// The actual header as received: IPv4 with its options, IPv6 the
    /// unfragmentable part (the base header and the extension headers
    /// before the Fragment header) and the Fragment header.
    pub header: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> Piece<'a> {
    pub fn ipv4(packet: &ntcp_ip::FragmentPacket<'a>) -> Self {
        Self {
            source: packet.ip.source,
            destination: packet.ip.destination,
            protocol: packet.protocol,
            identification: u32::from(packet.fragmentation.identification),
            offset: u32::from(packet.fragmentation.offset),
            more: packet.fragmentation.more_fragments,
            ecn: packet.traffic_class & 3,
            selector: 0,
            upper_protocol: packet.protocol,
            upper: 0,
            header: packet.header,
            data: packet.payload,
        }
    }
    /// The received IPv6 packet `frame` whose chain the walker validated;
    /// None without a Fragment header.
    pub fn ipv6(frame: &'a [u8], chain: &ntcp_ip6::Chain<'a>) -> Option<Self> {
        let fragment = chain.fragment()?;
        let address = |b: &[u8]| IpAddr::from(<[u8; 16]>::try_from(b).unwrap());
        Some(Self {
            source: address(&frame[8..24]),
            destination: address(&frame[24..40]),
            protocol: fragment.next_header,
            selector: fragment.selector,
            upper_protocol: chain.protocol(),
            upper: chain.header_len() - fragment.data(),
            identification: fragment.identification,
            offset: u32::from(fragment.fragment_offset),
            more: fragment.more_fragments,
            ecn: (frame[1] >> 4) & 3,
            header: &frame[..fragment.data()],
            data: &frame[fragment.data()..],
        })
    }
    fn ipv6_family(&self) -> bool {
        self.source.is_ipv6()
    }
}

#[derive(Debug)]
pub(crate) enum Input<'a> {
    /// A complete datagram that needs no assembly state: an IPv4 packet with
    /// offset 0 and MF clear, or an IPv6 atomic fragment (RFC 6946). The
    /// caller processes the arriving packet itself.
    Whole,
    /// Stored; the datagram is still incomplete.
    Held,
    /// An exact duplicate (offset, extent, final flag and data): its ECN
    /// codepoint counted, nothing stored, no deadline change.
    Duplicate,
    Complete(Reassembled<'a>),
    Discarded(Discard),
}

/// A reconstructed datagram, valid until the next engine call. `packet` is
/// a complete IP packet: fragment zero's header (IPv4 options included) with
/// lengths, fragmentation fields, checksum and the RFC 3168 section 5.3 ECN
/// result rewritten; an IPv6 packet keeps fragment zero's unfragmentable
/// part, without its Fragment header, with the Next Header that selected it
/// repaired to the Fragment header's and the Payload Length counting the
/// retained extension headers (RFC 8200 section 4.5). `first_header` is
/// fragment zero's header exactly as it arrived (an IPv6 Fragment header
/// included), and `first_data` the length of fragment zero's data, so the
/// first fragment is `first_header` followed by that much data.
#[derive(Debug)]
pub(crate) struct Reassembled<'a> {
    pub packet: &'a [u8],
    pub arrival: Arrival,
    // Fragment zero as it arrived, for quoting by fragment-aware ICMP
    // correlation; Host dispatch reads only the reconstructed packet so far.
    #[cfg_attr(not(test), allow(dead_code))]
    pub first_header: &'a [u8],
    #[cfg_attr(not(test), allow(dead_code))]
    pub first_data: usize,
}

/// An assembly that expired after its fragment zero arrived: the invoking
/// packet for RFC 1122 section 3.3.2's (or RFC 8200 section 4.5's) Time
/// Exceeded is that first fragment as it arrived.
#[derive(Debug)]
pub(crate) struct Expired<'a> {
    pub arrival: Arrival,
    pub first_fragment: &'a [u8],
}

// Datagram identity. IPv4 (RFC 791 section 3.2): source, destination,
// protocol and Identification. IPv6 (RFC 8200 section 4.5): source,
// destination and Identification; the Fragment Next Header may differ
// between fragments and is not part of it. A link-local address names a
// node only within its link, so the arrival link joins the identity then.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key {
    source: IpAddr,
    destination: IpAddr,
    zone: Option<LinkId>,
    protocol: Option<u8>,
    identification: u32,
}

impl Key {
    fn new(
        arrival: Arrival,
        source: IpAddr,
        destination: IpAddr,
        protocol: Option<u8>,
        identification: u32,
    ) -> Self {
        Self {
            source,
            destination,
            zone: (is_link_local(source) || is_link_local(destination)).then_some(arrival.link),
            protocol,
            identification,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct First {
    header_len: usize,
    protocol: u8,
    // IPv6: the offset of the Next Header octet naming the Fragment header.
    selector: usize,
    arrival: Arrival,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    key: Key,
    // RFC 5722 / RFC 8200 section 4.5: an abandoned IPv6 datagram keeps its
    // slot and original deadline, holding no fragments, so its remaining
    // fragments cannot start a new assembly; it is never evicted.
    rejected: bool,
    deadline: Instant,
    arrival: Arrival,
    first: Option<First>,
    final_len: Option<u32>,
    // Bit per ECN codepoint seen among stored and duplicate fragments.
    ecn: u8,
    // IPv4 copied options of the first fragment that arrived.
    copied: [u8; 40],
    copied_len: Option<u8>,
    // Descriptors in use, sorted by offset.
    count: usize,
    charged: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct Descriptor {
    offset: u32,
    len: u32,
    // Start of this fragment's region in the pool; fragment zero's region
    // begins with its header, which an IPv6 unfragmentable part may make
    // longer than 255 octets.
    pool: u32,
    header: u32,
    last: bool,
}

impl Descriptor {
    fn end(&self) -> u32 {
        self.offset + self.len
    }
    fn region(&self) -> usize {
        self.header as usize + self.len as usize
    }
    fn data(&self) -> usize {
        self.pool as usize + self.header as usize
    }
}

pub(crate) struct Reassembly {
    limits: ReassemblyLimits,
    capacity: [usize; 2],
    units_per_second: u64,
    slots: Vec<Option<Slot>>,
    descriptors: Vec<Descriptor>,
    pool: Vec<u8>,
    // Pool octets below `top` are in use or garbage; `charged` counts the
    // live ones. Compaction moves live regions down when garbage blocks a
    // charge that fits.
    top: usize,
    charged: usize,
    scratch: Vec<u32>,
    output: Vec<u8>,
    counters: ReassemblyCounters,
}

fn storage<T: Clone>(count: usize, value: T) -> Result<Vec<T>, Error> {
    count
        .checked_mul(core::mem::size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    result.resize(count, value);
    Ok(result)
}

impl Reassembly {
    pub fn new(limits: ReassemblyLimits, units_per_second: u64) -> Result<Self, Error> {
        limits.validate()?;
        let capacity = [
            limits.datagram_capacity(false).unwrap_or(0),
            limits.datagram_capacity(true).unwrap_or(0),
        ];
        let descriptors = limits.assemblies * limits.fragments;
        let pool = if limits.enabled() {
            limits.buffered_bytes
        } else {
            0
        };
        Ok(Self {
            limits,
            capacity,
            units_per_second,
            slots: storage(limits.assemblies, None)?,
            descriptors: storage(descriptors, Descriptor::default())?,
            pool: storage(pool, 0)?,
            top: 0,
            charged: 0,
            scratch: storage(descriptors, 0)?,
            output: storage(capacity[0].max(capacity[1]), 0)?,
            counters: ReassemblyCounters::default(),
        })
    }

    pub fn limits(&self) -> ReassemblyLimits {
        self.limits
    }
    pub fn counters(&self) -> ReassemblyCounters {
        self.counters
    }
    /// Live assemblies and rejection markers.
    #[cfg(test)]
    pub fn assemblies(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    #[cfg(test)]
    pub fn buffered(&self) -> usize {
        self.charged
    }

    fn lifetime(&self, ipv6: bool) -> Instant {
        let seconds = if ipv6 {
            IPV6_TIMEOUT_SECONDS
        } else {
            self.limits.ipv4_timeout_seconds
        };
        seconds.saturating_mul(self.units_per_second)
    }

    /// Admit one arriving packet whose framing and local destination the
    /// Host already validated. Nothing is allocated before the source and
    /// the fragment's own fields are validated.
    pub fn input<'s>(&'s mut self, now: Instant, arrival: Arrival, piece: Piece<'_>) -> Input<'s> {
        let result = self.admit(now, arrival, piece);
        let counters = &mut self.counters;
        match &result {
            Ok(Admitted::Whole) => {}
            Ok(Admitted::Held) => counters.held += 1,
            Ok(Admitted::Duplicate) => counters.duplicates += 1,
            Ok(Admitted::Complete(_)) => counters.completed += 1,
            Err(discard) => {
                let d = &mut counters.discarded;
                *match discard {
                    Discard::Source => &mut d.source,
                    Discard::Empty => &mut d.empty,
                    Discard::Misaligned => &mut d.misaligned,
                    Discard::Oversize => &mut d.oversize,
                    Discard::Capacity => &mut d.capacity,
                    Discard::IncompleteHeader => &mut d.incomplete_header,
                    Discard::Late => &mut d.late,
                    Discard::Rejected => &mut d.rejected,
                    Discard::Overlap => &mut d.overlap,
                    Discard::Conflict => &mut d.conflict,
                    Discard::Contradiction => &mut d.contradiction,
                    Discard::Options => &mut d.options,
                    Discard::Ecn => &mut d.ecn,
                    Discard::Assemblies => &mut d.assemblies,
                    Discard::Fragments => &mut d.fragments,
                    Discard::Bytes => &mut d.bytes,
                } += 1;
            }
        }
        match result {
            Ok(Admitted::Whole) => Input::Whole,
            Ok(Admitted::Held) => Input::Held,
            Ok(Admitted::Duplicate) => Input::Duplicate,
            Ok(Admitted::Complete(c)) => Input::Complete(Reassembled {
                packet: &self.output[..c.len],
                arrival: c.arrival,
                // Released regions keep their bytes until the next charge.
                first_header: &self.pool[c.first_header..][..c.first_header_len],
                first_data: c.first_data,
            }),
            Err(discard) => Input::Discarded(discard),
        }
    }

    /// Discard (counted) an arriving IPv6 fragment of `identification`
    /// whose datagram has a live rejection marker, before receive
    /// processing of its headers could answer it with an ICMP error (the
    /// marker's precedence in `admit`, for a packet refused before it).
    pub fn rejects(
        &mut self,
        now: Instant,
        arrival: Arrival,
        source: IpAddr,
        destination: IpAddr,
        identification: u32,
    ) -> bool {
        let key = Key::new(arrival, source, destination, None, identification);
        let marked = self.marked(now, key);
        if marked {
            self.counters.discarded.rejected += 1;
        }
        marked
    }

    fn marked(&self, now: Instant, key: Key) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|s| s.rejected && s.key == key && now < s.deadline)
    }

    fn admit(&mut self, now: Instant, arrival: Arrival, p: Piece<'_>) -> Result<Admitted, Discard> {
        let ipv6 = p.ipv6_family();
        if p.offset == 0 && !p.more {
            return Ok(Admitted::Whole);
        }
        if !admissible_source(p.source) {
            return Err(Discard::Source);
        }
        if !self.limits.enabled() {
            return Err(Discard::Assemblies);
        }
        let key = Key::new(
            arrival,
            p.source,
            p.destination,
            (!ipv6).then_some(p.protocol),
            p.identification,
        );
        // RFC 5722 section 4:
        //   When reassembling an IPv6 datagram, if one or more of its
        //   constituent fragments is determined to be an overlapping
        //   fragment, the entire datagram (and any constituent fragments,
        //   including those not yet received) MUST be silently discarded.
        // A live rejection marker therefore discards its datagram's later
        // fragments before any check that could answer them with an ICMP
        // error (RFC 8200 section 4.5: no ICMP error messages for an
        // abandoned overlapping packet). After the marker's deadline the
        // key is no longer that datagram's.
        if self.marked(now, key) {
            return Err(Discard::Rejected);
        }
        let len = u32::try_from(p.data.len()).map_err(|_| Discard::Oversize)?;
        if p.more && len == 0 {
            return Err(Discard::Empty);
        }
        // RFC 8200 section 4.5:
        //   If the length of a fragment, as derived from the fragment packet's
        //   Payload Length field, is not a multiple of 8 octets and the M flag
        //   of that fragment is 1, then that fragment must be discarded
        // RFC 791 section 3.2 likewise sends every non-final IPv4 fragment
        // on an 8-octet boundary.
        if p.more && len % 8 != 0 {
            return Err(Discard::Misaligned);
        }
        let end = p.offset.checked_add(len).ok_or(Discard::Oversize)?;
        // The reconstructed header: an IPv6 packet keeps fragment zero's
        // unfragmentable part once it is held (RFC 8200 section 4.5), this
        // fragment's own until then.
        let base = if ipv6 {
            self.slots
                .iter()
                .flatten()
                .find(|s| s.key == key)
                .and_then(|s| s.first)
                .map_or(p.header.len(), |first| first.header_len)
                - ntcp_ip6::FRAGMENT_HEADER
        } else {
            IPV4_HEADER
        };
        // RFC 8200 section 4.5: a Payload Length of the packet reassembled
        // from this fragment beyond 65535, its extension headers included;
        // RFC 791 section 3.1: an IPv4 Total Length beyond 65535.
        if (ipv6 && oversize(base, end as usize)) || (!ipv6 && end as usize + IPV4_HEADER > 65535) {
            return Err(Discard::Oversize);
        }
        let capacity = self.capacity[usize::from(ipv6)];
        if end as usize + base > capacity {
            return Err(Discard::Capacity);
        }
        // RFC 8200 section 4.5:
        //   If the first fragment does not include all headers through an
        //   Upper-Layer header, then that fragment should be discarded and
        //   an ICMP Parameter Problem, Code 3, message should be sent to the
        //   source of the fragment, with the Pointer field set to zero.
        // IPv4 has no such rule: a legal tiny first fragment is accepted.
        if ipv6 && p.offset == 0 && !upper_layer_complete(p.upper_protocol, &p.data[p.upper..]) {
            return Err(Discard::IncompleteHeader);
        }
        let copied = if ipv6 {
            None
        } else {
            let mut copied = [0; 40];
            let len = ntcp::copied_fragment_options(&p.header[IPV4_HEADER..], &mut copied)
                .map_err(|_| Discard::Options)?;
            Some((copied, len as u8))
        };
        let found = self
            .slots
            .iter()
            .position(|s| s.is_some_and(|s| s.key == key));
        let index = match found {
            Some(index) => {
                let slot = self.slots[index].as_ref().unwrap();
                // A live rejection marker was answered above.
                if slot.deadline <= now {
                    return Err(Discard::Late);
                }
                index
            }
            None => {
                let index = self
                    .slots
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Discard::Assemblies)?;
                // Lifetime from the first-arriving fragment, never derived
                // from TTL and never refreshed (RFC 8200 section 4.5, RFC
                // 1122 section 3.3.2).
                self.slots[index] = Some(Slot {
                    key,
                    rejected: false,
                    deadline: now.saturating_add(self.lifetime(ipv6)),
                    arrival,
                    first: None,
                    final_len: None,
                    ecn: 0,
                    copied: [0; 40],
                    copied_len: None,
                    count: 0,
                    charged: 0,
                });
                index
            }
        };
        let outcome = self.add(index, arrival, p, end, copied);
        // A slot created for a fragment that was then refused holds nothing.
        if found.is_none()
            && let Some(slot) = self.slots[index]
            && slot.count == 0
            && !slot.rejected
        {
            self.slots[index] = None;
        }
        outcome
    }

    fn add(
        &mut self,
        index: usize,
        arrival: Arrival,
        p: Piece<'_>,
        end: u32,
        copied: Option<([u8; 40], u8)>,
    ) -> Result<Admitted, Discard> {
        let ipv6 = p.ipv6_family();
        let fragments = self.limits.fragments;
        let base = index * fragments;
        let mut slot = self.slots[index].unwrap();
        // RFC 791 section 3.2:
        //   the options field is copied
        // Copied options must agree among all fragments of one datagram:
        // their immutable content is the original datagram's. A source
        // route's recorded addresses and pointer are rewritten in transit
        // and only its kind and length are compared; non-copied options
        // (fragment zero's alone) and TTL/DSCP may differ, the reassembled
        // datagram keeping fragment zero's (RFC 815).
        if let Some((copied, len)) = copied {
            match slot.copied_len {
                None => {
                    slot.copied = copied;
                    slot.copied_len = Some(len);
                }
                Some(reference)
                    if !same_copied(
                        &slot.copied[..usize::from(reference)],
                        &copied[..usize::from(len)],
                    ) =>
                {
                    self.release(index);
                    return Err(Discard::Options);
                }
                Some(_) => {}
            }
        }
        // RFC 3168 section 5.3:
        //   Reassembly of a fragmented packet MUST NOT lose indications of
        //   congestion.
        // Every validated fragment of the datagram counts: stored, exact
        // duplicate (evaluated before duplicate elimination) or refused for
        // space, so no copy that saw congestion is forgotten.
        slot.ecn |= 1 << p.ecn;
        let held = &self.descriptors[base..base + slot.count];
        let max_end = held.iter().map(Descriptor::end).max().unwrap_or(0);
        let verdict = held
            .iter()
            .filter(|d| d.offset < end && p.offset < d.end())
            .map(|d| {
                let stored = &self.pool[d.data()..][..d.len as usize];
                if d.offset == p.offset
                    && d.len as usize == p.data.len()
                    && d.last != p.more
                    && stored == p.data
                {
                    return Some(Ok(Admitted::Duplicate));
                }
                if ipv6 {
                    return Some(Err(Discard::Overlap));
                }
                // RFC 6864 section 4.2 keeps IPv4 overlap support: octets
                // present twice must agree, or they are not one datagram.
                let from = d.offset.max(p.offset);
                let to = d.end().min(end);
                let ours = &p.data[(from - p.offset) as usize..(to - p.offset) as usize];
                let theirs = &stored[(from - d.offset) as usize..(to - d.offset) as usize];
                (ours != theirs).then_some(Err(Discard::Conflict))
            })
            .find_map(|verdict| verdict);
        match verdict {
            Some(Ok(duplicate)) => {
                self.slots[index] = Some(slot);
                return Ok(duplicate);
            }
            // RFC 8200 section 4.5:
            //   If any of the fragments being reassembled overlap with any
            //   other fragments being reassembled for the same packet,
            //   reassembly of that packet must be abandoned and all the
            //   fragments that have been received for that packet must be
            //   discarded, and no ICMP error messages should be sent.
            Some(Err(Discard::Overlap)) => {
                self.slots[index].as_mut().unwrap().rejected = true;
                self.release(index);
                return Err(Discard::Overlap);
            }
            Some(Err(discard)) => {
                self.release(index);
                return Err(discard);
            }
            None => {}
        }
        // Final boundaries: one final length; no data at or beyond it from
        // a fragment claiming more, none beyond it at all.
        let contradiction = if p.more {
            slot.final_len.is_some_and(|f| end >= f)
        } else {
            slot.final_len.is_some_and(|f| f != end)
                || held
                    .iter()
                    .any(|d| d.end() > end || (!d.last && d.end() >= end))
        };
        if contradiction {
            self.release(index);
            return Err(Discard::Contradiction);
        }
        // The first fragment zero to arrive supplies the header; another
        // copy at offset zero (IPv4 overlap) stores its data only.
        let zero = p.offset == 0 && slot.first.is_none();
        let header_len = if zero { p.header.len() } else { 0 };
        // The datagram keeps fragment zero's actual header, IPv4 options or
        // the IPv6 unfragmentable part included, so its length counts
        // against the reconstructed limits; every stored extent is checked
        // again when fragment zero arrives after them.
        let stored = if ipv6 { ntcp_ip6::FRAGMENT_HEADER } else { 0 };
        let header = match slot.first {
            Some(first) => first.header_len - stored,
            None if zero => header_len - stored,
            None if ipv6 => IPV6_HEADER,
            None => IPV4_HEADER,
        };
        let extent = max_end.max(end) as usize;
        // Admission checked this fragment's own extent against its own
        // unfragmentable part; fragment zero's arrival can still place data
        // stored before it beyond the largest Payload Length, which no
        // single fragment caused.
        let refused = if ipv6 && oversize(header, extent) {
            Some(if zero {
                Discard::Contradiction
            } else {
                Discard::Oversize
            })
        } else if header + extent > self.capacity[usize::from(ipv6)] {
            Some(Discard::Capacity)
        } else {
            None
        };
        if let Some(discard) = refused {
            if zero {
                // Its header is what makes the datagram too large.
                self.release(index);
            } else {
                self.slots[index] = Some(slot);
            }
            return Err(discard);
        }
        if slot.count == fragments {
            self.slots[index] = Some(slot);
            return Err(Discard::Fragments);
        }
        let charge = header_len + p.data.len();
        if self.charged + charge > self.limits.buffered_bytes {
            self.slots[index] = Some(slot);
            return Err(Discard::Bytes);
        }
        if self.top + charge > self.pool.len() {
            self.slots[index] = Some(slot);
            self.compact();
            slot = self.slots[index].unwrap();
        }
        let at = self.top;
        self.pool[at..at + header_len].copy_from_slice(&p.header[..header_len]);
        self.pool[at + header_len..at + charge].copy_from_slice(p.data);
        self.top += charge;
        self.charged += charge;
        slot.charged += charge;
        let descriptor = Descriptor {
            offset: p.offset,
            len: p.data.len() as u32,
            pool: at as u32,
            header: header_len as u32,
            last: !p.more,
        };
        let held = &mut self.descriptors[base..base + slot.count + 1];
        let position = held[..slot.count].partition_point(|d| d.offset <= p.offset);
        held.copy_within(position..slot.count, position + 1);
        held[position] = descriptor;
        slot.count += 1;
        if !p.more {
            slot.final_len = Some(end);
        }
        if zero {
            slot.first = Some(First {
                header_len,
                protocol: p.protocol,
                selector: p.selector,
                arrival,
            });
        }
        self.slots[index] = Some(slot);
        self.complete(index)
    }

    // Reconstruct once fragment zero, the final fragment and every octet in
    // between are present.
    fn complete(&mut self, index: usize) -> Result<Admitted, Discard> {
        let slot = self.slots[index].unwrap();
        let (Some(first), Some(final_len)) = (slot.first, slot.final_len) else {
            return Ok(Admitted::Held);
        };
        let base = index * self.limits.fragments;
        let held = &self.descriptors[base..base + slot.count];
        let mut covered = 0;
        for d in held {
            if d.offset > covered {
                return Ok(Admitted::Held);
            }
            covered = covered.max(d.end());
        }
        if covered < final_len {
            return Ok(Admitted::Held);
        }
        let Some(ecn) = ecn_result(slot.ecn) else {
            self.release(index);
            return Err(Discard::Ecn);
        };
        let ipv6 = slot.key.source.is_ipv6();
        let zero = held[0];
        debug_assert_eq!((zero.offset, zero.header as usize), (0, first.header_len));
        // An IPv6 packet keeps the unfragmentable part, not the Fragment
        // header.
        let header = if ipv6 {
            first.header_len - ntcp_ip6::FRAGMENT_HEADER
        } else {
            first.header_len
        };
        let len = header + final_len as usize;
        let out = &mut self.output[..len];
        out[..header].copy_from_slice(&self.pool[zero.pool as usize..][..header]);
        for d in held {
            let data = &self.pool[d.data()..][..d.len as usize];
            out[header + d.offset as usize..][..data.len()].copy_from_slice(data);
        }
        if ipv6 {
            // Admission bounded the Payload Length by 65535.
            let payload = (len - IPV6_HEADER) as u16;
            out[4..6].copy_from_slice(&payload.to_be_bytes());
            out[first.selector] = first.protocol;
            out[1] = (out[1] & !0x30) | (ecn << 4);
        } else {
            out[1] = (out[1] & !3) | ecn;
            out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            // The datagram keeps fragment zero's DF; MF and offset clear.
            out[6] &= 0x40;
            out[7] = 0;
            out[10..12].fill(0);
            let sum = ntcp_ip_common::checksum(&out[..header]);
            out[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        let first_data = zero.len as usize;
        self.release(index);
        Ok(Admitted::Complete(Completion {
            len,
            arrival: first.arrival,
            first_header: zero.pool as usize,
            first_header_len: first.header_len,
            first_data,
        }))
    }

    // Free an assembly's fragments; the slot itself stays as it is.
    fn release(&mut self, index: usize) {
        let slot = self.slots[index].as_mut().unwrap();
        self.charged -= slot.charged;
        slot.charged = 0;
        slot.count = 0;
        slot.first = None;
        slot.final_len = None;
        if self.charged == 0 {
            self.top = 0;
        }
        if !slot.rejected {
            self.slots[index] = None;
        }
    }

    // Move every live region down to the start of the pool, in pool order.
    fn compact(&mut self) {
        let fragments = self.limits.fragments;
        let mut live = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            for d in 0..slot.count {
                self.scratch[live] = (index * fragments + d) as u32;
                live += 1;
            }
        }
        let descriptors = &mut self.descriptors;
        self.scratch[..live].sort_unstable_by_key(|i| descriptors[*i as usize].pool);
        let mut top = 0;
        for &i in &self.scratch[..live] {
            let d = &mut descriptors[i as usize];
            let region = d.region();
            self.pool
                .copy_within(d.pool as usize..d.pool as usize + region, top);
            d.pool = top as u32;
            top += region;
        }
        debug_assert_eq!(top, self.charged);
        self.top = top;
    }

    /// Discard every assembly whose deadline has passed or whose arrival
    /// link no longer owns its local address (`live`), oldest state first.
    /// `expired` receives each timed-out assembly whose fragment zero
    /// arrived, for its Time Exceeded; markers and retired assemblies are
    /// discarded silently. Runs on every Host service pass, with or without
    /// traffic.
    pub fn expire(
        &mut self,
        now: Instant,
        mut live: impl FnMut(LinkId, SourceId) -> bool,
        mut expired: impl FnMut(Expired<'_>),
    ) {
        for index in 0..self.slots.len() {
            let Some(slot) = self.slots[index] else {
                continue;
            };
            if !live(slot.arrival.link, slot.arrival.local) {
                self.counters.retired += 1;
            } else if slot.deadline <= now {
                self.counters.expired += 1;
                if let Some(first) = slot.first {
                    let zero = self.descriptors[index * self.limits.fragments];
                    expired(Expired {
                        arrival: first.arrival,
                        first_fragment: &self.pool[zero.pool as usize..][..zero.region()],
                    });
                }
            } else {
                continue;
            }
            self.slots[index].as_mut().unwrap().rejected = false;
            self.release(index);
        }
    }

    /// The earliest deadline of any assembly or marker, for embeddings that
    /// schedule their next service pass.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots.iter().flatten().map(|s| s.deadline).min()
    }
}

enum Admitted {
    Whole,
    Held,
    Duplicate,
    Complete(Completion),
}

struct Completion {
    len: usize,
    arrival: Arrival,
    // Fragment zero's header in the pool.
    first_header: usize,
    first_header_len: usize,
    first_data: usize,
}

// RFC 8200 section 4.5: the Payload Length of a packet reassembled with an
// unfragmentable part of `header` octets and `extent` fragmentable octets
// exceeds 65535.
fn oversize(header: usize, extent: usize) -> bool {
    header - IPV6_HEADER + extent > 65535
}

const NOT_ECT: u8 = 1 << 0;
const CE: u8 = 1 << 3;
const ECT1: u8 = 1 << 1;

// RFC 3168 section 5.3:
//   In other words, if any fragment of an IP packet to be
//   reassembled has the CE codepoint set, then one of two actions MUST be
//   taken:
// The complete table over the codepoints seen (None drops the datagram):
// - one codepoint only: kept unchanged (RFC 3168 section 5.3);
// - CE with any Not-ECT: dropped, since CE may not be set then and the
//   congestion indication may not be lost;
// - CE with ECT(0)/ECT(1) only: CE;
// - ECT(0) with ECT(1), no CE or Not-ECT: ECT(0). Both mean ECN-capable
//   and routers treat them alike (RFC 3168 section 5); a mixture names no
//   single sender choice, so the reassembler claims only classic ECT(0)
//   rather than ECT(1), which RFC 9331 reserves to identify L4S traffic;
// - ECT with Not-ECT, no CE: Not-ECT. No congestion indication exists to
//   lose, and a datagram partly sent Not-ECT (or bleached on the way) is
//   not claimed ECN-capable; dropping it would discard data for no signal.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# Reassembly of a fragmented packet MUST NOT lose indications of
//# congestion.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# In other words, if any fragment of an IP packet to be
//# reassembled has the CE codepoint set, then one of two actions MUST be
//# taken:
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# However, this
//# MUST NOT occur if any of the other fragments contributing to
//# this reassembly carries the Not-ECT codepoint.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# If both actions are applicable, either MAY be chosen.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# Reassembly of
//# a fragmented packet MUST NOT change the ECN codepoint when all of the
//# fragments carry the same codepoint.
//= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
//= reason=The Host reassembly engine records the ECN codepoint of every validated fragment of a datagram, including exact duplicates (evaluated before duplicate elimination) and fragments refused for space, and at completion applies one published table: identical codepoints are kept unchanged; CE with any Not-ECT fragment drops the datagram instead of reassembling it; CE with ECT(0)/ECT(1) fragments only yields CE; ECT(0) with ECT(1) yields ECT(0); ECT with Not-ECT yields Not-ECT. Other drops are the engine's validation and resource discards. Host::receive routes every received fragment through this engine before demultiplexing.
//# * The packet is dropped, instead of being reassembled, for any other reason.
pub(crate) fn ecn_result(seen: u8) -> Option<u8> {
    if seen & CE != 0 {
        return (seen & NOT_ECT == 0).then_some(3);
    }
    if seen & NOT_ECT != 0 {
        return Some(0);
    }
    Some(if seen == ECT1 { 1 } else { 2 })
}

// RFC 7112 and RFC 8200 section 4.5: fragment zero must hold the whole
// header chain through the upper-layer header. The walker already required
// every extension header after the Fragment header to lie within the
// fragment; `data` starts at the upper-layer header: a TCP header through
// its Data Offset, UDP's 8 octets, or the 8-octet fixed part every ICMPv6
// message has (RFC 4443 sections 2.1, 3 and 4). No Next Header needs
// nothing, and other upper layers are not interpreted here.
fn upper_layer_complete(protocol: u8, data: &[u8]) -> bool {
    match protocol {
        6 => data.len() >= 20 && data.len() >= usize::from(data[12] >> 4) * 4,
        17 | 58 => data.len() >= 8,
        _ => true,
    }
}

// RFC 1122 section 3.2.1.3: a host silently discards datagrams whose source
// is not a single host (this network, limited broadcast, Class D/E,
// loopback from outside). RFC 4291 sections 2.5.2, 2.5.3 and 2.7: IPv6
// unspecified, loopback and multicast sources likewise.
pub(crate) fn admissible_source(source: IpAddr) -> bool {
    match source {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_loopback()
                || a.octets()[0] == 0
                || a.octets()[0] >= 240)
        }
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast() || a.is_loopback()),
    }
}

fn is_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v) if v.is_unicast_link_local())
}

// Copied option lists (zero-padded projections) agree option by option:
// same kinds and lengths; content too, except for source routes.
fn same_copied(a: &[u8], b: &[u8]) -> bool {
    let (mut i, mut j) = (0, 0);
    loop {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(j).copied().unwrap_or(0);
        if x == 0 || y == 0 {
            return x == y;
        }
        let (Some(&lx), Some(&ly)) = (a.get(i + 1), b.get(j + 1)) else {
            return false;
        };
        let (lx, ly) = (usize::from(lx), usize::from(ly));
        if x != y || lx != ly || i + lx > a.len() || j + ly > b.len() {
            return false;
        }
        if !matches!(x, 131 | 137) && a[i..i + lx] != b[j..j + ly] {
            return false;
        }
        i += lx;
        j += ly;
    }
}
