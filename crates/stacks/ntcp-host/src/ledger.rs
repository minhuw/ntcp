//! Bounded evidence of physical IP submissions made through `Host`.
//!
//! An ICMP error is only plausible feedback if it quotes a packet this host
//! actually handed to a link. Connection-local TCP rings are written at output
//! selection and exclude datagrams, so physical evidence lives here: reserved
//! before the backend call, sealed after it without allocation or fallible
//! lookup. This is plausibility against off-path forgery, not authentication
//! against an attacker who has observed the exact packet.

use crate::Error;
use crate::live::Live;
use alloc::vec::Vec;
use core::net::IpAddr;
use ntcp::{ConnectionId, Instant, TransmitAttempt};
use ntcp_path::{LinkId, PathId};

/// Explicit ledger storage, allocated once by `Host::new`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerLimits {
    /// Concurrent owner records (TCP generations, datagram flows, and the
    /// stateless lane). Admitting a new owner is the only owner backpressure.
    pub owners: usize,
    /// Committed entries guaranteed to every owner; the owner's own oldest
    /// entry is evicted (into a tombstone) beyond this.
    pub history_per_owner: usize,
    /// Bytes per history entry the base was derived from (the configured
    /// MSS). A connection configured with a larger send buffer gets a
    /// fallibly allocated extension sized the same way (see `provision`).
    pub segment_bytes: usize,
    /// Reserved-but-unsealed physical attempts (each segment counts).
    pub concurrent_attempts: usize,
    /// Evicted datagrams whose exact signature stays correlatable for the
    /// horizon, shared by datagram owners (see `managed_udp_limits`).
    /// Beyond it the oldest signatures fold into their flow's own summary,
    /// which keeps them ambiguous at the cost of that flow's attribution.
    pub datagram_evidence: usize,
    /// How long an entry without delivery-based retirement (ACK-only/control,
    /// stateless, datagram) and every tombstone may still correlate, in
    /// caller time units. See `feedback_horizon`.
    pub feedback_horizon: Instant,
}

/// Default horizon: one maximum segment lifetime for the original packet to
/// reach the reporting router plus one for the ICMP error to return. RFC 8085
/// section 3.3 relies on the same two-minute MSL for delayed datagrams but
/// sets no hard maximum, so the embedding's configured MSL is the bound.
pub fn feedback_horizon(timebase: ntcp::CallerTimebase) -> Option<Instant> {
    timebase
        .max_segment_lifetime_us
        .checked_mul(2)?
        .checked_mul(timebase.units_per_second / 1_000_000)
}

/// The transport identity that held a physical submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    /// Exact Endpoint connection generation.
    Tcp(ConnectionId),
    /// Host datagram flow slot and its generation.
    Datagram { flow: usize, generation: u64 },
    /// Endpoint stateless control lane (resets, cookie SYN-ACKs).
    Stateless,
}

/// Transport fields a valid ICMP quote can carry. A TCP span is the
/// sequence space the segment consumed; `start == end` marks a segment that
/// consumed none (pure ACK, bare RST), identified by its sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selector {
    Tcp {
        source_port: u16,
        destination_port: u16,
        start: u32,
        end: u32,
    },
    /// A complete (unfragmented) UDP datagram.
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
        checksum: u16,
    },
    /// Fragment zero of a UDP datagram this Host source-fragmented (offset
    /// zero, MF / M set). Its leading data octets are the UDP header of the
    /// complete datagram, so these fields are its recorded data prefix;
    /// `length` exceeds the fragment's own data.
    UdpFirstFragment {
        source_port: u16,
        destination_port: u16,
        length: u16,
        checksum: u16,
    },
    /// A non-first fragment of a datagram this Host source-fragmented: no
    /// transport field is on the wire (RFC 791 section 3.2, RFC 8200 section
    /// 4.5), so the record is portless. `offset` is its data offset in
    /// octets, `more` its MF / M flag and `prefix` its leading data octets.
    /// `logical_ports` name the datagram's flow tuple for the owner's
    /// advice only; they are not on the wire and never take part in
    /// matching or in summary keys.
    Fragment {
        offset: u16,
        more: bool,
        prefix: FragmentPrefix,
        logical_ports: (u16, u16),
    },
    /// Another protocol; this Host submits only TCP and UDP.
    #[cfg(any(test, feature = "test-support"))]
    Other,
}

/// The first min(8, fragment data length) data octets of a non-first
/// fragment: what every ICMPv4 error quotes beyond the header (RFC 792,
/// RFC 1122 section 3.2.2), and the only content of such a fragment a quote
/// can be checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentPrefix {
    bytes: [u8; 8],
    len: u8,
}

impl FragmentPrefix {
    /// The leading octets of `data`, at most eight.
    pub fn new(data: &[u8]) -> Self {
        let len = data.len().min(8);
        let mut bytes = [0; 8];
        bytes[..len].copy_from_slice(&data[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    /// Whether a quoted prefix contains every octet recorded here. A quote
    /// that omits a recorded octet cannot be checked against it and so is
    /// not exact evidence.
    fn present_in(&self, quoted: &Self) -> bool {
        quoted.len >= self.len && quoted.bytes[..usize::from(self.len)] == *self.as_slice()
    }
}

/// Facts fixed at submission. The context is `link.context()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub link: LinkId,
    pub path: PathId,
    pub owner: Owner,
    pub source: IpAddr,
    /// Canonical final destination (not an IPv4 source-route hop).
    pub destination: IpAddr,
    /// Original DSCP; routers may remark the quoted copy.
    pub dscp: u8,
    /// Physical lengths, IP extension headers and options included, in the
    /// width of a packet length so that no header length is ever narrowed.
    pub header_len: u32,
    pub packet_len: u32,
    pub protocol: u8,
    pub transport: Selector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub evidence: Evidence,
    pub committed_at: Instant,
    /// The backend outcome was unknown: never success, never unsent.
    pub possibly_submitted: bool,
}

/// What a quote may refer to, after IP/transport validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub header_len: u32,
    pub packet_len: u32,
    pub protocol: u8,
    pub transport: QuotedSelector,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotedSelector {
    Tcp {
        source_port: u16,
        destination_port: u16,
        sequence: u32,
    },
    /// A quoted complete UDP datagram.
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
        checksum: u16,
    },
    /// A quoted UDP fragment at offset zero with MF / M set; its UDP header
    /// is the complete datagram's.
    UdpFirstFragment {
        source_port: u16,
        destination_port: u16,
        length: u16,
        checksum: u16,
    },
    /// Any other quoted fragment: its position, MF / M flag and the leading
    /// data octets present in the quote. Nothing in it is parsed as a
    /// transport header, and its Identification is not part of it (RFC 6864
    /// section 4.1 limits the IPv4 ID to fragmentation and reassembly).
    Fragment {
        offset: u16,
        more: bool,
        prefix: FragmentPrefix,
    },
    Other,
}

/// Correlation of one quote with physical evidence.
///
/// Evidence is exact or lossy. Exact evidence (live entries and exact
/// evicted-datagram signatures) matched every selector field of a recorded
/// submission and is the only positive evidence: nothing may act on a quote
/// without it. Lossy history (tombstone summaries, merged covers, discarded
/// summaries) only admits what it might have held; it never creates a
/// match, a path or an owner, and only takes them away: a lossy hit denies
/// owner-level attribution, and withdraws path agreement unless it is known
/// to hold this same path incarnation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Correlation {
    /// Exact matches: live entries plus exact evicted-datagram signatures.
    pub matches: usize,
    /// Lossy history may also hold a submission this quote names.
    pub summarized: bool,
    /// Present only with an exact match, when every match and every lossy
    /// hit was submitted on this one path incarnation.
    pub path: Option<PathId>,
    /// Present only for exactly one live match and nothing else.
    #[cfg(any(test, feature = "test-support"))]
    pub unique: Option<Record>,
    /// Owner-level identity: every live match belongs to one owner generation
    /// and one submission, no evicted signature or tombstone matches, and the
    /// owner was not blinded by a discarded summary. Identical TCP segments
    /// (a retransmission of the same span) are one range; identical datagrams
    /// stay distinct submissions, so they are never merged here. The latest
    /// such record is reported.
    pub owner: Option<Record>,
    // Path agreement of every exact and lossy hit: None without any hit,
    // Some(None) when they disagree or a lossy hit's path is unknown.
    hits: Option<Option<PathId>>,
}

impl Correlation {
    fn hit(&self) -> bool {
        self.hits.is_some()
    }
    /// Combine the correlations of two alternative readings of one quote
    /// (RFC 1191's legacy length correction). Hits under both readings,
    /// lossy ones included, are ambiguous at the owner level and must agree
    /// on the path; the exact matches of either reading remain the only
    /// positive evidence.
    pub(crate) fn either(self, other: Self) -> Self {
        if !self.hit() {
            return other;
        }
        if !other.hit() {
            return self;
        }
        let hits = Some(self.hits.flatten().filter(|p| other.hits == Some(Some(*p))));
        let matches = self.matches + other.matches;
        Self {
            matches,
            summarized: self.summarized || other.summarized,
            path: hits.flatten().filter(|_| matches != 0),
            #[cfg(any(test, feature = "test-support"))]
            unique: None,
            owner: None,
            hits,
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    record: Record,
    order: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Pending {
    pub ticket: u64,
    pub owner: usize,
    pub attempt: Option<TransmitAttempt>,
    pub issued: bool,
    pub evidence: Option<Evidence>,
}

/// Whose evicted history a tombstone summarizes. Summaries never merge across
/// keys, so one flow's evictions cannot widen into another flow's quotes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Key {
    /// Exact addresses, protocol and ports, and the link of a link-local
    /// source (`zone`). Every generation sending under the same scoped
    /// four-tuple shares it, so reuse stays ambiguous; the same link-local
    /// four-tuple on another link is another flow.
    Flow {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        ports: Option<(u16, u16)>,
        zone: Option<LinkId>,
    },
    /// The stateless lane, whose replies go to arbitrary peers.
    Stateless,
}

impl Key {
    fn of(e: &Evidence) -> Self {
        match e.owner {
            Owner::Stateless => Self::Stateless,
            _ => Self::Flow {
                source: e.source,
                destination: e.destination,
                protocol: e.protocol,
                ports: ports(e.transport),
                zone: zone(e),
            },
        }
    }
    // Zones are compared by `Tombstone::admits`.
    fn admits(self, quote: &QuoteKey) -> bool {
        match self {
            Self::Flow {
                source,
                destination,
                protocol,
                ports,
                ..
            } => {
                (source, destination, protocol, ports)
                    == (
                        quote.source,
                        quote.destination,
                        quote.protocol,
                        quoted_ports(quote.transport),
                    )
            }
            Self::Stateless => true,
        }
    }
    // Whether an owner that last submitted under `self` may submit under
    // `other`: a datagram flow keeps its local binding but may send to any
    // remote it is not connected to.
    fn may_share(self, owner: Owner, other: Self) -> bool {
        match (owner, self, other) {
            (
                Owner::Datagram { .. },
                Self::Flow {
                    source: a,
                    protocol: p,
                    ports: Some((port, _)),
                    zone: x,
                    ..
                },
                Self::Flow {
                    source: b,
                    protocol: q,
                    ports: Some((other_port, _)),
                    zone: y,
                    ..
                },
            ) => (a, x, p, port) == (b, y, q, other_port),
            // A datagram flow's non-first fragments are recorded under the
            // portless key of their addresses and protocol (see `seal`, which
            // keeps the flow's own key), so any flow bound to that source
            // and protocol may have submitted under it.
            (
                Owner::Datagram { .. },
                Self::Flow {
                    source: a,
                    protocol: p,
                    ports: Some(_),
                    zone: x,
                    ..
                },
                Self::Flow {
                    source: b,
                    protocol: q,
                    ports: None,
                    zone: y,
                    ..
                },
            ) => (a, x, p) == (b, y, q),
            _ => self == other,
        }
    }
    // What `may_share` compares for a datagram owner: its local binding.
    fn binding(self) -> Option<(IpAddr, Option<LinkId>, u8, u16)> {
        match self {
            Self::Flow {
                source,
                protocol,
                ports: Some((port, _)),
                zone,
                ..
            } => Some((source, zone, protocol, port)),
            _ => None,
        }
    }
}

/// Horizons of discarded summaries, folded by key class. Each class keeps
/// the latest horizon of any discarded key hashing to it, so an owner is
/// only ever blinded too long or too broadly, never too little. A
/// collision costs an unrelated key attribution until that horizon (path-
/// level action is unaffected); an off-path sender that can churn flows to
/// overflow the summaries could already cause this for its own keys.
struct Discarded {
    // Exact keys (TCP generations, connected flows, the stateless lane).
    keys: Vec<Instant>,
    // Local bindings, which an unconnected datagram flow keeps across remotes.
    bindings: Vec<Instant>,
}

impl Discarded {
    fn class(&self, value: impl core::hash::Hash) -> usize {
        let mut hasher = Fnv(0xcbf2_9ce4_8422_2325);
        value.hash(&mut hasher);
        (core::hash::Hasher::finish(&hasher) % self.keys.len() as u64) as usize
    }
    fn record(&mut self, key: Key, until: Instant) {
        let class = self.class(key);
        self.keys[class] = self.keys[class].max(until);
        if let Some(binding) = key.binding() {
            let class = self.class(binding);
            self.bindings[class] = self.bindings[class].max(until);
        }
    }
    // Until when an owner submitting under `key` may share a discarded key.
    fn until(&self, owner: Owner, key: Key) -> Instant {
        match (owner, key.binding()) {
            (Owner::Datagram { .. }, Some(binding)) => self.bindings[self.class(binding)],
            _ => self.keys[self.class(key)],
        }
    }
    // Whether a discarded summary may have held a submission this quote
    // names: one of its own flow key's class (in the quote's zone), or
    // (unless a connection's match exists, see `correlate`) of the
    // stateless lane.
    fn shadows(
        &self,
        quote: &QuoteKey,
        zone: Option<LinkId>,
        connection: bool,
        now: Instant,
    ) -> bool {
        let flow = Key::Flow {
            source: quote.source,
            destination: quote.destination,
            protocol: quote.protocol,
            ports: quoted_ports(quote.transport),
            zone,
        };
        self.keys[self.class(flow)] > now
            || !connection && self.keys[self.class(Key::Stateless)] > now
    }
}

// FNV-1a: a fixed, allocation-free hash usable while sealing.
struct Fnv(u64);
impl core::hash::Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
}

/// Field-wise merge of one key's evicted history: a `None` field matches
/// anything, so merging only ever widens what the tombstone may match within
/// its key. Entries that consume no sequence space (pure ACKs, carrying
/// SND.NXT) are summarized apart from those that do, and both keep their
/// complete-length range: otherwise an evicted ACK's sequence point would
/// widen the cover over live data sent around it, and a quote of that data
/// (a different packet length) would be falsely ambiguous.
#[derive(Clone, Copy, Debug)]
struct Tombstone {
    key: Key,
    until: Instant,
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    protocol: Option<u8>,
    ports: Option<(u16, u16)>,
    path: Option<PathId>,
    // The zone of every summarized submission (None: unscoped); unknown
    // once they disagree, which only the stateless lane's key allows.
    zone: Option<Option<LinkId>>,
    // [sequence-consuming, datagram or other; zero-length TCP point].
    classes: [Option<Class>; 2],
}
#[derive(Clone, Copy, Debug)]
struct Class {
    lengths: (u32, u32),
    cover: Cover,
}

impl Tombstone {
    fn of(e: &Evidence, until: Instant) -> Self {
        let point = matches!(e.transport, Selector::Tcp { start, end, .. } if start == end);
        let mut classes = [None; 2];
        classes[usize::from(point)] = Some(Class {
            lengths: (e.packet_len, e.packet_len),
            cover: Cover::of(e.transport),
        });
        Self {
            key: Key::of(e),
            until,
            source: Some(e.source),
            destination: Some(e.destination),
            protocol: Some(e.protocol),
            ports: ports(e.transport),
            path: Some(e.path),
            zone: Some(zone(e)),
            classes,
        }
    }
    // Merge another summary of the same key.
    fn absorb(&mut self, other: &Self) {
        debug_assert_eq!(self.key, other.key);
        self.until = self.until.max(other.until);
        self.source = merge(self.source, other.source);
        self.destination = merge(self.destination, other.destination);
        self.protocol = merge(self.protocol, other.protocol);
        self.ports = merge(self.ports, other.ports);
        self.path = merge(self.path, other.path);
        self.zone = merge(self.zone, other.zone);
        for (mine, theirs) in self.classes.iter_mut().zip(other.classes) {
            let Some(theirs) = theirs else {
                continue;
            };
            *mine = Some(mine.map_or(theirs, |c| Class {
                lengths: (
                    c.lengths.0.min(theirs.lengths.0),
                    c.lengths.1.max(theirs.lengths.1),
                ),
                cover: c.cover.union(theirs.cover),
            }));
        }
    }
    // A scoped quote (`zone`) is admitted only by history of its own zone,
    // or of zones no longer known.
    fn admits(&self, quote: &QuoteKey, zone: Option<LinkId>) -> bool {
        self.key.admits(quote)
            && zone.is_none_or(|zone| self.zone.is_none_or(|z| z == Some(zone)))
            && self.source.is_none_or(|a| a == quote.source)
            && self.destination.is_none_or(|a| a == quote.destination)
            && self.protocol.is_none_or(|p| p == quote.protocol)
            && self
                .ports
                .is_none_or(|p| Some(p) == quoted_ports(quote.transport))
            && self.classes.iter().flatten().any(|c| {
                (c.lengths.0..=c.lengths.1).contains(&quote.packet_len)
                    && c.cover.contains(quote.transport)
            })
    }
}
#[derive(Clone, Copy, Debug)]
enum Cover {
    // Serial interval [start, end) of quoted sequence numbers.
    Sequence {
        start: u32,
        end: u32,
    },
    // UDP lengths, and the checksum while every summarized datagram agrees
    // on it. Only datagrams that overflowed the exact signature store are
    // summarized, and only within their own four-tuple. Whole datagrams and
    // first fragments of one flow share it (their four-tuple is one key).
    Length {
        min: u16,
        max: u16,
        checksum: Option<u16>,
    },
    // Non-first fragments of every flow between one address pair and
    // protocol (their portless key): the offset range, and MF while every
    // summarized fragment agrees on it. Data prefixes are not summarized,
    // so any prefix is admitted.
    Fragment {
        min: u16,
        max: u16,
        more: Option<bool>,
    },
    Any,
}

fn merge<T: PartialEq>(a: Option<T>, b: Option<T>) -> Option<T> {
    if a == b { a } else { None }
}

fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 1 << 31
}
fn serial_lt(a: u32, b: u32) -> bool {
    a != b && serial_le(a, b)
}

impl Cover {
    fn of(selector: Selector) -> Self {
        match selector {
            Selector::Tcp { start, end, .. } => Self::Sequence {
                start,
                end: if start == end {
                    start.wrapping_add(1)
                } else {
                    end
                },
            },
            Selector::Udp {
                length, checksum, ..
            }
            | Selector::UdpFirstFragment {
                length, checksum, ..
            } => Self::Length {
                min: length,
                max: length,
                checksum: Some(checksum),
            },
            Selector::Fragment { offset, more, .. } => Self::Fragment {
                min: offset,
                max: offset,
                more: Some(more),
            },
            #[cfg(any(test, feature = "test-support"))]
            Selector::Other => Self::Any,
        }
    }
    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Sequence { start: a, end: b }, Self::Sequence { start: c, end: d }) => {
                // Smallest serial interval covering both; give up (match
                // everything) rather than wrap past half the sequence space.
                let start = if serial_le(a, c) { a } else { c };
                let end = if serial_le(b, d) { d } else { b };
                if end.wrapping_sub(start) >= 1 << 31 {
                    Self::Any
                } else {
                    Self::Sequence { start, end }
                }
            }
            (
                Self::Length {
                    min: a,
                    max: b,
                    checksum: x,
                },
                Self::Length {
                    min: c,
                    max: d,
                    checksum: y,
                },
            ) => Self::Length {
                min: a.min(c),
                max: b.max(d),
                checksum: merge(x, y),
            },
            (
                Self::Fragment {
                    min: a,
                    max: b,
                    more: x,
                },
                Self::Fragment {
                    min: c,
                    max: d,
                    more: y,
                },
            ) => Self::Fragment {
                min: a.min(c),
                max: b.max(d),
                more: merge(x, y),
            },
            _ => Self::Any,
        }
    }
    fn contains(self, quote: QuotedSelector) -> bool {
        match (self, quote) {
            (Self::Any, _) => true,
            (Self::Sequence { start, end }, QuotedSelector::Tcp { sequence, .. }) => {
                sequence.wrapping_sub(start) < end.wrapping_sub(start)
            }
            (
                Self::Length { min, max, checksum },
                QuotedSelector::Udp {
                    length,
                    checksum: quoted,
                    ..
                }
                | QuotedSelector::UdpFirstFragment {
                    length,
                    checksum: quoted,
                    ..
                },
            ) => (min..=max).contains(&length) && checksum.is_none_or(|c| c == quoted),
            (
                Self::Fragment { min, max, more },
                QuotedSelector::Fragment {
                    offset, more: m, ..
                },
            ) => (min..=max).contains(&offset) && more.is_none_or(|more| more == m),
            _ => false,
        }
    }
}

// The link a submission's source address is scoped to: a link-local source
// names an address of its link only (the zone `correlate_in` receives for
// a quote of it), other sources are unscoped.
fn zone(e: &Evidence) -> Option<LinkId> {
    matches!(e.source, IpAddr::V6(v) if v.is_unicast_link_local()).then_some(e.link)
}

fn ports(selector: Selector) -> Option<(u16, u16)> {
    match selector {
        Selector::Tcp {
            source_port,
            destination_port,
            ..
        }
        | Selector::Udp {
            source_port,
            destination_port,
            ..
        }
        | Selector::UdpFirstFragment {
            source_port,
            destination_port,
            ..
        } => Some((source_port, destination_port)),
        Selector::Fragment { .. } => None,
        #[cfg(any(test, feature = "test-support"))]
        Selector::Other => None,
    }
}
fn quoted_ports(selector: QuotedSelector) -> Option<(u16, u16)> {
    match selector {
        QuotedSelector::Tcp {
            source_port,
            destination_port,
            ..
        }
        | QuotedSelector::Udp {
            source_port,
            destination_port,
            ..
        }
        | QuotedSelector::UdpFirstFragment {
            source_port,
            destination_port,
            ..
        } => Some((source_port, destination_port)),
        QuotedSelector::Fragment { .. } | QuotedSelector::Other => None,
    }
}

// Outstanding TCP data: retired by delivery, never by time while its
// generation lives.
fn retirable(record: &Record) -> bool {
    matches!(
        (record.evidence.owner, record.evidence.transport),
        (Owner::Tcp(_), Selector::Tcp { start, end, .. }) if start != end
    )
}

impl Entry {
    fn retirable(&self) -> bool {
        retirable(&self.record)
    }
    fn matches(&self, quote: &QuoteKey) -> bool {
        evidence_matches(&self.record.evidence, quote)
    }
}

fn evidence_matches(e: &Evidence, quote: &QuoteKey) -> bool {
    e.source == quote.source
        && e.destination == quote.destination
        && e.header_len == quote.header_len
        && e.packet_len == quote.packet_len
        && e.protocol == quote.protocol
        && match (e.transport, quote.transport) {
            (
                Selector::Tcp {
                    source_port,
                    destination_port,
                    start,
                    ..
                },
                QuotedSelector::Tcp {
                    source_port: s,
                    destination_port: d,
                    sequence,
                },
            ) => {
                // A quote names the first sequence number of the exact
                // physical segment; a later byte of a recorded span is a
                // different packet (tombstones stay range-conservative).
                (source_port, destination_port) == (s, d) && sequence == start
            }
            (
                Selector::Udp {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
                QuotedSelector::Udp {
                    source_port: s,
                    destination_port: d,
                    length: l,
                    checksum: c,
                },
            ) => (source_port, destination_port, length, checksum) == (s, d, l, c),
            // Fragment zero: the UDP selector is its recorded data prefix;
            // offset zero and MF are implied by both sides.
            (
                Selector::UdpFirstFragment {
                    source_port,
                    destination_port,
                    length,
                    checksum,
                },
                QuotedSelector::UdpFirstFragment {
                    source_port: s,
                    destination_port: d,
                    length: l,
                    checksum: c,
                },
            ) => (source_port, destination_port, length, checksum) == (s, d, l, c),
            // A later fragment carries no ports: only its exact physical
            // evidence (the common fields above, offset, MF and every
            // recorded data octet) identifies it, never its flow tuple and
            // never the IPv4 Identification (RFC 6864 section 4.1).
            (
                Selector::Fragment {
                    offset,
                    more,
                    prefix,
                    ..
                },
                QuotedSelector::Fragment {
                    offset: o,
                    more: m,
                    prefix: quoted,
                },
            ) => (offset, more) == (o, m) && prefix.present_in(&quoted),
            #[cfg(any(test, feature = "test-support"))]
            (Selector::Other, QuotedSelector::Other) => true,
            _ => false,
        }
}

pub(crate) struct Ledger {
    limits: LedgerLimits,
    owners: Vec<Option<Owner>>,
    // Per endpoint connection slot (`ConnectionId::index`), the record of
    // its TCP owner generation, if any; empty until `index_connections`.
    tcp_owners: Vec<Option<usize>>,
    // Occupied owner records, unsealed reservations and summaries: what
    // the passes made on every collection visit (`check_live`).
    live_owners: Live,
    live_pending: Live,
    live_tombstones: Live,
    // No history entry without delivery retirement, evicted datagram
    // signature or summary expires before this, so `expire` has nothing
    // to remove until then. A lower bound: whatever leaves earlier by
    // another route leaves it in place.
    next_expiry: Instant,
    // Per owner record: the key its submissions use, and the time until
    // which it gets no owner-level attribution because a summary its quotes
    // could match was discarded (see `fold` and `seal`).
    keys: Vec<Option<Key>>,
    blind: Vec<Instant>,
    // Owner record i owns history[i * history_per_owner ..][..history_per_owner]
    // and then extra[i] (see `provision`).
    history: Vec<Option<Entry>>,
    extra: Vec<Vec<Option<Entry>>>,
    // Per owner record: its occupied history slots, and how many of them are
    // retirable (outstanding TCP data). Passes over a record's history stop
    // once they have seen every occupied slot, and delivery retirement skips
    // a record with nothing retirable: an idle connection's history is
    // mostly empty slots and pure ACKs.
    occupied: Vec<usize>,
    retirable: Vec<usize>,
    // Per owner record: the SND.UNA its delivery retirement last ran at,
    // while neither its history nor its own summary changed since.
    // Retirement is idempotent, so another pass at that SND.UNA, which every
    // collection makes for every live connection, has nothing to do.
    retired: Vec<Option<u32>>,
    // A live TCP generation's own evicted history. It is kept apart from the
    // shared summaries so delivery can shrink it (`retire_tcp`): otherwise a
    // long transfer's evictions would widen one cover until it matched every
    // quote of the connection, including its newest live segments. It joins
    // the shared summary of its four-tuple when the generation is released.
    own: Vec<Option<Tombstone>>,
    pending: Vec<Option<Pending>>,
    // Exact evicted datagrams, each until its own horizon.
    datagrams: Vec<Option<(Evidence, Instant)>>,
    tombstones: Vec<Option<Tombstone>>,
    discarded: Discarded,
    order: u64,
    tickets: u64,
    #[cfg(test)]
    discards: usize,
}

impl Ledger {
    /// How long network evidence about a submission can still arrive.
    pub(crate) fn feedback_horizon(&self) -> Instant {
        self.limits.feedback_horizon
    }

    pub fn new(limits: LedgerLimits) -> Result<Self, Error> {
        if limits.owners == 0 || limits.history_per_owner == 0 || limits.concurrent_attempts == 0 {
            return Err(Error::Capacity);
        }
        let entries = limits
            .owners
            .checked_mul(limits.history_per_owner)
            .ok_or(Error::Capacity)?;
        let summaries = limits.owners.checked_mul(2).ok_or(Error::Capacity)?;
        Ok(Self {
            limits,
            owners: crate::table(limits.owners, None)?,
            tcp_owners: Vec::new(),
            live_owners: Live::new(limits.owners)?,
            live_pending: Live::new(limits.concurrent_attempts)?,
            live_tombstones: Live::new(summaries)?,
            next_expiry: Instant::MAX,
            keys: crate::table(limits.owners, None)?,
            blind: crate::table(limits.owners, 0)?,
            history: crate::table(entries, None)?,
            extra: crate::table(limits.owners, Vec::new())?,
            occupied: crate::table(limits.owners, 0)?,
            retirable: crate::table(limits.owners, 0)?,
            retired: crate::table(limits.owners, None)?,
            own: crate::table(limits.owners, None)?,
            pending: crate::table(limits.concurrent_attempts, None)?,
            datagrams: crate::table(limits.datagram_evidence, None)?,
            // A connection or connected datagram flow submits under one key,
            // as does the stateless lane, and each record can retain one
            // released predecessor's key until the horizon. Unconnected flows
            // talking to more remotes than this rely on `fold`'s discard.
            tombstones: crate::table(summaries, None)?,
            // One class per summary slot: a discard only happens when every
            // slot is live, so the classes scale with the churn the
            // summaries were sized for.
            discarded: Discarded {
                keys: crate::table(summaries, 0)?,
                bindings: crate::table(summaries, 0)?,
            },
            order: 0,
            tickets: 0,
            #[cfg(test)]
            discards: 0,
        })
    }
    #[cfg(test)]
    pub fn limits(&self) -> LedgerLimits {
        self.limits
    }
    // History slots of an owner record: the guaranteed base, then its
    // extension.
    fn slots(&self, owner: usize) -> usize {
        self.limits.history_per_owner + self.extra[owner].len()
    }
    fn slot(&self, owner: usize, i: usize) -> Option<&Entry> {
        let h = self.limits.history_per_owner;
        if i < h {
            self.history[owner * h + i].as_ref()
        } else {
            self.extra[owner][i - h].as_ref()
        }
    }
    // The only writer of history slots: keeps the occupancy counts.
    fn set_slot(&mut self, owner: usize, i: usize, value: Option<Entry>) -> Option<Entry> {
        let h = self.limits.history_per_owner;
        let slot = if i < h {
            &mut self.history[owner * h + i]
        } else {
            &mut self.extra[owner][i - h]
        };
        let old = core::mem::replace(slot, value);
        self.retired[owner] = None;
        for (entry, added) in [(&old, false), (&value, true)] {
            let Some(entry) = entry else {
                continue;
            };
            let retirable = usize::from(entry.retirable());
            if added {
                self.occupied[owner] += 1;
                self.retirable[owner] += retirable;
            } else {
                self.occupied[owner] -= 1;
                self.retirable[owner] -= retirable;
            }
        }
        old
    }
    // A record's occupied history slots in order; it stops at the last one.
    // Callers do not change the record's history while iterating.
    fn occupied_slots(&self, owner: usize) -> impl Iterator<Item = usize> + '_ {
        let (mut slot, mut remaining) = (0, self.occupied[owner]);
        core::iter::from_fn(move || {
            while remaining != 0 && slot < self.slots(owner) {
                let current = slot;
                slot += 1;
                if self.slot(owner, current).is_some() {
                    remaining -= 1;
                    return Some(current);
                }
            }
            None
        })
    }
    /// Before a physical call: extend an owner's history to one entry per
    /// segment of `send_capacity` plus one control segment, the derivation
    /// of the base. Sockets may configure larger send buffers than the
    /// default the base was sized from (SO_SNDBUF); without room for the
    /// whole window, feedback for its oldest segments, which a PTB names
    /// first, would find only ambiguous history. The extension is bounded
    /// by the Endpoint's buffer budget, allocated fallibly (failure leaves
    /// same-owner eviction) and freed with the owner record.
    pub fn provision(&mut self, owner: usize, send_capacity: usize) {
        let wanted = send_capacity
            .div_ceil(self.limits.segment_bytes.max(1))
            .saturating_add(1)
            .saturating_sub(self.limits.history_per_owner);
        let extra = &mut self.extra[owner];
        if wanted > extra.len() && extra.try_reserve_exact(wanted - extra.len()).is_ok() {
            extra.resize(wanted, None);
        }
    }
    /// Index TCP owners by their connections' slots, of an endpoint with
    /// `connections` slots.
    pub fn index_connections(&mut self, connections: usize) -> Result<(), Error> {
        self.tcp_owners
            .try_reserve_exact(connections)
            .map_err(|_| Error::Allocation)?;
        self.tcp_owners.resize(connections, None);
        for index in self.live_owners.iter() {
            if let Some(Owner::Tcp(id)) = self.owners[index] {
                self.tcp_owners[id.index()] = Some(index);
            }
        }
        Ok(())
    }
    pub fn owner_index(&self, owner: Owner) -> Option<usize> {
        // The index names the newest generation admitted in a slot; an
        // older one still holding history is found by the scan.
        if let Owner::Tcp(id) = owner
            && let Some(Some(index)) = self.tcp_owners.get(id.index()).copied()
            && self.owners[index] == Some(owner)
        {
            return Some(index);
        }
        self.live_owners
            .iter()
            .find(|&index| self.owners[index] == Some(owner))
    }
    /// The first occupied owner record at or after `from`.
    pub fn next_owner(&self, from: usize) -> Option<usize> {
        self.live_owners.next(from)
    }
    /// Existing record, or a free one. Callers release dead owners first.
    pub fn admit(&mut self, owner: Owner) -> Result<usize, Error> {
        if let Some(index) = self.owner_index(owner) {
            return Ok(index);
        }
        let index = self
            .owners
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.owners[index] = Some(owner);
        self.live_owners.insert(index);
        if let Owner::Tcp(id) = owner
            && let Some(entry) = self.tcp_owners.get_mut(id.index())
        {
            *entry = Some(index);
        }
        self.keys[index] = None;
        self.blind[index] = 0;
        self.own[index] = None;
        self.retired[index] = None;
        Ok(index)
    }
    pub fn owner_pinned(&self, index: usize) -> bool {
        self.live_pending
            .iter()
            .any(|p| self.pending[p].is_some_and(|p| p.owner == index))
    }
    /// Fold remaining history into tombstones and free the record. Pinned
    /// owners (unsealed reservations) are never released.
    pub fn release_owner(&mut self, index: usize, now: Instant) -> bool {
        if self.owners[index].is_none() || self.owner_pinned(index) {
            return false;
        }
        for i in 0..self.slots(index) {
            if self.occupied[index] == 0 {
                break;
            }
            if let Some(entry) = self.set_slot(index, i, None) {
                self.bury(entry.record, now);
            }
        }
        if let Some(own) = self.own[index].take().filter(|t| t.until > now) {
            self.fold(own, now);
        }
        self.extra[index] = Vec::new();
        if let Some(Owner::Tcp(id)) = self.owners[index]
            && let Some(entry) = self.tcp_owners.get_mut(id.index())
            && *entry == Some(index)
        {
            *entry = None;
        }
        self.owners[index] = None;
        self.live_owners.remove(index);
        self.keys[index] = None;
        self.blind[index] = 0;
        self.retired[index] = None;
        true
    }

    /// Idempotent per attempt: the same physical attempt always owns one
    /// reservation. A retained ticket of the same owner whose rejected
    /// attempt is no longer live (`stale`) is re-keyed to the new attempt.
    pub fn reserve(
        &mut self,
        owner: usize,
        attempt: TransmitAttempt,
        stale: impl Fn(TransmitAttempt) -> bool,
    ) -> Result<usize, Error> {
        if let Some(index) = self
            .live_pending
            .iter()
            .find(|&i| self.pending[i].is_some_and(|p| p.attempt == Some(attempt)))
        {
            return if self.pending[index].unwrap().owner == owner {
                Ok(index)
            } else {
                Err(Error::Obsolete)
            };
        }
        if let Some(index) = self.live_pending.iter().find(|&i| {
            self.pending[i]
                .is_some_and(|p| p.owner == owner && p.issued && p.attempt.is_none_or(&stale))
        }) {
            let p = self.pending[index].as_mut().unwrap();
            p.attempt = Some(attempt);
            p.evidence = None;
            return Ok(index);
        }
        self.reserve_slot(owner, Some(attempt))
    }
    fn reserve_slot(
        &mut self,
        owner: usize,
        attempt: Option<TransmitAttempt>,
    ) -> Result<usize, Error> {
        let index = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.tickets += 1;
        self.pending[index] = Some(Pending {
            ticket: self.tickets,
            owner,
            attempt,
            issued: false,
            evidence: None,
        });
        self.live_pending.insert(index);
        Ok(index)
    }
    /// Pre-reserve every segment one aggregated physical call may emit; the
    /// whole group shares one ticket and seals or cancels together. A single
    /// datagram is a group of one whose evidence is complete before the call.
    pub fn reserve_group(&mut self, owner: usize, evidence: &[Evidence]) -> Result<u64, Error> {
        if evidence.is_empty() || self.pending.len() - self.live_pending.len() < evidence.len() {
            return Err(Error::Capacity);
        }
        let first = self.reserve_slot(owner, None)?;
        let ticket = self.pending[first].unwrap().ticket;
        self.pending[first].as_mut().unwrap().evidence = Some(evidence[0]);
        for e in &evidence[1..] {
            let index = self.pending.iter().position(Option::is_none).unwrap();
            self.pending[index] = Some(Pending {
                ticket,
                owner,
                attempt: None,
                issued: false,
                evidence: Some(*e),
            });
            self.live_pending.insert(index);
        }
        Ok(ticket)
    }
    pub fn set_evidence(&mut self, index: usize, evidence: Evidence) {
        self.pending[index].as_mut().unwrap().evidence = Some(evidence);
    }
    pub fn has_evidence(&self, index: usize) -> bool {
        self.pending[index].is_some_and(|p| p.evidence.is_some())
    }
    /// Issue the single ticket for this reservation.
    pub fn issue(&mut self, index: usize) -> Result<u64, Error> {
        let p = self.pending[index].as_mut().ok_or(Error::Obsolete)?;
        if p.issued {
            return Err(Error::InvalidContext);
        }
        p.issued = true;
        Ok(p.ticket)
    }
    pub fn find_ticket(&self, ticket: u64) -> Option<usize> {
        self.live_pending
            .iter()
            .find(|&i| self.pending[i].is_some_and(|p| p.ticket == ticket))
    }
    pub fn pending(&self, index: usize) -> Option<Pending> {
        self.pending[index]
    }
    /// The first unsealed reservation at or after `from`.
    pub fn next_pending(&self, from: usize) -> Option<usize> {
        self.live_pending.next(from)
    }
    /// Reclaim an unsealed reservation no physical call can still use.
    pub fn drop_pending(&mut self, index: usize) {
        if self.pending[index].take().is_some() {
            self.live_pending.remove(index);
        }
    }
    pub fn owner(&self, index: usize) -> Option<Owner> {
        self.owners[index]
    }
    /// Certified non-submission: drop the reservation(s), record nothing.
    pub fn cancel(&mut self, ticket: u64) {
        let mut next = 0;
        while let Some(index) = self.live_pending.next(next) {
            next = index + 1;
            if self.pending[index].is_some_and(|p| p.ticket == ticket) {
                self.drop_pending(index);
            }
        }
    }
    /// Infallible, allocation-free commit of every segment of a ticket.
    /// Reservation guaranteed the owner record and the evidence.
    pub fn seal(&mut self, ticket: u64, now: Instant, possibly_submitted: bool) -> usize {
        let mut sealed = 0;
        let mut next = 0;
        while let Some(index) = self.live_pending.next(next) {
            next = index + 1;
            let Some(p) = self.pending[index].filter(|p| p.ticket == ticket) else {
                continue;
            };
            self.drop_pending(index);
            let Some(evidence) = p.evidence else {
                debug_assert!(false, "sealed reservation without validated evidence");
                continue;
            };
            let slot = self.victim(p.owner, now);
            if let Some(old) = self.set_slot(p.owner, slot, None) {
                self.evict(p.owner, old.record, now);
            }
            // A discarded summary of this key may hide an older identical
            // packet, so the old quote must not name this owner.
            let key = Key::of(&evidence);
            if let Some(owner) = self.owners[p.owner] {
                self.blind[p.owner] = self.blind[p.owner].max(self.discarded.until(owner, key));
            }
            // A non-first fragment's portless key is shared by every flow
            // between its addresses; the owner keeps the key of its flow
            // (sealed with fragment zero, which always precedes it), which
            // `may_share` relates to portless keys.
            if ports(evidence.transport).is_some() || self.keys[p.owner].is_none() {
                self.keys[p.owner] = Some(key);
            }
            self.order += 1;
            let record = Record {
                evidence,
                committed_at: now,
                possibly_submitted,
            };
            if !retirable(&record) {
                self.next_expiry = self.next_expiry.min(self.expiry(&record));
            }
            self.set_slot(
                p.owner,
                slot,
                Some(Entry {
                    record,
                    order: self.order,
                }),
            );
            sealed += 1;
        }
        sealed
    }
    // A free or expired slot first; otherwise the owner's oldest entry,
    // preferring entries that consume no sequence space so a stream of pure
    // ACKs cannot push outstanding data out of the guaranteed history.
    fn victim(&mut self, owner: usize, now: Instant) -> usize {
        let n = self.slots(owner);
        if let Some(slot) = (0..n).find(|&s| {
            self.slot(owner, s)
                .is_none_or(|e| !e.retirable() && self.expired(&e.record, now))
        }) {
            self.set_slot(owner, slot, None);
            return slot;
        }
        let oldest = |retirable: bool| {
            (0..n)
                .filter(|&s| self.slot(owner, s).unwrap().retirable() == retirable)
                .min_by_key(|&s| self.slot(owner, s).unwrap().order)
        };
        oldest(false).or_else(|| oldest(true)).unwrap()
    }
    fn expired(&self, record: &Record, now: Instant) -> bool {
        self.expiry(record) <= now
    }
    fn expiry(&self, record: &Record) -> Instant {
        record
            .committed_at
            .saturating_add(self.limits.feedback_horizon)
    }
    // Same-owner eviction. A TCP generation's evicted history becomes its
    // own summary, which delivery shrinks; anything else is buried at once.
    // Like the live outstanding data it summarizes, the own summary does
    // not expire while the generation lives (`until` applies once it is
    // released): otherwise a quote of undelivered evicted data would lose
    // its ambiguity with a later copy on another path.
    fn evict(&mut self, owner: usize, record: Record, now: Instant) {
        let until = record
            .committed_at
            .saturating_add(self.limits.feedback_horizon);
        if until <= now && !retirable(&record) {
            return;
        }
        if !matches!(self.owners[owner], Some(Owner::Tcp(_))) {
            return self.bury(record, now);
        }
        let summary = Tombstone::of(&record.evidence, until);
        self.retired[owner] = None;
        match &mut self.own[owner] {
            Some(own) => own.absorb(&summary),
            own => *own = Some(summary),
        }
    }
    fn bury(&mut self, record: Record, now: Instant) {
        let until = record
            .committed_at
            .saturating_add(self.limits.feedback_horizon);
        if until <= now {
            return;
        }
        let e = record.evidence;
        // An evicted datagram keeps its exact signature while there is room,
        // so only a byte-identical datagram stays ambiguous with it. When
        // full, the signature closest to its horizon moves to its flow's
        // summary instead.
        if matches!(e.owner, Owner::Datagram { .. }) && !self.datagrams.is_empty() {
            let slot = (0..self.datagrams.len())
                .find(|&s| self.datagrams[s].is_none_or(|(_, until)| until <= now))
                .unwrap_or_else(|| {
                    (0..self.datagrams.len())
                        .min_by_key(|&s| self.datagrams[s].unwrap().1)
                        .unwrap()
                });
            self.next_expiry = self.next_expiry.min(until);
            if let Some((old, old_until)) = self.datagrams[slot].replace((e, until))
                && old_until > now
            {
                self.fold(Tombstone::of(&old, old_until), now);
            }
            return;
        }
        self.fold(Tombstone::of(&e, until), now);
    }
    fn fold(&mut self, summary: Tombstone, now: Instant) {
        let key = summary.key;
        let live = |t: &Option<Tombstone>| t.filter(|t| t.until > now);
        if let Some(index) = self
            .live_tombstones
            .iter()
            .find(|&i| live(&self.tombstones[i]).is_some_and(|t| t.key == key))
        {
            // A later horizon only: `next_expiry` stays a lower bound.
            self.tombstones[index].as_mut().unwrap().absorb(&summary);
            return;
        }
        let slot = match (0..self.tombstones.len()).find(|&s| live(&self.tombstones[s]).is_none()) {
            Some(slot) => slot,
            None => {
                // Every slot holds another key's unexpired history (more
                // released owners with recent submissions than records). The
                // summary closest to its horizon is discarded; merging it into
                // another key would make unrelated flows ambiguous. Instead,
                // every owner that could submit under the discarded key loses
                // owner-level attribution until that horizon: owners that
                // already submitted under it now, and owners that first
                // submit under its class later, when they seal. Owners of
                // other keys keep attribution. Quotes of the discarded key's
                // class also lose path agreement (`Discarded::shadows`): the
                // lost history's paths are unknown.
                let slot = (0..self.tombstones.len())
                    .min_by_key(|&s| self.tombstones[s].unwrap().until)
                    .unwrap();
                let lost = self.tombstones[slot].unwrap();
                self.discarded.record(lost.key, lost.until);
                #[cfg(test)]
                {
                    self.discards += 1;
                }
                for record in 0..self.keys.len() {
                    if let Some(owner) = self.owners[record]
                        && self.keys[record].is_some_and(|key| key.may_share(owner, lost.key))
                    {
                        self.blind[record] = self.blind[record].max(lost.until);
                    }
                }
                slot
            }
        };
        if self.tombstones[slot].is_none() {
            self.live_tombstones.insert(slot);
        }
        self.next_expiry = self.next_expiry.min(summary.until);
        self.tombstones[slot] = Some(summary);
    }

    /// TCP delivery retirement: entries of this exact generation whose whole
    /// consumed span precedes SND.UNA (serial arithmetic) can no longer be
    /// the subject of useful feedback and are removed without a tombstone.
    /// The generation's own evicted summary is cut back the same way, so
    /// its cover never spans more than the outstanding window: below the
    /// first live outstanding segment only sequence space this generation
    /// already delivered remains. Pure ACKs left there share that floor;
    /// their quotes name a segment of the same generation and, at a header
    /// size no candidate MTU can be below, never a path change.
    /// `delivered` sees each record retired: data a new cumulative
    /// acknowledgment covers.
    #[cfg(test)]
    pub fn retire_tcp(
        &mut self,
        owner: ConnectionId,
        unacknowledged: u32,
        delivered: impl FnMut(&Record),
    ) {
        if let Some(index) = self.owner_index(Owner::Tcp(owner)) {
            self.retire_record(index, unacknowledged, delivered);
        }
    }
    /// `retire_tcp` of the TCP generation owning record `index`.
    pub fn retire_record(
        &mut self,
        index: usize,
        unacknowledged: u32,
        mut delivered: impl FnMut(&Record),
    ) {
        debug_assert!(matches!(self.owners[index], Some(Owner::Tcp(_))));
        if self.retired[index] == Some(unacknowledged) {
            debug_assert!((0..self.slots(index)).all(|slot| {
                self.slot(index, slot).is_none_or(|e| {
                    !e.retirable()
                        || !matches!(e.record.evidence.transport,
                            Selector::Tcp { end, .. } if serial_le(end, unacknowledged))
                })
            }));
            return;
        }
        let mut floor = unacknowledged;
        // Stop once every retirable entry was seen (`seen` counts those kept).
        let (mut slot, mut seen) = (0, 0);
        while seen < self.retirable[index] && slot < self.slots(index) {
            let current = slot;
            slot += 1;
            let Some(entry) = self.slot(index, current).filter(|e| e.retirable()) else {
                continue;
            };
            seen += 1;
            let Selector::Tcp { start, end, .. } = entry.record.evidence.transport else {
                continue;
            };
            if serial_le(end, unacknowledged) {
                let entry = self.set_slot(index, current, None).unwrap();
                seen -= 1;
                delivered(&entry.record);
            } else if serial_lt(start, floor) {
                floor = start;
            }
        }
        self.retired[index] = Some(unacknowledged);
        let Some(own) = &mut self.own[index] else {
            return;
        };
        for class in &mut own.classes {
            let Some(Class {
                cover: Cover::Sequence { start, end },
                ..
            }) = class
            else {
                continue;
            };
            if serial_le(*end, floor) {
                *class = None;
            } else if serial_lt(*start, floor) {
                *start = floor;
            }
        }
        if own.classes.iter().all(Option::is_none) {
            self.own[index] = None;
        }
    }
    /// Time expiry for entries without delivery retirement, evicted
    /// datagram signatures, and released owners' tombstones.
    pub fn expire(&mut self, now: Instant) {
        self.check_live();
        if now < self.next_expiry {
            return;
        }
        let mut next = Instant::MAX;
        // Only `seal` fills history, for an owner a reservation pins, and
        // `release_owner` empties it before freeing the record.
        let mut from = 0;
        while let Some(owner) = self.live_owners.next(from) {
            from = owner + 1;
            // Stop once every occupied slot was seen (`seen` counts those kept).
            let (mut slot, mut seen) = (0, 0);
            while seen < self.occupied[owner] && slot < self.slots(owner) {
                let current = slot;
                slot += 1;
                let Some(entry) = self.slot(owner, current) else {
                    continue;
                };
                seen += 1;
                if entry.retirable() {
                    continue;
                }
                if self.expired(&entry.record, now) {
                    self.set_slot(owner, current, None);
                    seen -= 1;
                } else {
                    next = next.min(self.expiry(&entry.record));
                }
            }
        }
        for d in &mut self.datagrams {
            match *d {
                Some((_, until)) if until <= now => *d = None,
                Some((_, until)) => next = next.min(until),
                None => {}
            }
        }
        let mut from = 0;
        while let Some(index) = self.live_tombstones.next(from) {
            from = index + 1;
            let until = self.tombstones[index].unwrap().until;
            if until <= now {
                self.tombstones[index] = None;
                self.live_tombstones.remove(index);
            } else {
                next = next.min(until);
            }
        }
        self.next_expiry = next;
        self.check_live();
    }

    // The full scans the indexes and the expiry bound replace, for debug
    // builds: the occupied records, reservations and summaries, nothing
    // expirable before `next_expiry`, and no history in a free record.
    fn check_live(&self) {
        if !cfg!(debug_assertions) {
            return;
        }
        assert!(self.live_owners.matches(&self.owners));
        assert!(self.live_pending.matches(&self.pending));
        assert!(self.live_tombstones.matches(&self.tombstones));
        for owner in 0..self.owners.len() {
            let (mut occupied, mut retirable) = (0, 0);
            for slot in 0..self.slots(owner) {
                let Some(entry) = self.slot(owner, slot) else {
                    continue;
                };
                occupied += 1;
                retirable += usize::from(entry.retirable());
                assert!(self.owners[owner].is_some());
                assert!(entry.retirable() || self.expiry(&entry.record) >= self.next_expiry);
            }
            assert_eq!(
                (occupied, retirable),
                (self.occupied[owner], self.retirable[owner])
            );
        }
        let datagrams = self.datagrams.iter().flatten().map(|(_, until)| *until);
        let tombstones = self.tombstones.iter().flatten().map(|t| t.until);
        assert!(
            datagrams
                .chain(tombstones)
                .all(|until| until >= self.next_expiry)
        );
    }

    // Unexpired live entries (and their owner records) exactly matching a quote.
    fn live(
        &self,
        now: Instant,
        quote: &QuoteKey,
        zone: Option<LinkId>,
    ) -> impl Iterator<Item = (usize, Entry)> + '_ {
        let quote = *quote;
        // Free records hold no history (`check_live`).
        self.live_owners
            .iter()
            .flat_map(move |record| self.occupied_slots(record).map(move |slot| (record, slot)))
            .filter_map(move |(record, slot)| Some((record, *self.slot(record, slot)?)))
            .filter(move |(_, entry)| {
                (entry.retirable() || !self.expired(&entry.record, now))
                    && entry.matches(&quote)
                    && zone.is_none_or(|zone| entry.record.evidence.link == zone)
            })
    }
    // Unexpired exact evicted-datagram signatures matching a quote.
    fn signatures(
        &self,
        now: Instant,
        quote: &QuoteKey,
        zone: Option<LinkId>,
    ) -> impl Iterator<Item = &Evidence> + '_ {
        let quote = *quote;
        self.datagrams
            .iter()
            .flatten()
            .filter(move |(e, until)| {
                *until > now
                    && evidence_matches(e, &quote)
                    && zone.is_none_or(|zone| e.link == zone)
            })
            .map(|(e, _)| e)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn correlate(&self, now: Instant, quote: &QuoteKey) -> Correlation {
        self.correlate_in(now, quote, None)
    }

    /// `correlate` within one zone: a quote whose source is link-local names
    /// an address of the link it arrived on, so identical traffic of another
    /// link is not a candidate, and neither the lossy history nor the
    /// discarded summaries and blinding of another link's identical flow
    /// deny it. Unscoped quotes (`zone` None) search every link.
    pub fn correlate_in(&self, now: Instant, quote: &QuoteKey, zone: Option<LinkId>) -> Correlation {
        let mut live = 0;
        #[cfg(any(test, feature = "test-support"))]
        let mut unique = None;
        // The latest entry of the candidate owner and its record.
        let mut owner: Option<(Entry, usize)> = None;
        let mut one_owner = true;
        let mut connection = false;
        // None: no match yet; Some(None): matches disagree on the path.
        let mut path: Option<Option<PathId>> = None;
        let mut join = |p: Option<PathId>| {
            path = Some(match path {
                None => p,
                Some(q) => merge(q, p),
            });
        };
        for (record, entry) in self.live(now, quote, zone) {
            live += 1;
            #[cfg(any(test, feature = "test-support"))]
            {
                unique = Some(entry.record);
            }
            join(Some(entry.record.evidence.path));
            let e = entry.record.evidence;
            connection |= e.owner != Owner::Stateless;
            match owner {
                None => owner = Some((entry, record)),
                Some((first, _))
                    if first.record.evidence.owner == e.owner
                        && first.record.evidence.transport == e.transport
                        && matches!(e.transport, Selector::Tcp { .. }) =>
                {
                    if entry.order > first.order {
                        owner = Some((entry, record));
                    }
                }
                Some(_) => one_owner = false,
            }
        }
        // Exact evicted datagrams are positive evidence of their own
        // submission, but deny attribution of any live match.
        let mut signatures = 0;
        for e in self.signatures(now, quote, zone) {
            signatures += 1;
            join(Some(e.path));
        }
        // Lossy history from here on: it can only take away.
        let mut summarized = false;
        // The stateless lane's merged summary does not shadow a connection's
        // own match: a reply it sent carries the sequence number the peer's
        // segment asked for (RST) or a cookie ISS (SYN-ACK), and a later
        // connection on that four-tuple sends from its own RFC 6528 ISS, so a
        // byte-identical segment is a chance collision, not reuse. Its
        // replies to arbitrary peers would otherwise make every connection
        // ambiguous under reset load.
        let shared = self.tombstones.iter().flatten().filter(|t| t.until > now);
        for t in shared
            .chain(self.own.iter().flatten())
            .filter(|t| !(t.key == Key::Stateless && connection) && t.admits(quote, zone))
        {
            summarized = true;
            join(t.path);
        }
        if self.discarded.shadows(quote, zone, connection, now) {
            summarized = true;
            join(None);
        }
        let matches = live + signatures;
        #[cfg(any(test, feature = "test-support"))]
        let alone = live == 1 && signatures == 0 && !summarized;
        Correlation {
            matches,
            summarized,
            path: path.flatten().filter(|_| matches != 0),
            #[cfg(any(test, feature = "test-support"))]
            unique: unique.filter(|_| alone),
            owner: owner
                .filter(|(_, record)| {
                    one_owner && signatures == 0 && !summarized && self.blind[*record] <= now
                })
                .map(|(e, _)| e.record),
            hits: path,
        }
    }

    #[cfg(test)]
    pub fn records(&self) -> impl Iterator<Item = Record> + '_ {
        self.history
            .iter()
            .chain(self.extra.iter().flatten())
            .flatten()
            .map(|e| e.record)
    }
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending.iter().flatten().count()
    }
    /// Summaries `fold` discarded because every slot held a live key.
    #[cfg(test)]
    pub fn discards(&self) -> usize {
        self.discards
    }
    /// The class a discarded summary of a TCP flow from `local` to `remote`
    /// in `zone` shadows: a hash, so distinct flows may share one.
    #[cfg(test)]
    pub fn discard_class(
        &self,
        local: core::net::SocketAddr,
        remote: core::net::SocketAddr,
        zone: Option<LinkId>,
    ) -> usize {
        self.discarded.class(Key::Flow {
            source: local.ip(),
            destination: remote.ip(),
            protocol: 6,
            ports: Some((local.port(), remote.port())),
            zone,
        })
    }
    /// Which evicted evidence `correlate` consulted for a quote: exact
    /// signature hits, and whether a discarded summary shadowed it.
    #[cfg(test)]
    pub fn evicted_hits(&self, now: Instant, quote: &QuoteKey) -> (usize, bool) {
        let connection = self
            .live(now, quote, None)
            .any(|(_, e)| e.record.evidence.owner != Owner::Stateless);
        (
            self.signatures(now, quote, None).count(),
            self.discarded.shadows(quote, None, connection, now),
        )
    }
}
