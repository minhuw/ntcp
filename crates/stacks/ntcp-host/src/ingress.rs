//! The physical input pipeline and the Host's own ICMP output.
//!
//! Every arriving IP packet passes one pipeline: physical framing, local
//! destination authority, then reassembly, before any protocol
//! demultiplexing. Its result is a complete datagram (the arriving packet
//! itself, or a reconstruction from fragments) that the existing dispatch
//! handles exactly like an unfragmented one: transport checksums, address
//! policy, ICMP correlation and owner generations are all evaluated on the
//! complete datagram.
//!
//! Messages the Host originates itself (Echo Replies and the reassembly
//! errors of `icmp_error`) wait in one bounded queue, allocated once, that
//! the embedding drains through `Host::icmp_output` under current path
//! authority.

use alloc::vec::Vec;
use core::net::IpAddr;
use ntcp::{
    EncodedIpv4Options, InputDisposition, Instant, IpMetadata, Ipv4Options, Ipv4Timestamp,
    Ipv4TimestampProvider, RxPacketMetadata,
};
use ntcp_icmp::{EchoKind, ErrorMessage};
use ntcp_path::{Dscp, LinkId, PathStatus, ScopedAddress, SourceId};

use crate::emitter::{DatagramError, Plan, header_len};
use crate::icmp_error::{ReassemblyError, originate};
use crate::ident::IdentifierBackpressure;
use crate::reassembly::{Arrival, Input, Piece, admissible_source};
use crate::{BackendOutcome, Error, Host, IcmpDispatch, IcmpOutcome, IngressContext, UdpEgress};

/// Storage for ICMP messages this Host originates. Zero `messages` (the
/// `managed_limits` default) originates none: an embedding enables the
/// queue only together with a drain (`Host::icmp_output`), since queued
/// messages are sent nowhere else. `managed_icmp_output_limits` adds the
/// path client a drain uses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IcmpOutputLimits {
    /// Messages queued for the drain; later ones are dropped and counted,
    /// except that a message held for an identifier gives way to them
    /// (`Host::icmp_output`).
    pub messages: usize,
    /// Largest ICMP message (header and data) one queue slot holds. At
    /// least an ICMPv6 error with RFC 4443 section 2.4(c)'s maximal quote,
    /// so that no originated error is truncated by storage; an Echo Request
    /// whose reply does not fit is not answered (never truncated, RFC 1122
    /// section 3.2.2.6, RFC 4443 section 4.2). A message's IPv4 options
    /// are stored beside its slot, not in it.
    pub message_bytes: usize,
    /// TTL or Hop Limit of originated messages (RFC 1122 section 3.2.1.7).
    pub hop_limit: u8,
}

impl IcmpOutputLimits {
    fn validate(&self) -> Result<(), Error> {
        if self.messages != 0
            && (self.hop_limit == 0
                || !(ntcp_icmp::ICMPV6_ERROR_LIMIT..=usize::from(u16::MAX))
                    .contains(&self.message_bytes))
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Add the path client an ICMP output drain uses to limits from
/// `managed_limits`: each drained message reads its current path estimate
/// through one transient client, released before the call returns.
pub fn managed_icmp_output_limits(
    paths: ntcp_path::Limits,
    limits: crate::Limits,
    icmp_output: IcmpOutputLimits,
) -> Result<(ntcp_path::Limits, crate::Limits), Error> {
    let clients = usize::from(icmp_output.messages != 0);
    let add = |a: usize| a.checked_add(clients).ok_or(Error::Capacity);
    Ok((
        ntcp_path::Limits {
            paths: add(paths.paths)?,
            clients: add(paths.clients)?,
            ..paths
        },
        crate::Limits {
            icmp_output,
            ..limits
        },
    ))
}

/// What happened to the ICMP messages this Host originated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IcmpOutputCounters {
    /// Echo Replies queued for answered Echo Requests.
    pub echo_replies: u64,
    /// Reassembly errors queued (after suppression and rate limiting).
    pub errors: u64,
    /// Messages not queued: the queue was full of messages no drain attempt
    /// had held for an identifier, or the message exceeded a slot.
    pub dropped: u64,
    /// Echo Requests not answered because the return route reversed from
    /// their source route is not authorized
    /// (`EchoDisposition::UnauthorizedRoute`).
    pub unauthorized_routes: u64,
    /// Queued messages discarded at the drain: no route or source any more,
    /// larger than the path allows and beyond the peer reassembly guarantee,
    /// or no identifier available for its fragments, refused by the backend
    /// (`BackendOutcome::NotSubmitted`), no neighbor storage, or a failed
    /// neighbor resolution on an ND-capable port; and held messages
    /// (waiting for an identifier on a DF-clear route, or for neighbor
    /// resolution) displaced by a new message arriving at a full queue.
    pub unsent: u64,
}

/// Disposition of an Echo Request addressed to this Host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoDisposition {
    /// Its Echo Reply waits in the Host ICMP output queue.
    Queued,
    /// Not answered: the queue was full, the reply exceeds a queue slot or
    /// output is disabled.
    Dropped,
    /// Not answered because the reply would take the reversed return route
    /// of the request's IPv4 source route, which the endpoint's address
    /// policy does not authorize (`Endpoint::admits_return_route`); counted
    /// in `IcmpOutputCounters::unauthorized_routes`.
    UnauthorizedRoute,
}

#[derive(Clone, Copy, Debug)]
struct Queued {
    // The final destination; a source route's first hop is in `options`.
    ip: IpMetadata,
    link: LinkId,
    len: usize,
    // IPv4 options sent as is with the message, kept beside its slot so
    // that they follow it through hold, rotation and displacement.
    options: Option<EncodedIpv4Options>,
    // An error, stored with the quote for a minimal outer header and
    // encoded again for the header its route needs when it is sent.
    error: Option<ErrorMessage>,
    // Queueing order, which rotation does not change.
    arrival: u64,
    // An `icmp_output` attempt found it waiting for an identifier.
    held: bool,
}

pub(crate) struct IcmpOutput {
    limits: IcmpOutputLimits,
    entries: Vec<Option<Queued>>,
    bytes: Vec<u8>,
    head: usize,
    len: usize,
    arrivals: u64,
    counters: IcmpOutputCounters,
}

impl IcmpOutput {
    pub fn hop_limit(&self) -> u8 {
        self.limits.hop_limit
    }
    pub fn new(limits: IcmpOutputLimits) -> Result<Self, Error> {
        limits.validate()?;
        let stride = if limits.messages == 0 {
            0
        } else {
            limits.message_bytes
        };
        Ok(Self {
            limits,
            entries: crate::table(limits.messages, None)?,
            bytes: crate::table(
                limits.messages.checked_mul(stride).ok_or(Error::Capacity)?,
                0u8,
            )?,
            head: 0,
            len: 0,
            arrivals: 0,
            counters: IcmpOutputCounters::default(),
        })
    }
    // Physical slot of the held message that has waited longest, when the
    // queue is full: the one a new message replaces.
    fn displaced(&self) -> Option<usize> {
        let n = self.limits.messages;
        if self.len != n {
            return None;
        }
        (0..n)
            .map(|i| (self.head + i) % n)
            .filter_map(|index| Some((index, self.entries[index]?)))
            .filter(|(_, queued)| queued.held)
            .min_by_key(|(_, queued)| queued.arrival)
            .map(|(index, _)| index)
    }
    // Storage for a new message: the next free slot or, when the queue is
    // full, the slot of the message `push` will displace; None (counted)
    // when the queue is full and no message is held. The caller writes the
    // slot only for a message it then pushes.
    fn free(&mut self) -> Option<&mut [u8]> {
        let index = if self.len < self.limits.messages {
            (self.head + self.len) % self.limits.messages
        } else if let Some(index) = self.displaced() {
            index
        } else {
            self.counters.dropped += 1;
            return None;
        };
        let stride = self.limits.message_bytes;
        Some(&mut self.bytes[index * stride..][..stride])
    }
    // Queue the message written to the slot from `free`. In a full queue it
    // replaces the displaced held message (counted unsent) and moves behind
    // the others, which keep their relative order.
    fn push(
        &mut self,
        ip: IpMetadata,
        link: LinkId,
        len: usize,
        options: Option<EncodedIpv4Options>,
        error: Option<ErrorMessage>,
    ) {
        let n = self.limits.messages;
        let queued = Queued {
            ip,
            link,
            len,
            options,
            error,
            arrival: self.arrivals,
            held: false,
        };
        self.arrivals = self.arrivals.saturating_add(1);
        if self.len < n {
            self.entries[(self.head + self.len) % n] = Some(queued);
            self.len += 1;
            return;
        }
        let Some(mut index) = self.displaced() else {
            return;
        };
        self.counters.unsent += 1;
        self.entries[index] = Some(queued);
        let tail = (self.head + n - 1) % n;
        while index != tail {
            let next = (index + 1) % n;
            self.swap(index, next);
            index = next;
        }
    }
    // Exchange two slots, metadata and bytes.
    fn swap(&mut self, a: usize, b: usize) {
        let stride = self.limits.message_bytes;
        let (low, high) = (a.min(b), a.max(b));
        let (first, second) = self.bytes.split_at_mut(high * stride);
        first[low * stride..][..stride].swap_with_slice(&mut second[..stride]);
        self.entries.swap(a, b);
    }
    // The oldest message waits for an identifier.
    fn hold(&mut self) {
        if let Some(queued) = self.entries.get_mut(self.head).and_then(Option::as_mut) {
            queued.held = true;
        }
    }
    fn front(&self) -> Option<(Queued, &[u8])> {
        if self.len == 0 {
            return None;
        }
        let queued = self.entries[self.head]?;
        let stride = self.limits.message_bytes;
        Some((queued, &self.bytes[self.head * stride..][..queued.len]))
    }
    fn queued(&self) -> impl Iterator<Item = Queued> + '_ {
        (0..self.len).filter_map(|i| self.entries[(self.head + i) % self.limits.messages])
    }
    fn pop(&mut self) {
        self.entries[self.head] = None;
        self.head = (self.head + 1) % self.limits.messages;
        self.len -= 1;
    }
    // The message queued as `arrival`, if still queued.
    fn position(&self, arrival: u64) -> Option<usize> {
        (0..self.len).find(|i| {
            self.entries[(self.head + i) % self.limits.messages]
                .is_some_and(|q| q.arrival == arrival)
        })
    }
    // Remove the message queued as `arrival` unsent (counted), keeping the
    // order of the others.
    fn discard(&mut self, arrival: u64) {
        let Some(mut i) = self.position(arrival) else {
            return;
        };
        let n = self.limits.messages;
        while i > 0 {
            self.swap((self.head + i) % n, (self.head + i - 1) % n);
            i -= 1;
        }
        self.pop();
        self.counters.unsent += 1;
    }
    // Move the oldest message behind the others, keeping the relative order
    // of the rest; storage stays within the fixed slots.
    fn rotate(&mut self) {
        if self.len < 2 {
            return;
        }
        let tail = (self.head + self.len) % self.limits.messages;
        if tail != self.head {
            let stride = self.limits.message_bytes;
            self.bytes
                .copy_within(self.head * stride..(self.head + 1) * stride, tail * stride);
            self.entries[tail] = self.entries[self.head].take();
        }
        self.head = (self.head + 1) % self.limits.messages;
    }
}

/// Metadata of a complete datagram, kept with its bytes while an embedding
/// retains them (`Datagram::envelope`, `Envelope::datagram`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope {
    context: IngressContext,
    len: usize,
    // Reconstructed from fragments: bounded by the reassembly capacity
    // rather than the arrival link's physical packet limit.
    reassembled: bool,
    // The arriving packet carried a Fragment header, an atomic fragment's
    // included (RFC 6946), whatever the reconstruction's bytes now hold;
    // Neighbor Discovery refuses such messages (RFC 6980 section 5).
    fragment_header: bool,
}

impl Envelope {
    // An unfragmented packet as it arrived.
    pub(crate) const fn physical(context: IngressContext, len: usize) -> Self {
        Self {
            context,
            len,
            reassembled: false,
            fragment_header: false,
        }
    }
    pub const fn context(self) -> IngressContext {
        self.context
    }
    /// Rejoin retained bytes; None unless they have the datagram's length.
    pub fn datagram(self, bytes: &[u8]) -> Option<Datagram<'_>> {
        (bytes.len() == self.len).then_some(Datagram {
            envelope: self,
            bytes,
        })
    }
}

/// One complete IP datagram from `Host::receive`: an unfragmented packet as
/// it arrived, or a datagram reconstructed from fragments (fragment zero's
/// header, IPv4 options included, with lengths and fragmentation fields
/// rewritten; an IPv6 datagram without its Fragment header). `Host::process`
/// validates and processes it like any arriving packet; its result
/// (`Processed`) is what dispatch takes.
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    envelope: Envelope,
    bytes: &'a [u8],
}

impl<'a> Datagram<'a> {
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub const fn envelope(&self) -> Envelope {
        self.envelope
    }
    pub const fn context(&self) -> IngressContext {
        self.envelope.context
    }
}

/// Metadata of a complete datagram after destination processing
/// (`Host::process`), kept with its bytes while an embedding retains them
/// (`Processed::envelope`, `ProcessedEnvelope::datagram`). It holds the
/// processed outer header, so rejoining and dispatching it again never
/// processes or records anything a second time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessedEnvelope {
    envelope: Envelope,
    ip: IpMetadata,
    traffic_class: u8,
    protocol: u8,
    // IPv6 extension headers may make it longer than 65535 octets.
    header_len: usize,
    options: Ipv4Options,
}

impl ProcessedEnvelope {
    /// Rejoin the retained datagram bytes; None unless they have its length.
    pub fn datagram(self, bytes: &[u8]) -> Option<Processed<'_>> {
        (bytes.len() == self.envelope.len).then_some(Processed {
            envelope: self,
            bytes,
        })
    }
}

/// One complete datagram admitted to this Host and processed as its
/// destination: the authoritative ingress context, the addresses (the
/// destination is one this Host context owns), traffic class, protocol,
/// complete header length, reassembly provenance, every IPv4 option except
/// NOP and EOL as processed, and the immutable payload. TCP and every ICMP
/// consumer take their outer metadata from it.
#[derive(Clone, Copy, Debug)]
pub struct Processed<'a> {
    envelope: ProcessedEnvelope,
    bytes: &'a [u8],
}

impl<'a> Processed<'a> {
    pub const fn envelope(&self) -> ProcessedEnvelope {
        self.envelope
    }
    pub const fn context(&self) -> IngressContext {
        self.envelope.envelope.context
    }
    /// The datagram as received or reassembled: its header still holds the
    /// options as they arrived.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Reconstructed from fragments.
    pub const fn reassembled(&self) -> bool {
        self.envelope.envelope.reassembled
    }
    /// The arriving packet carried a Fragment header: a reassembled
    /// datagram, or an atomic fragment processed whole.
    pub const fn contained_fragment_header(&self) -> bool {
        self.envelope.envelope.fragment_header
    }
    /// The processed header with the datagram's payload.
    pub fn packet(&self) -> crate::IngressPacket<'a> {
        let e = self.envelope;
        crate::IngressPacket {
            ip: e.ip,
            traffic_class: e.traffic_class,
            protocol: e.protocol,
            options: e.options,
            payload: &self.bytes[e.header_len..],
        }
    }
}

// Time for destination Timestamp recording.
pub(crate) enum Clock<'c> {
    // A caller-asserted wire value, or none.
    Asserted(Option<u32>),
    Provider(&'c mut dyn Ipv4TimestampProvider),
}

// No time is available: Timestamp slots are kept, Record Route still recorded.
struct Unavailable;
impl Ipv4TimestampProvider for Unavailable {
    fn ipv4_timestamp(&mut self) -> Option<Ipv4Timestamp> {
        None
    }
}

/// The outcome of one physical packet.
#[derive(Clone, Copy, Debug)]
pub enum Received<'a> {
    Datagram(Datagram<'a>),
    /// A fragment stored (or an exact duplicate): its datagram is still
    /// incomplete.
    Held,
    /// A Neighbor Solicitation or Advertisement on an ND-capable port,
    /// consumed by the Host's Neighbor Discovery.
    Neighbor,
    /// A fragment discarded by reassembly, counted in
    /// `Host::reassembly_counters`; any error it caused is queued.
    Discarded,
}

fn is_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v) if v.is_unicast_link_local())
}

// Any IPv4 Loose or Strict Source and Record Route option.
pub(crate) fn source_routed(options: &[u8]) -> bool {
    let mut i = 0;
    while let Some(&kind) = options.get(i) {
        match kind {
            0 => return false,
            1 => i += 1,
            131 | 137 => return true,
            _ => match options.get(i + 1) {
                Some(&len) if len >= 2 => i += usize::from(len),
                _ => return false,
            },
        }
    }
    false
}

// The Record Route and Timestamp options of `options` (processed options,
// without NOP or End), in received order, copied into `out`.
fn recorded_options<'a>(options: &[u8], out: &'a mut [u8; 40]) -> &'a [u8] {
    let mut len = 0;
    let mut i = 0;
    while let (Some(&kind), Some(&size)) = (options.get(i), options.get(i + 1)) {
        let size = usize::from(size);
        let Some(option) = options.get(i..i + size).filter(|_| size >= 2) else {
            break;
        };
        if matches!(kind, 7 | 68) {
            out[len..len + size].copy_from_slice(option);
            len += size;
        }
        i += size;
    }
    &out[..len]
}

impl Host {
    /// Physical input: framing against the arrival link's receive
    /// capabilities, then local destination authority, then reassembly.
    /// Nothing is allocated, and no assembly state is created, before the
    /// fragment's framing, its local destination and its source pass.
    ///
    /// `link_multicast` states that the link layer addressed the frame to a
    /// multicast or broadcast destination; ICMP errors are then suppressed
    /// (RFC 1122 section 3.2.2, RFC 4443 section 2.4(e)). An unfragmented
    /// packet is returned as it arrived. A completed datagram, and an IPv6
    /// atomic fragment without its Fragment header (RFC 6946: processed as a
    /// non-fragmented packet), are written to `out`, which then owns them:
    /// an embedding may retain them until dispatch. An `out` too small for
    /// the datagram discards it as Unsupported.
    pub fn receive<'o>(
        &mut self,
        context: IngressContext,
        now: Instant,
        frame: &'o [u8],
        link_multicast: bool,
        out: &'o mut [u8],
    ) -> Result<Received<'o>, Error> {
        let capabilities = self.port(context.link)?.receive;
        if frame.len() > capabilities.max_ip_packet {
            return Err(Error::Unsupported);
        }
        if capabilities.ipv6 != crate::Ipv6Receive::Disabled
            && frame.first().is_some_and(|b| b >> 4 == 6)
            && self.neighbor_receive(context, now, frame)?
        {
            return Ok(Received::Neighbor);
        }
        let whole = Datagram {
            envelope: Envelope::physical(context, frame.len()),
            bytes: frame,
        };
        let piece = match frame.first().ok_or(ntcp_ip::Error::Truncated)? >> 4 {
            4 => {
                // Source-route admission and completion, per fragment and
                // before reassembly (RFC 1122 section 3.2.1.8).
                let source_routes = capabilities.ipv4.source_routes();
                let packet =
                    ntcp_ip::parse_fragment(frame, source_routes.ok_or(Error::Unsupported)?)?;
                if packet.fragmentation.is_complete() {
                    return Ok(Received::Datagram(whole));
                }
                Piece::ipv4(&packet)
            }
            6 if capabilities.ipv6 == crate::Ipv6Receive::BaseHeader => {
                let packet = ntcp_ip6::parse_fragment(frame)?;
                // This profile has no extension header receive processing
                // or reassembly of a variable unfragmentable part.
                if !packet.base_layout() {
                    return Err(ntcp_ip::Error::ExtensionsUnsupported.into());
                }
                let Some(piece) = Piece::ipv6(frame, &packet.chain) else {
                    return Ok(Received::Datagram(whole));
                };
                piece
            }
            6 if capabilities.ipv6 == crate::Ipv6Receive::Extensions => {
                return self.receive_extensions(context, now, frame, link_multicast, out);
            }
            _ => return Err(Error::Unsupported),
        };
        let local = self.local_in_context(context, piece.destination)?;
        let arrival = Arrival {
            link: context.link,
            local,
            link_multicast,
        };
        let ipv6 = piece.source.is_ipv6();
        let Self {
            reassembly,
            errors,
            icmp_output,
            ..
        } = self;
        match reassembly.input(now, arrival, piece) {
            Input::Whole => {
                // An IPv6 atomic fragment (IPv4 atomic datagrams returned
                // above): the base header naming the Fragment header's Next
                // Header, followed by the data.
                let len = ntcp_ip6::IPV6_HEADER + piece.data.len();
                let out = out.get_mut(..len).ok_or(Error::Unsupported)?;
                out[..ntcp_ip6::IPV6_HEADER].copy_from_slice(&frame[..ntcp_ip6::IPV6_HEADER]);
                out[4..6].copy_from_slice(&(piece.data.len() as u16).to_be_bytes());
                out[6] = piece.protocol;
                out[ntcp_ip6::IPV6_HEADER..].copy_from_slice(piece.data);
                Ok(Received::Datagram(Datagram {
                    envelope: Envelope {
                        context,
                        len,
                        reassembled: false,
                        fragment_header: true,
                    },
                    bytes: out,
                }))
            }
            Input::Held | Input::Duplicate => Ok(Received::Held),
            Input::Complete(done) => {
                let len = done.packet.len();
                let Some(out) = out.get_mut(..len) else {
                    return Err(Error::Unsupported);
                };
                out.copy_from_slice(done.packet);
                Ok(Received::Datagram(Datagram {
                    envelope: Envelope {
                        context: IngressContext {
                            link: done.arrival.link,
                        },
                        len,
                        reassembled: true,
                        fragment_header: true,
                    },
                    bytes: out,
                }))
            }
            Input::Discarded(discard) => {
                // RFC 8200 section 4.5's Parameter Problems about this
                // fragment; overlap and every IPv4 discard are silent.
                let fragment = ntcp_ip6::IPV6_HEADER;
                if let Some(error) = ReassemblyError::for_discard(ipv6, discard, fragment) {
                    queue_error(errors, icmp_output, now, error, arrival, frame);
                }
                Ok(Received::Discarded)
            }
        }
    }

    // `receive` under `Ipv6Receive::Extensions`. Physical framing first: a
    // packet shorter or longer than its declared length is dropped before
    // any of its headers is examined, and the destination must be one this
    // context owns (no multicast destination reaches option processing).
    // A fragment of a datagram abandoned for overlap is discarded silently
    // before any of its headers can draw an error (RFC 5722 section 4); an
    // atomic fragment is no fragment of it (RFC 6946 section 4).
    // Then the headers before any Fragment header are processed on this
    // packet; an unfragmented packet, an atomic fragment and a completed
    // datagram are processed through their whole chain, which repeats only
    // the side-effect-free unfragmentable part of a reassembled one. A
    // refusal queues its Parameter Problem about the packet it was found in
    // (the reconstruction, after reassembly) and is returned.
    fn receive_extensions<'o>(
        &mut self,
        context: IngressContext,
        now: Instant,
        frame: &'o [u8],
        link_multicast: bool,
        out: &'o mut [u8],
    ) -> Result<Received<'o>, Error> {
        let declared = ntcp_ip6::ipv6_fragment_bounds(frame)?;
        if frame.len() != declared {
            return Err(if frame.len() < declared {
                ntcp_ip::Error::Truncated
            } else {
                ntcp_ip::Error::Length
            }
            .into());
        }
        let destination = <[u8; 16]>::try_from(&frame[24..40]).map_err(|_| Error::Unsupported)?;
        let local = self.local_in_context(context, IpAddr::from(destination))?;
        let arrival = Arrival {
            link: context.link,
            local,
            link_multicast,
        };
        if let Some(fragment) = ntcp_ip6::FragmentHeader::locate(frame)
            .filter(|f| f.fragment_offset != 0 || f.more_fragments)
        {
            let source = <[u8; 16]>::try_from(&frame[8..24]).map_err(|_| Error::Unsupported)?;
            let (source, destination) = (IpAddr::from(source), IpAddr::from(destination));
            if self
                .reassembly
                .rejects(now, arrival, source, destination, fragment.identification)
            {
                return Ok(Received::Discarded);
            }
        }
        let chain = self.receive_chain(now, arrival, frame, true)?;
        let Some(piece) = Piece::ipv6(frame, &chain) else {
            return Ok(Received::Datagram(Datagram {
                envelope: Envelope::physical(context, frame.len()),
                bytes: frame,
            }));
        };
        let fragment = chain.fragment().map_or(0, |f| f.offset);
        let Self {
            reassembly,
            errors,
            icmp_output,
            ..
        } = self;
        let (len, arrival, reassembled) = match reassembly.input(now, arrival, piece) {
            Input::Whole => {
                // An atomic fragment (RFC 6946): the unfragmentable part,
                // its selector naming the Fragment header's Next Header,
                // followed by the data.
                let prefix = piece.header.len() - ntcp_ip6::FRAGMENT_HEADER;
                let len = prefix + piece.data.len();
                let out = out.get_mut(..len).ok_or(Error::Unsupported)?;
                out[..prefix].copy_from_slice(&frame[..prefix]);
                out[prefix..].copy_from_slice(piece.data);
                let payload = (len - ntcp_ip6::IPV6_HEADER) as u16;
                out[4..6].copy_from_slice(&payload.to_be_bytes());
                out[piece.selector] = piece.protocol;
                (len, arrival, false)
            }
            Input::Held | Input::Duplicate => return Ok(Received::Held),
            Input::Complete(done) => {
                let len = done.packet.len();
                out.get_mut(..len)
                    .ok_or(Error::Unsupported)?
                    .copy_from_slice(done.packet);
                (len, done.arrival, true)
            }
            Input::Discarded(discard) => {
                if let Some(error) = ReassemblyError::for_discard(true, discard, fragment) {
                    queue_error(errors, icmp_output, now, error, arrival, frame);
                }
                return Ok(Received::Discarded);
            }
        };
        let out: &'o [u8] = out;
        let out = &out[..len];
        self.receive_chain(now, arrival, out, false)?;
        Ok(Received::Datagram(Datagram {
            envelope: Envelope {
                context: IngressContext { link: arrival.link },
                len,
                reassembled,
                fragment_header: true,
            },
            bytes: out,
        }))
    }

    // Receive processing of one complete packet's chain (RFC 8200 section
    // 4): its fault, or for a chain without a Fragment header an upper layer
    // this Host does not process, queues the Parameter Problem and refuses
    // the packet. A Fragment header is accepted only on an arriving packet
    // (`fragment`); one left in a reconstruction is not reassembled again.
    fn receive_chain<'p>(
        &mut self,
        now: Instant,
        arrival: Arrival,
        packet: &'p [u8],
        fragment: bool,
    ) -> Result<ntcp_ip6::Chain<'p>, Error> {
        let (error, refused) = match ntcp_ip6::Chain::receive(packet) {
            Ok(chain) if chain.fragment().is_some() => {
                if fragment {
                    return Ok(chain);
                }
                (None, ntcp_ip::Error::FragmentationUnsupported)
            }
            Ok(chain) if processed_upper_layer(chain.protocol()) => return Ok(chain),
            Ok(chain) => (
                ReassemblyError::unrecognized(chain.protocol_selector()),
                ntcp_ip::Error::ExtensionsUnsupported,
            ),
            Err(fault) => (ReassemblyError::for_fault(fault), fault.into()),
        };
        if let Some(error) = error {
            queue_error(
                &mut self.errors,
                &mut self.icmp_output,
                now,
                error,
                arrival,
                packet,
            );
        }
        Err(refused.into())
    }

    // A fragment is admitted for a destination this context owns on any of
    // its links (an ICMP error may return asymmetrically; transport input is
    // held to its arrival link after completion, like unfragmented input);
    // a link-local destination only on the arrival link.
    fn local_in_context(
        &self,
        context: IngressContext,
        destination: IpAddr,
    ) -> Result<SourceId, Error> {
        if is_link_local(destination) {
            return Ok(self.paths.local_source(
                ScopedAddress::new(destination, Some(context.link))?,
                context.link,
            )?);
        }
        let address = ScopedAddress::new(destination, None)?;
        self.ports
            .iter()
            .flatten()
            .find_map(|port| self.paths.local_source(address, port.link).ok())
            .ok_or(ntcp_path::Error::NoRoute.into())
    }

    /// Discard expired assemblies and those whose local address or arrival
    /// link this context no longer owns, queueing RFC 1122 section 3.3.2's
    /// (or RFC 8200 section 4.5's) Time Exceeded for each expired one whose
    /// fragment zero arrived. Run by every `service_changes` pass, with or
    /// without traffic.
    pub(crate) fn expire_reassembly(&mut self, now: Instant) {
        let Self {
            reassembly,
            errors,
            icmp_output,
            paths,
            ports,
            ..
        } = self;
        reassembly.expire(
            now,
            |link, local| {
                paths.link(link).is_ok()
                    && ports
                        .iter()
                        .flatten()
                        .any(|port| paths.owns_source(local, port.link).unwrap_or(false))
            },
            |expired| {
                queue_error(
                    errors,
                    icmp_output,
                    now,
                    ReassemblyError::TimeExceeded,
                    expired.arrival,
                    expired.first_fragment,
                );
            },
        );
    }

    /// The processed header and payload of a datagram, with transport
    /// ingress ownership (the destination is a source registered on its
    /// arrival link), as `decode_ingress` checks for an unfragmented frame.
    /// Nothing is parsed or recorded again.
    pub fn decode_datagram<'a>(
        &self,
        processed: Processed<'a>,
    ) -> Result<crate::IngressPacket<'a>, Error> {
        let packet = self.processed_packet(processed)?;
        self.owned_on_link(processed.context(), packet.ip.destination)?;
        Ok(packet)
    }

    // The packet of a processed datagram of this Host context.
    fn processed_packet<'a>(
        &self,
        processed: Processed<'a>,
    ) -> Result<crate::IngressPacket<'a>, Error> {
        if processed.context().context() != self.paths.context() {
            return Err(Error::InvalidContext);
        }
        self.port(processed.context().link)?;
        Ok(processed.packet())
    }

    /// Destination processing of one complete datagram from `receive`, the
    /// single step between reassembly and protocol dispatch: validation as
    /// for any arriving packet (source-route admission included), admission
    /// of a destination this context owns on any of its links (the dispatch
    /// of transport and Echo input then holds it to the arrival link), and,
    /// when the link's profile enables interpretation, Record Route and
    /// Timestamp recording of that destination exactly once
    /// (`Ipv4Options::record_with`). `timestamps` is sampled at most once, and
    /// only for a Timestamp slot this host may write; without it Record Route
    /// is still recorded and Timestamp slots are kept. A Timestamp option
    /// whose overflow count cannot advance discards the datagram
    /// (`Error::Codec(Options)`). Every option except NOP and EOL is kept in
    /// the result, whatever the profile; quoted headers inside an ICMP error
    /// are payload and never processed.
    ///
    /// Dispatch (`input_datagram`, `input_icmp_datagram`) and retention
    /// (`Processed::envelope`) use the result as is: a datagram is processed
    /// once, however often its dispatch is retried.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
    //# passed to the transport layer (or to ICMP processing when the datagram is
    //# an ICMP message). The IP and transport layer MUST each interpret those IP
    //# options that they understand and silently ignore the others.
    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# The destination host MUST (if possible) add the current timestamp to
    //# a Timestamp option before passing the option to the transport layer
    //# or to ICMP for processing.
    pub fn process<'a>(
        &self,
        datagram: Datagram<'a>,
        timestamps: Option<&mut dyn Ipv4TimestampProvider>,
    ) -> Result<Processed<'a>, Error> {
        let clock = timestamps.map_or(Clock::Asserted(None), Clock::Provider);
        self.process_clock(datagram, clock)?
            .ok_or(ntcp_ip::Error::Options.into())
    }

    // `process`, with None for a datagram whose options cannot be recorded.
    pub(crate) fn process_clock<'a>(
        &self,
        datagram: Datagram<'a>,
        clock: Clock<'_>,
    ) -> Result<Option<Processed<'a>>, Error> {
        let mut packet = self.parse_datagram(datagram)?;
        self.owned_in_context(datagram.context(), packet.ip.destination)?;
        let interpretation = self.port(datagram.context().link)?.receive.ipv4.interpretation();
        if let (true, IpAddr::V4(local)) = (interpretation, packet.ip.destination)
            && !packet.options.is_empty()
        {
            let recorded = match clock {
                Clock::Asserted(Some(timestamp)) => packet.options.record(local, timestamp),
                Clock::Asserted(None) => packet.options.record_with(local, &mut Unavailable),
                Clock::Provider(provider) => packet.options.record_with(local, provider),
            };
            // Failure invalidates this datagram, not the embedding: a full
            // Timestamp option with overflow 15 cannot be advanced further.
            let Ok(recorded) = recorded else {
                return Ok(None);
            };
            packet.options = recorded;
        }
        let bytes = datagram.bytes();
        Ok(Some(Processed {
            envelope: ProcessedEnvelope {
                envelope: datagram.envelope(),
                ip: packet.ip,
                traffic_class: packet.traffic_class,
                protocol: packet.protocol,
                header_len: bytes.len() - packet.payload.len(),
                options: packet.options,
            },
            bytes,
        }))
    }

    pub(crate) fn parse_datagram<'a>(
        &self,
        datagram: Datagram<'a>,
    ) -> Result<crate::IngressPacket<'a>, Error> {
        let limit = if datagram.envelope.reassembled {
            let ipv6 = datagram.bytes.first().is_some_and(|b| b >> 4 == 6);
            Some(
                self.reassembly
                    .limits()
                    .datagram_capacity(ipv6)
                    .ok_or(Error::Unsupported)?,
            )
        } else {
            None
        };
        self.parse_ingress_limited(datagram.context(), datagram.bytes, limit)
    }

    /// Dispatch one processed datagram exactly like an unfragmented packet:
    /// see `input_ip`, which is this after `receive` and `process`.
    pub fn input_datagram(
        &mut self,
        endpoint: &mut ntcp::Endpoint,
        now: Instant,
        processed: Processed<'_>,
        metadata: RxPacketMetadata,
        outgoing_dscp: u8,
    ) -> Result<InputDisposition, Error> {
        self.check_endpoint(endpoint)?;
        let packet = self.processed_packet(processed)?;
        if crate::is_icmp(&packet) {
            // One dispatcher for every embedding. A reserved owner keeps this
            // entrypoint's established OutputReserved contract, with nothing
            // applied or published; callers that retain use input_icmp_datagram.
            return match self.input_icmp_datagram(endpoint, now, processed)? {
                IcmpDispatch::Deferred(_) => Err(ntcp::EndpointError::OutputReserved.into()),
                IcmpDispatch::Completed(
                    IcmpOutcome::Discarded(crate::IcmpDiscard::SourceQuench)
                    | IcmpOutcome::Echo(
                        EchoDisposition::Dropped | EchoDisposition::UnauthorizedRoute,
                    )
                    | IcmpOutcome::Probe(crate::ProbeOutcome::Unmatched),
                ) => Ok(InputDisposition::Dropped),
                IcmpDispatch::Completed(_) => Ok(InputDisposition::Processed),
            };
        }
        self.input_transport(
            endpoint,
            now,
            processed.context(),
            &packet,
            metadata,
            outgoing_dscp,
        )
    }

    /// The single ICMP dispatch for one processed datagram: an Echo Request
    /// is answered by the Host's Echo service, every other message goes to
    /// error classification and correlation (`input_icmp`). Each consumer
    /// receives the processed outer header; the outer packet is not parsed
    /// again.
    pub fn input_icmp_datagram(
        &mut self,
        endpoint: &mut ntcp::Endpoint,
        now: Instant,
        processed: Processed<'_>,
    ) -> Result<IcmpDispatch, Error> {
        self.check_endpoint(endpoint)?;
        let packet = self.processed_packet(processed)?;
        if !crate::is_icmp(&packet) {
            return Err(Error::Unsupported);
        }
        let (request, reply) = if packet.ip.source.is_ipv4() {
            (8, 0)
        } else {
            (128, 129)
        };
        // Neighbor Discovery is consumed by `receive` from unfragmented
        // packets only; one that reaches dispatch arrived with a Fragment
        // header (RFC 6980 section 5) or bypassed physical input. A
        // Redirect is acted on only where Neighbor Discovery resolves the
        // first hops it changes.
        let link = processed.context().link;
        if packet.ip.source.is_ipv6()
            && match packet.payload.first() {
                Some(135 | 136) => true,
                Some(137) => {
                    processed.contained_fragment_header() || self.neighbors.port(link).is_some()
                }
                _ => false,
            }
        {
            return Err(if processed.contained_fragment_header() {
                ntcp_ip::Error::FragmentationUnsupported.into()
            } else {
                Error::Unsupported
            });
        }
        if packet.ip.source.is_ipv4() && packet.payload.first() == Some(&5) {
            return Ok(IcmpDispatch::Completed(IcmpOutcome::Redirect(
                self.redirect_ipv4(processed.context(), now, &packet)?,
            )));
        }
        if packet.payload.first() == Some(&request) {
            return Ok(IcmpDispatch::Completed(IcmpOutcome::Echo(
                self.echo(endpoint, processed.context(), &packet)?,
            )));
        }
        if packet.payload.first() == Some(&reply) {
            // Echo Replies answer only the Host's adjunct probes.
            self.owned_in_context(processed.context(), packet.ip.destination)?;
            self.now = self.now.max(now);
            return Ok(IcmpDispatch::Completed(IcmpOutcome::Probe(
                self.adjunct_reply(now, &packet)?,
            )));
        }
        self.dispatch_icmp(endpoint, now, processed.context(), &packet)
    }

    // RFC 1122 section 3.2.2.6:
    //   Every host MUST implement an ICMP Echo server function that
    //   receives Echo Requests and sends corresponding Echo Replies.
    // RFC 1122 section 3.2.2.6 and RFC 4443 sections 4.1 and 4.2: the reply
    // comes from the request's specific destination (one of this Host's
    // unicast addresses on the arrival link) and echoes identifier, sequence
    // and every data octet unmodified. The request may have been
    // reassembled; its checksum covers the complete message. A reply that
    // cannot be stored whole is not sent rather than truncated.
    //
    // RFC 1122 section 3.2.2.6:
    //   If a Record Route and/or Time Stamp option is received in an ICMP
    //   Echo Request, this option (these options) SHOULD be updated to
    //   include the current host and included in the IP header of the Echo
    //   Reply message, without "truncation".
    //   If a Source Route option is received in an ICMP Echo Request, the
    //   return route MUST be reversed and used as a Source Route option for
    //   the Echo Reply message.
    // Destination processing already updated Record Route and Timestamp
    // with this host; with interpretation enabled they are carried as
    // processed, lengths and free slots included, and never recorded again.
    // Without it the profile declines that optional processing (RFC 1122
    // section 3.2.1.8) and the reply carries neither. Other options are not
    // reflected. Admission admitted the source route; the reply takes its
    // reversed return route only when the endpoint's route policy
    // authorizes it, as for TCP, and is otherwise not sent.
    fn echo(
        &mut self,
        endpoint: &ntcp::Endpoint,
        context: IngressContext,
        packet: &crate::IngressPacket,
    ) -> Result<EchoDisposition, Error> {
        self.owned_on_link(context, packet.ip.destination)?;
        if !admissible_source(packet.ip.source) {
            return Err(ntcp_ip::Error::Invalid.into());
        }
        let request = ntcp_icmp::decode_echo(packet.ip, packet.payload)?;
        if request.kind != EchoKind::Request {
            return Err(ntcp_ip::Error::Invalid.into());
        }
        if self.icmp_output.limits.messages == 0 {
            return Ok(EchoDisposition::Dropped);
        }
        let interpretation = self.port(context.link)?.receive.ipv4.interpretation();
        let output = &mut self.icmp_output;
        let options = match (packet.ip.destination, packet.ip.source) {
            (IpAddr::V4(local), IpAddr::V4(remote)) => {
                let received = packet.options.as_bytes();
                let route = if source_routed(received) {
                    match packet.options.return_route(remote) {
                        Some(route)
                            if endpoint.admits_return_route(local.into(), remote.into(), &route) =>
                        {
                            Some(route)
                        }
                        _ => {
                            output.counters.unauthorized_routes += 1;
                            return Ok(EchoDisposition::UnauthorizedRoute);
                        }
                    }
                } else {
                    None
                };
                let mut carried = [0; 40];
                let carried = if interpretation {
                    recorded_options(received, &mut carried)
                } else {
                    &[]
                };
                // Always representable: the received options fit 40
                // octets and the reversed route is no longer than the
                // received one.
                match EncodedIpv4Options::new(route.as_ref(), remote, carried) {
                    Ok(options) => Some(options).filter(|o| !o.as_bytes().is_empty()),
                    Err(_) => {
                        output.counters.dropped += 1;
                        return Ok(EchoDisposition::Dropped);
                    }
                }
            }
            _ => None,
        };
        let len = packet.payload.len();
        if len > output.limits.message_bytes {
            output.counters.dropped += 1;
            return Ok(EchoDisposition::Dropped);
        }
        let Some(slot) = output.free() else {
            return Ok(EchoDisposition::Dropped);
        };
        let reply = IpMetadata {
            source: packet.ip.destination,
            destination: packet.ip.source,
        };
        // Encoding cannot fail once the slot is written: the request decoded
        // under the same address pair and `len` is within a slot.
        slot[8..len].copy_from_slice(request.data);
        let len = ntcp_icmp::encode_echo(
            reply,
            EchoKind::Reply,
            request.identifier,
            request.sequence,
            slot,
            len - 8,
        )?;
        output.counters.echo_replies += 1;
        output.push(reply, context.link, len, options, None);
        Ok(EchoDisposition::Queued)
    }

    // The path request of a queued message and the address its first hop
    // is resolved toward: the first hop of its source route, otherwise its
    // destination. Output and its accounting share it.
    fn icmp_route(
        &self,
        queued: Queued,
    ) -> Result<(ntcp_path::PathRequest, ScopedAddress), Error> {
        let ip = queued.ip;
        // A message to a link-local address stays on the link it concerns.
        let zone = Some(queued.link);
        let request = self.request(ip.source, ip.destination, zone, Dscp::new(0)?)?;
        let first_hop = queued
            .options
            .map_or(ip.destination, |options| options.destination().into());
        Ok((request, crate::scoped(first_hop, zone)?))
    }

    // Whether the queued message is routed over the path with `key` now.
    fn icmp_routed(&self, queued: Queued, key: ntcp_path::PathKey) -> bool {
        self.icmp_route(queued)
            .and_then(|(request, via)| Ok(self.paths.resolve_via(request, via)?))
            .is_ok_and(|resolved| resolved.key() == key)
    }

    /// Whether the Host answers Echo Requests (its ICMP output is
    /// configured), and how many queued ICMP messages leave over the path
    /// with `key`.
    pub(crate) fn icmp_output_on(&self, key: ntcp_path::PathKey) -> Option<usize> {
        (self.icmp_output.limits.messages != 0).then(|| {
            self.icmp_output
                .queued()
                .filter(|&queued| self.icmp_routed(queued, key))
                .count()
        })
    }

    /// Whether a queued ICMP message leaving over the path with `key`
    /// carries a source route.
    pub(crate) fn icmp_source_routed_on(&self, key: ntcp_path::PathKey) -> bool {
        self.icmp_output.queued().any(|queued| {
            queued
                .options
                .is_some_and(|o| source_routed(o.as_bytes()))
                && self.icmp_routed(queued, key)
        })
    }

    // A queued message whose neighbor resolution ended (`resolved`), or is
    // still waiting (None): a failed one is discarded, counted unsent.
    // False when the message is no longer queued.
    pub(crate) fn icmp_output_settle(&mut self, arrival: u64, resolved: Option<bool>) -> bool {
        if self.icmp_output.position(arrival).is_none() {
            return false;
        }
        if resolved == Some(false) {
            self.icmp_output.discard(arrival);
        }
        true
    }

    pub fn icmp_output_counters(&self) -> IcmpOutputCounters {
        self.icmp_output.counters
    }
    /// Messages waiting for `icmp_output`.
    pub fn icmp_output_pending(&self) -> usize {
        self.icmp_output.len
    }

    /// Send the oldest queued ICMP message through the datagram emitter
    /// under current path authority: its source must still be this Host's
    /// and a route must reach its destination through a usable port. A
    /// message within the connectionless effective size goes out whole; a
    /// larger one within the peer reassembly guarantee (RFC 1122 section
    /// 3.3.3, RFC 8200 section 5, or `DatagramLimits` deployment knowledge)
    /// is source-fragmented to that size, every IPv4 fragment with DF; one
    /// beyond the guarantee goes out whole when the path budget allows it.
    /// Errors are built within their quote limits and never need
    /// fragmentation. `submit` is called once per physical packet, in order.
    /// WouldBlock or Rejected before any packet was submitted keeps the
    /// message queued; once a packet may have reached the link the message
    /// is consumed and the returned outcome is the one that stopped the
    /// transaction (Submitted when every packet went out). None when the
    /// queue is empty. An error consumes the message unsent (counted).
    /// On a discovery-disabled IPv4 route every message leaves DF clear and
    /// needs a leased Identification (RFC 1191 section 6.6, RFC 6864): while
    /// the allocator's start quiet period or the RFC 6864 ceiling withholds
    /// one, the message stays queued (nothing submitted) and is sized again
    /// at the next attempt; an identifier is never reused. Only that message
    /// waits: it moves behind the other queued messages and the call goes on
    /// with the next one, so output to other destinations is not held behind
    /// it. WouldBlock when every queued message waits for an identifier and
    /// no adjunct probe is due. A message whose next hop on an ND-capable
    /// port (`register_neighbor_port`) has no usable mapping waits the same
    /// way while Neighbor Discovery resolves it (RFC 4861 section 7.2.2's
    /// per-neighbor queue): it is sent, to the resolved address, by a pass
    /// after resolution, and discarded (counted unsent) when resolution
    /// fails; a cached mapping is used at once (`UdpEgress::link_layer`),
    /// the first use of a STALE one starting DELAY. Exhausted neighbor
    /// storage discards the message, counted unsent.
    /// From that attempt on the message is held,
    /// and a held message never keeps a new one out of the queue: a new Echo
    /// Reply or error arriving at a full queue that holds one takes the place
    /// of the held message that has waited longest, which is discarded
    /// (counted unsent) while the others keep their order. A full queue with
    /// no held message drops the new message (counted dropped).
    /// `packet` holds the complete datagram plus, when it is fragmented, one
    /// fragment: `message_bytes` + 40 + the link MTU suffices whatever header
    /// the selected route adds, since a whole packet, any Segment Routing
    /// Header included, is within the path budget and a fragmented message
    /// is cut to at most that budget.
    ///
    /// When the queue is empty, or holds only messages waiting for an
    /// identifier, the call sends the Echo adjunct's next due probe instead
    /// (`Host::adjunct_due`), one unfragmented packet; None when the queue
    /// is empty and no probe is due.
    pub fn icmp_output(
        &mut self,
        now: Instant,
        packet: &mut [u8],
        submit: impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<Option<BackendOutcome>, Error> {
        // Free what held messages no longer need.
        self.settle_held_icmp(now);
        if self.icmp_output.len == 0 {
            // With nothing queued, the Echo adjunct's next due probe.
            return self.adjunct_probe(now, packet, submit);
        }
        self.now = self.now.max(now);
        let mut submit = submit;
        // Each queued message is tried at most once per call.
        for _ in 0..self.icmp_output.len {
            let Some((queued, _)) = self.icmp_output.front() else {
                break;
            };
            match self.icmp_output_head(now, queued, packet, &mut submit)? {
                Some(outcome) => return Ok(Some(outcome)),
                None => {
                    self.icmp_output.hold();
                    self.icmp_output.rotate();
                }
            }
        }
        // Every queued message waits for an identifier.
        Ok(Some(
            self.adjunct_probe(now, packet, &mut submit)?
                .unwrap_or(BackendOutcome::WouldBlock),
        ))
    }

    // Send the oldest queued message (as `icmp_output` describes); None when
    // it waits for an identifier on a DF-clear route, or for its neighbor's
    // resolution, and stays queued.
    fn icmp_output_head(
        &mut self,
        now: Instant,
        queued: Queued,
        packet: &mut [u8],
        submit: &mut impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<Option<BackendOutcome>, Error> {
        let mut result = Err(DatagramError::Host(Error::Obsolete));
        // On a route that keeps DF, a message that the path budget carries
        // whole is never lost for want of an identifier: without one it goes
        // out unfragmented. On a DF-clear route the whole packet needs one
        // too, so a retryable shortage holds the message instead.
        for fragments in [true, false] {
            let plan = match self.plan_icmp_output(queued, packet, fragments) {
                Ok(plan) => plan,
                Err(error) => {
                    self.icmp_output.counters.unsent += 1;
                    self.icmp_output.pop();
                    return Err(error);
                }
            };
            let fragmented = plan.fragment_size.is_some();
            let clears_df = plan.snapshot.clears_dont_fragment();
            let held = crate::discovery::HeldOutput::Icmp(queued.arrival);
            let link_layer = match self.host_output_neighbor(plan.snapshot.key(), now, held) {
                Ok(None) => None,
                Ok(Some(crate::NeighborHop::Resolved(mac))) => Some(mac),
                // Nothing was submitted: held output, sent once resolved.
                Ok(Some(crate::NeighborHop::Held)) => return Ok(None),
                Err(error) => {
                    self.icmp_output.counters.unsent += 1;
                    self.icmp_output.pop();
                    return Err(error);
                }
            };
            let mut resolved = |egress: UdpEgress, bytes: &[u8]| {
                submit(
                    UdpEgress {
                        link_layer,
                        ..egress
                    },
                    bytes,
                )
            };
            result = self.transmit(now, plan, packet, |_, _| None, None, None, &mut resolved);
            if let Err(DatagramError::Backpressure(backpressure)) = result
                && clears_df
                && matches!(
                    backpressure,
                    IdentifierBackpressure::Unavailable { until: Some(_) }
                        | IdentifierBackpressure::Exhausted { .. }
                )
            {
                // Nothing was submitted (the lease precedes every packet):
                // held output, retried on a later pass.
                return Ok(None);
            }
            if !(fragmented && matches!(result, Err(DatagramError::Backpressure(_)))) {
                break;
            }
        }
        match result {
            Ok(report) => {
                self.icmp_output.pop();
                Ok(Some(report.terminal.unwrap_or(BackendOutcome::Submitted)))
            }
            Err(DatagramError::NotSubmitted(outcome)) => {
                if !matches!(
                    outcome,
                    BackendOutcome::WouldBlock | BackendOutcome::Rejected
                ) {
                    // Refused by the backend (an IPv4 next hop without a
                    // static neighbor, for one): consumed unsent.
                    if outcome == BackendOutcome::NotSubmitted {
                        self.icmp_output.counters.unsent += 1;
                    }
                    self.icmp_output.pop();
                }
                Ok(Some(outcome))
            }
            Err(error) => {
                self.icmp_output.counters.unsent += 1;
                self.icmp_output.pop();
                Err(match error {
                    DatagramError::Host(error) => error,
                    // No identifier on a route that keeps DF for a message
                    // the budget cannot carry whole (quiet period, MDL
                    // ceiling), or none can ever be issued (no allocator,
                    // entropy failure): the message is not sent rather than
                    // held at the head of the queue.
                    _ => Error::Capacity,
                })
            }
        }
    }

    // Path authority and layout for the queued message: the complete packet
    // in `packet[..header + len]`, or for fragmentation the message at
    // `packet[size..]`.
    fn plan_icmp_output(
        &mut self,
        queued: Queued,
        packet: &mut [u8],
        fragments: bool,
    ) -> Result<Plan, Error> {
        let ip = queued.ip;
        let (request, via) = self.icmp_route(queued)?;
        let resolved = self.paths.resolve_via(request, via)?;
        self.forwarding_resolved(resolved.key())?;
        let (client, snapshot) = self.paths.acquire_via(request, via)?;
        self.paths.release(client)?;
        if snapshot.status() != PathStatus::Valid {
            return Err(Error::Obsolete);
        }
        // A link-local destination is bound to the link it was received on.
        if is_link_local(ip.destination) && snapshot.key().link() != queued.link {
            return Err(Error::Obsolete);
        }
        let ipv4 = ip.source.is_ipv4();
        let options = queued.options;
        // The complete header H of the route selected now: an SR route's
        // Segment Routing Header is part of it.
        let header =
            self.header_plan(snapshot.key())?.len + options.map_or(0, |o| o.as_bytes().len());
        let hop_limit = self.icmp_output.limits.hop_limit;
        let (_, message) = self.icmp_output.front().ok_or(Error::Obsolete)?;
        // An error is encoded again, behind the header of the route selected
        // now, from the quote stored for a minimal header: the quote is
        // truncated (and the checksum recomputed) whenever that header is
        // longer, at every attempt, so after WouldBlock or a route
        // replacement the packet stays within the family's error size and an
        // IPv6 error is never fragmented; a header that leaves no room for
        // the ICMP header within the minimum MTU is not sent. An IPv4
        // error's header never grows, and one longer than the path's size
        // is fragmented like other Host ICMP output.
        let data_len = match queued.error {
            Some(kind) => ntcp_icmp::encode_error(
                ip,
                kind,
                message.get(8..).ok_or(Error::Obsolete)?,
                header,
                packet.get_mut(header..).ok_or(Error::Capacity)?,
            )?,
            None => queued.len,
        };
        let len = header + data_len;
        let budget = snapshot.ip_packet_budget()? as usize;
        // The Echo adjunct probes the direct path: its confirmed size says
        // nothing about a source route.
        let size = if options.is_some_and(|o| source_routed(o.as_bytes())) {
            self.connectionless_unconfirmed_size(snapshot)?
        } else {
            self.connectionless_size(snapshot)?
        } as usize;
        let guarantee = if ipv4 {
            self.datagram_limits
                .peer_reassembly_ipv4
                .unwrap_or(crate::IPV4_PEER_REASSEMBLY)
        } else {
            self.datagram_limits
                .peer_reassembly_ipv6
                .unwrap_or(crate::IPV6_PEER_REASSEMBLY)
        } as usize;
        let protocol = if ipv4 { 1 } else { 58 };
        let fragment_size = if len <= size {
            None
        } else if fragments
            && (ipv4 || queued.error.is_none())
            && len <= guarantee
            && self
                .fragment_count(
                    ip,
                    options.as_ref(),
                    self.header_plan(snapshot.key())?.segments,
                    queued.len,
                    size,
                )
                .is_ok()
        {
            Some(size)
        } else if len <= budget {
            None
        } else {
            return Err(Error::Unsupported);
        };
        match fragment_size {
            Some(size) => {
                packet
                    .get_mut(size..size + queued.len)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(message);
            }
            None => {
                // The codec moves the message behind the options; an error
                // is already in place.
                let base = if ipv4 { header_len(ipv4) } else { header };
                if queued.error.is_none() {
                    packet
                        .get_mut(base..base + queued.len)
                        .ok_or(Error::Capacity)?
                        .copy_from_slice(message);
                }
                let header = ntcp_ip::Header {
                    ip,
                    hop_limit,
                    dscp: 0,
                    ecn: 0,
                    ipv4_options: Default::default(),
                };
                let encoded = if let Some(options) = options {
                    ntcp_ip::encode_datagram_with_options(
                        packet, header, &options, protocol, data_len,
                    )
                } else if ipv4 {
                    ntcp_ip::encode_datagram(packet, header, protocol, data_len, 0)
                } else {
                    ntcp_ip6::encode_routed(
                        packet,
                        ntcp_ip6::Header {
                            ip,
                            hop_limit,
                            dscp: 0,
                            ecn: 0,
                        },
                        self.header_plan(snapshot.key())?.segments,
                        protocol,
                        data_len,
                    )
                };
                if encoded? != len {
                    return Err(Error::Obsolete);
                }
            }
        }
        Ok(Plan {
            ip,
            protocol,
            dscp: 0,
            hop_limit,
            data_len,
            fragment_size,
            snapshot,
            client: None,
            options,
        })
    }

    // Queue one ICMP message with its IPv4 options as the Host's own
    // originators do; false when it is dropped (counted).
    #[cfg(test)]
    pub(crate) fn queue_icmp(
        &mut self,
        ip: IpMetadata,
        link: LinkId,
        message: &[u8],
        options: Option<EncodedIpv4Options>,
    ) -> bool {
        let output = &mut self.icmp_output;
        if message.len() > output.limits.message_bytes {
            output.counters.dropped += 1;
            return false;
        }
        let Some(slot) = output.free() else {
            return false;
        };
        slot[..message.len()].copy_from_slice(message);
        output.push(ip, link, message.len(), options, None);
        true
    }
}

// Queue one originated error (`originate`) when the Host ICMP output is
// enabled and has room.
fn queue_error(
    errors: &mut crate::icmp_error::ErrorLimiter,
    icmp_output: &mut IcmpOutput,
    now: Instant,
    error: ReassemblyError,
    arrival: Arrival,
    invoking: &[u8],
) {
    if icmp_output.limits.messages != 0
        && let Some(slot) = icmp_output.free()
        && let Some(sent) = originate(errors, now, error, arrival, invoking, slot)
    {
        icmp_output.counters.errors += 1;
        icmp_output.push(sent.ip, sent.link, sent.len, None, Some(sent.kind));
    }
}

// The protocols that end an IPv6 header chain this Host processes: the
// upper layers it dispatches and No Next Header (RFC 8200 section 4.7).
// Every other selector, AH and ESP included, is unrecognized.
pub(crate) fn processed_upper_layer(protocol: u8) -> bool {
    matches!(
        protocol,
        ntcp_ip::PROTOCOL_TCP | ntcp_ip::PROTOCOL_UDP | 58 | 59
    )
}
