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
use ntcp::{InputDisposition, Instant, IpMetadata, RxPacketMetadata};
use ntcp_icmp::EchoKind;
use ntcp_path::{Dscp, LinkId, PathStatus, ScopedAddress, SourceId};

use crate::emitter::{DatagramError, Plan, header_len};
use crate::icmp_error::{ReassemblyError, originate};
use crate::reassembly::{Arrival, Input, Piece, admissible_source};
use crate::{BackendOutcome, Error, Host, IcmpDispatch, IcmpOutcome, IngressContext, UdpEgress};

/// Storage for ICMP messages this Host originates. Zero `messages` (the
/// `managed_limits` default) originates none: an embedding enables the
/// queue only together with a drain (`Host::icmp_output`), since queued
/// messages are sent nowhere else. `managed_icmp_output_limits` adds the
/// path client a drain uses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IcmpOutputLimits {
    /// Messages queued for the drain; later ones are dropped and counted.
    pub messages: usize,
    /// Largest ICMP message (header and data) one queue slot holds. At
    /// least an ICMPv6 error with RFC 4443 section 2.4(c)'s maximal quote,
    /// so that no originated error is truncated by storage; an Echo Request
    /// whose reply does not fit is not answered (never truncated, RFC 1122
    /// section 3.2.2.6, RFC 4443 section 4.2).
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
    /// Messages not queued: the queue was full or the message exceeded a
    /// slot.
    pub dropped: u64,
    /// Queued messages discarded at the drain: no route or source any more,
    /// larger than the path allows and beyond the peer reassembly guarantee,
    /// or no identifier available for its fragments.
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
    /// Not answered because the request carries an IPv4 source route: RFC
    /// 1122 section 3.2.2.6 requires its reversal in the reply, and received
    /// option metadata does not reach Host-originated replies yet.
    SourceRouted,
}

#[derive(Clone, Copy, Debug)]
struct Queued {
    ip: IpMetadata,
    link: LinkId,
    len: usize,
}

pub(crate) struct IcmpOutput {
    limits: IcmpOutputLimits,
    entries: Vec<Option<Queued>>,
    bytes: Vec<u8>,
    head: usize,
    len: usize,
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
            counters: IcmpOutputCounters::default(),
        })
    }
    // Storage of the next free slot, or None (counted) when full.
    fn free(&mut self) -> Option<&mut [u8]> {
        if self.len == self.limits.messages {
            self.counters.dropped += 1;
            return None;
        }
        let index = (self.head + self.len) % self.limits.messages;
        let stride = self.limits.message_bytes;
        Some(&mut self.bytes[index * stride..][..stride])
    }
    fn push(&mut self, queued: Queued) {
        let index = (self.head + self.len) % self.limits.messages;
        self.entries[index] = Some(queued);
        self.len += 1;
    }
    fn front(&self) -> Option<(Queued, &[u8])> {
        if self.len == 0 {
            return None;
        }
        let queued = self.entries[self.head]?;
        let stride = self.limits.message_bytes;
        Some((queued, &self.bytes[self.head * stride..][..queued.len]))
    }
    fn pop(&mut self) {
        self.entries[self.head] = None;
        self.head = (self.head + 1) % self.limits.messages;
        self.len -= 1;
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
}

impl Envelope {
    // An unfragmented packet as it arrived.
    pub(crate) const fn physical(context: IngressContext, len: usize) -> Self {
        Self {
            context,
            len,
            reassembled: false,
        }
    }
    pub const fn context(self) -> IngressContext {
        self.context
    }
    pub const fn reassembled(self) -> bool {
        self.reassembled
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
/// rewritten; an IPv6 datagram without its Fragment header). Dispatch
/// (`Host::input_datagram`, `Host::input_icmp_datagram`) validates it like
/// any arriving packet.
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

/// The outcome of one physical packet.
#[derive(Clone, Copy, Debug)]
pub enum Received<'a> {
    Datagram(Datagram<'a>),
    /// A fragment stored (or an exact duplicate): its datagram is still
    /// incomplete.
    Held,
    /// A fragment discarded by reassembly, counted in
    /// `Host::reassembly_counters`; any error it caused is queued.
    Discarded,
}

fn is_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v) if v.is_unicast_link_local())
}

// Any IPv4 Loose or Strict Source and Record Route option.
fn source_routed(options: &[u8]) -> bool {
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
        let whole = Datagram {
            envelope: Envelope {
                context,
                len: frame.len(),
                reassembled: false,
            },
            bytes: frame,
        };
        let piece = match frame.first().ok_or(ntcp_ip::Error::Truncated)? >> 4 {
            4 => {
                let source_routes = match capabilities.ipv4 {
                    crate::Ipv4Receive::Disabled => return Err(Error::Unsupported),
                    crate::Ipv4Receive::Unrecognized => false,
                    crate::Ipv4Receive::Options { source_routes } => source_routes,
                };
                let packet = ntcp_ip::parse_fragment(frame, source_routes)?;
                if packet.fragmentation.is_complete() {
                    return Ok(Received::Datagram(whole));
                }
                Piece::ipv4(&packet)
            }
            6 if capabilities.ipv6 == crate::Ipv6Receive::BaseHeader => {
                let packet = ntcp_ip6::parse_fragment(frame)?;
                let Some(piece) = Piece::ipv6(&packet) else {
                    return Ok(Received::Datagram(whole));
                };
                piece
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
                    },
                    bytes: out,
                }))
            }
            Input::Discarded(discard) => {
                // RFC 8200 section 4.5's Parameter Problems about this
                // fragment; overlap and every IPv4 discard are silent.
                if let Some(error) = ReassemblyError::for_discard(ipv6, discard)
                    && icmp_output.limits.messages != 0
                    && let Some(slot) = icmp_output.free()
                    && let Some(sent) = originate(errors, now, error, arrival, frame, slot)
                {
                    icmp_output.counters.errors += 1;
                    icmp_output.push(Queued {
                        ip: sent.ip,
                        link: sent.link,
                        len: sent.len,
                    });
                }
                Ok(Received::Discarded)
            }
        }
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
                if icmp_output.limits.messages != 0
                    && let Some(slot) = icmp_output.free()
                    && let Some(sent) = originate(
                        errors,
                        now,
                        ReassemblyError::TimeExceeded,
                        expired.arrival,
                        expired.first_fragment,
                        slot,
                    )
                {
                    icmp_output.counters.errors += 1;
                    icmp_output.push(Queued {
                        ip: sent.ip,
                        link: sent.link,
                        len: sent.len,
                    });
                }
            },
        );
    }

    /// Validate a complete datagram for dispatch, with transport ingress
    /// ownership (the destination is a source registered on its arrival
    /// link), as `decode_ingress` does for an unfragmented frame.
    pub fn decode_datagram<'a>(
        &self,
        datagram: Datagram<'a>,
    ) -> Result<crate::IngressPacket<'a>, Error> {
        let packet = self.parse_datagram(datagram)?;
        self.owned_on_link(datagram.context(), packet.ip.destination)?;
        Ok(packet)
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

    /// Dispatch one complete datagram exactly like an unfragmented packet:
    /// see `input_ip`, which is this after `receive`.
    pub fn input_datagram(
        &mut self,
        endpoint: &mut ntcp::Endpoint,
        now: Instant,
        datagram: Datagram<'_>,
        metadata: RxPacketMetadata,
        outgoing_dscp: u8,
        timestamp: Option<u32>,
    ) -> Result<InputDisposition, Error> {
        self.check_endpoint(endpoint)?;
        let packet = self.parse_datagram(datagram)?;
        if crate::is_icmp(&packet) {
            // One dispatcher for every embedding. A reserved owner keeps this
            // entrypoint's established OutputReserved contract, with nothing
            // applied or published; callers that retain use input_icmp_datagram.
            return match self.input_icmp_datagram(endpoint, now, datagram)? {
                IcmpDispatch::Deferred(_) => Err(ntcp::EndpointError::OutputReserved.into()),
                IcmpDispatch::Completed(
                    IcmpOutcome::Discarded(crate::IcmpDiscard::SourceQuench)
                    | IcmpOutcome::Echo(EchoDisposition::Dropped | EchoDisposition::SourceRouted)
                    | IcmpOutcome::Probe(crate::ProbeOutcome::Unmatched),
                ) => Ok(InputDisposition::Dropped),
                IcmpDispatch::Completed(_) => Ok(InputDisposition::Processed),
            };
        }
        self.input_transport(
            endpoint,
            now,
            datagram.context(),
            &packet,
            metadata,
            outgoing_dscp,
            timestamp,
        )
    }

    /// The single ICMP dispatch for one complete datagram: an Echo Request is
    /// answered by the Host's Echo service, every other message goes to
    /// error classification and correlation (`input_icmp`).
    pub fn input_icmp_datagram(
        &mut self,
        endpoint: &mut ntcp::Endpoint,
        now: Instant,
        datagram: Datagram<'_>,
    ) -> Result<IcmpDispatch, Error> {
        self.check_endpoint(endpoint)?;
        let packet = self.parse_datagram(datagram)?;
        if !crate::is_icmp(&packet) {
            return Err(Error::Unsupported);
        }
        let (request, reply) = if packet.ip.source.is_ipv4() {
            (8, 0)
        } else {
            (128, 129)
        };
        if packet.payload.first() == Some(&request) {
            return Ok(IcmpDispatch::Completed(IcmpOutcome::Echo(
                self.echo(datagram.context(), &packet)?,
            )));
        }
        if packet.payload.first() == Some(&reply) {
            // Echo Replies answer only the Host's adjunct probes.
            self.owned_in_context(datagram.context(), packet.ip.destination)?;
            self.now = self.now.max(now);
            return Ok(IcmpDispatch::Completed(IcmpOutcome::Probe(
                self.adjunct_reply(now, &packet)?,
            )));
        }
        self.dispatch_icmp(endpoint, now, datagram, &packet)
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
    fn echo(
        &mut self,
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
        if source_routed(packet.options.as_bytes()) {
            return Ok(EchoDisposition::SourceRouted);
        }
        let output = &mut self.icmp_output;
        if output.limits.messages == 0 {
            return Ok(EchoDisposition::Dropped);
        }
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
        output.push(Queued {
            ip: reply,
            link: context.link,
            len,
        });
        Ok(EchoDisposition::Queued)
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
    /// `packet` holds the complete datagram plus, when it is fragmented, one
    /// fragment: `message_bytes` + 40 + the link MTU suffices.
    ///
    /// When the queue is empty the call sends the Echo adjunct's next due
    /// probe instead (`Host::adjunct_due`), one unfragmented packet; None
    /// when there is neither.
    pub fn icmp_output(
        &mut self,
        now: Instant,
        packet: &mut [u8],
        submit: impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<Option<BackendOutcome>, Error> {
        let Some((queued, _)) = self.icmp_output.front() else {
            // With nothing queued, the Echo adjunct's next due probe.
            return self.adjunct_probe(now, packet, submit);
        };
        self.now = self.now.max(now);
        let mut submit = submit;
        let mut result = Err(DatagramError::Host(Error::Obsolete));
        // A message that the path budget carries whole is never lost for
        // want of an identifier: without one it goes out unfragmented.
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
            result = self.transmit(now, plan, packet, |_, _| None, None, None, &mut submit);
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
                    self.icmp_output.pop();
                }
                Ok(Some(outcome))
            }
            Err(error) => {
                self.icmp_output.counters.unsent += 1;
                self.icmp_output.pop();
                Err(match error {
                    DatagramError::Host(error) => error,
                    // No identifier (quiet period, MDL ceiling, entropy):
                    // the message is not sent rather than held at the head
                    // of the queue.
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
        let request = self.request(ip.source, ip.destination, Dscp::new(0)?)?;
        let via = ScopedAddress::new(ip.destination, None)?;
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
        let header = header_len(ipv4);
        let len = header + queued.len;
        let budget = snapshot.ip_packet_budget()? as usize;
        let size = self.connectionless_size(snapshot)? as usize;
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
            && len <= guarantee
            && self.fragment_count(ip, queued.len, size).is_ok()
        {
            Some(size)
        } else if len <= budget {
            None
        } else {
            return Err(Error::Unsupported);
        };
        let hop_limit = self.icmp_output.limits.hop_limit;
        let (_, message) = self.icmp_output.front().ok_or(Error::Obsolete)?;
        match fragment_size {
            Some(size) => {
                packet
                    .get_mut(size..size + queued.len)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(message);
            }
            None => {
                packet
                    .get_mut(header..len)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(message);
                let encoded = if ipv4 {
                    ntcp_ip::encode_datagram(
                        packet,
                        ntcp_ip::Header {
                            ip,
                            hop_limit,
                            dscp: 0,
                            ecn: 0,
                            ipv4_options: Default::default(),
                        },
                        protocol,
                        queued.len,
                        0,
                    )
                } else {
                    ntcp_ip6::encode_datagram(
                        packet,
                        ntcp_ip6::Header {
                            ip,
                            hop_limit,
                            dscp: 0,
                            ecn: 0,
                        },
                        protocol,
                        queued.len,
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
            data_len: queued.len,
            fragment_size,
            snapshot,
            client: None,
        })
    }
}
