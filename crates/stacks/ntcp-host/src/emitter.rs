//! The Host datagram emitter: one transaction that sends a complete datagram
//! the Host originates (a UDP datagram or an ICMP message) unfragmented or
//! as source fragments, with per-fragment submission evidence.
//!
//! RFC 4821 section 8 recommends that IPv4 hosts mimic IPv6: datagrams
//! larger than the effective Path MTU are fragmented in the host, even when
//! smaller than the first-hop MTU, and DF is set on the fragments (RFC 4821
//! 4821-062/155). Every IPv4 fragment therefore carries DF, except on a
//! route or path whose owner disabled discovery: there the IP layer leaves
//! DF clear on every packet whatever the upper layer requests (RFC 1191
//! section 6.6, the user's recorded disposition for administratively
//! flagged routes), source fragments and whole datagrams alike, each whole
//! DF-clear datagram with its own leased Identification. Every IPv6
//! fragment repeats the unfragmentable part, the base header and on an SR
//! route its Segment Routing Header, before the Fragment header and the
//! fragment data (RFC 8200 section 4.5); fragment zero carries the complete
//! upper-layer header. The upper-layer checksum, computed once over the
//! complete datagram with the final destination, stays valid. IPv6 atomic
//! fragments are never originated (RFC 8021): a datagram that fits is sent
//! unfragmented. TCP never enters this emitter.
//!
//! The transaction reserves every local resource before the first fragment
//! (the identifier lease and one independently sealable ledger ticket per
//! fragment), submits fragments in order, revalidating the path authority
//! for each, and stops at the first uncertain or certainly unsuccessful
//! backend outcome. Fragments that were submitted or possibly submitted are
//! sealed one by one; only the unattempted suffix is cancelled. A sent
//! prefix is never reported as unsent, and a whole retry is a new datagram
//! with a new identifier.

use core::net::{IpAddr, Ipv6Addr};

use ntcp::{EncodedIpv4Options, Instant, IpMetadata};
use ntcp_path::{PathSnapshot, PathStatus};

use crate::ident::{IdentifierBackpressure, IdentifierLimits};
use crate::ledger::Evidence;
use crate::{BackendOutcome, Error, Host, UdpEgress};

/// RFC 1122 section 3.3.3 (and its DISCUSSION): without knowledge of the
/// destination's reassembly capacity, a host must not send a datagram that
/// would need more than EMTU_R = 576 octets to be reassembled.
pub const IPV4_PEER_REASSEMBLY: u32 = 576;
/// RFC 8200 section 5: a node must be able to accept a fragmented packet
/// that, after reassembly, is up to 1500 octets long.
pub const IPV6_PEER_REASSEMBLY: u32 = 1500;

/// Configuration of the datagram emitter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatagramLimits {
    /// Most fragments one datagram may use. Each holds one ledger ticket
    /// for the duration of a transaction (`managed_udp_limits` adds them to
    /// the concurrent attempts); a datagram that would need more is refused
    /// as too big. Zero sends nothing fragmented.
    pub max_fragments: usize,
    /// The identifier allocator's storage and maximum datagram lifetime.
    pub identifiers: IdentifierLimits,
    /// Connectionless initial effective PMTU, complete IP octets, per family.
    pub connectionless: ConnectionlessSizing,
    /// Peer reassembly capacity (complete reconstructed IP octets) this
    /// deployment may assume for messages the Host itself originates (Echo
    /// Replies); None keeps the receiver guarantee of RFC 1122 / RFC 8200.
    pub peer_reassembly_ipv4: Option<u32>,
    pub peer_reassembly_ipv6: Option<u32>,
    /// The ICMP Echo adjunct that confirms larger connectionless sizes per
    /// path (RFC 4821 section 10.3); disabled by default.
    pub adjunct: crate::AdjunctLimits,
}

/// Initial effective PMTU used to size fragments for connectionless senders
/// (RFC 4821 section 7.2), separate from TCP's search and from shared learned
/// ceilings: it is never written into shared state and never lowers another
/// client's budget. Fragment size = min(shared ordinary budget, max(initial,
/// the adjunct's confirmed lower bound for the path)).
//= https://www.rfc-editor.org/rfc/rfc4821#section-10.3
//= reason=The Host has a separate Host-wide control for the connectionless initial eff_pmtu, DatagramLimits::connectionless (ConnectionlessSizing, crates/stacks/ntcp-host/src/emitter.rs), distinct from TCP's PLPMTUD configuration: by default RFC 4821 section 7.2's suggested 1024 octets for IPv4 and the 1280-octet IPv6 minimum link MTU, validated when the Host is created. Until the Echo adjunct confirms a larger size, Host UDP Fragment mode and Echo Replies (a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) cut fragments to min(shared ordinary budget, initial value), even below a 1500 first hop, and the initial value is never written into shared state or lowers another client's budget. Host tests assert the 1024/1280 effective size and fragments within it under a 1500 budget; the integration/rfc_host fragment case captures 1020-octet IPv4 and 1280-octet IPv6 reply fragments before any probe.
//# Since connectionless protocols might not keep enough state to effectively diagnose MTU black holes, it would be more robust to err on the side of using too small of an initial MTU (e.g., 1 kByte or less) prior to probing a path to measure the MTU. For this reason, implementations that use IP fragmentation SHOULD use an initial eff_pmtu, which is selected as described in Section 7.2, except using a separate global control for the default initial eff_mtu for connectionless protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionlessSizing {
    pub ipv4: u32,
    pub ipv6: u32,
}

impl Default for ConnectionlessSizing {
    /// RFC 4821 section 7.2 suggests 1024 octets as a search_low "likely to
    /// work over a very wide range of environments"; IPv6 links carry at
    /// least 1280 (RFC 8200 section 5).
    fn default() -> Self {
        Self {
            ipv4: 1024,
            ipv6: 1280,
        }
    }
}

impl DatagramLimits {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let ConnectionlessSizing { ipv4, ipv6 } = self.connectionless;
        let capability = |c: Option<u32>, floor: u32, max: u32| {
            c.is_none_or(|c| (floor..=max).contains(&c))
        };
        if !(68..=65535).contains(&ipv4)
            || !(1280..=65575).contains(&ipv6)
            || !capability(self.peer_reassembly_ipv4, IPV4_PEER_REASSEMBLY, 65535)
            || !capability(self.peer_reassembly_ipv6, IPV6_PEER_REASSEMBLY, 65575)
        {
            return Err(Error::Capacity);
        }
        self.adjunct.validate()
    }
}

/// How one UDP datagram larger than the unfragmented limit is handled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSendMode {
    /// Source-fragment it to the connectionless effective size (RFC 4821
    /// section 8) when the receiver can reassemble it.
    Fragment,
    /// Refuse it with the unfragmented payload limit; nothing is submitted
    /// (the `udp_send` contract).
    Refuse,
    /// Send it as one unfragmented probe up to the first-hop MTU (RFC 4821
    /// section 9): only the learned-size admission is bypassed.
    Probe,
}

/// Mode and the peer reassembly capability, in complete reconstructed IP
/// octets, that the application knows from explicit application, protocol or
/// deployment knowledge. Receiving a large datagram from the peer is not such
/// knowledge. None assumes only the receiver guarantee: IPv4 576 (RFC 1122
/// sections 3.3.2 and 3.3.3), IPv6 1500 (RFC 8200 section 5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpSend {
    pub mode: UdpSendMode,
    pub peer_capability: Option<u32>,
}

impl Default for UdpSend {
    fn default() -> Self {
        Self {
            mode: UdpSendMode::Refuse,
            peer_capability: None,
        }
    }
}

/// What a flow may send to one destination now, and how
/// `udp_send_datagram` will send each payload size under `send`.
///
/// Fragment mode's rule, which `fragments` and `buffer_len` state exactly:
/// a payload within `effective_payload` goes whole; a larger one within
/// `fragmentable_payload` is cut into fragments of `effective_size`; a
/// payload that cannot be fragmented but is within `unfragmented_payload`
/// goes whole (Fragment mode is never stricter than Refuse mode); anything
/// larger is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagramLimits {
    pub path: crate::UdpPathLimits,
    pub send: UdpSend,
    /// Largest UDP payload one unfragmented datagram carries under the
    /// shared ordinary budget (`path.max_payload`). This is the limit Refuse
    /// mode and `udp_send` enforce; in Fragment mode a payload below it but
    /// above `effective_payload` is still fragmented when the peer guarantee
    /// allows it.
    pub unfragmented_payload: usize,
    /// The flow's connectionless effective size (complete IP octets):
    /// min(shared ordinary budget, the flow's probe upper bound,
    /// max(connectionless initial PMTU, the adjunct's confirmed lower bound,
    /// the flow's confirmed probe size)). Fragments are cut to it (RFC 4821
    /// sections 7.2, 8, 9 and 10.3).
    pub effective_size: u32,
    /// Largest UDP payload whose datagram fits `effective_size` whole.
    pub effective_payload: usize,
    /// Largest UDP payload Fragment mode fragments: bounded by the peer
    /// guarantee in force, `max_fragments` and the family's datagram size.
    /// At or below `effective_payload` when nothing can be fragmented (and
    /// zero outside Fragment mode).
    pub fragmentable_payload: usize,
    /// Largest UDP payload this mode accepts: in Fragment mode the larger of
    /// `fragmentable_payload` and `unfragmented_payload`, the first-hop
    /// maximum in Probe mode, `unfragmented_payload` in Refuse mode.
    pub max_payload: usize,
    /// The peer reassembly guarantee in force (complete IP octets) and
    /// whether it was stated by the application.
    pub guarantee: u32,
    pub guarantee_stated: bool,
    /// The flow's own probe-outcome bounds for this path (all None when its
    /// application reported no outcome on this path incarnation).
    pub probe: crate::UdpProbeBounds,
}

impl UdpDatagramLimits {
    /// Whether `udp_send_datagram` sends a payload of this length as source
    /// fragments (the decision it applies itself).
    pub fn fragments(&self, payload_len: usize) -> bool {
        self.send.mode == UdpSendMode::Fragment
            && payload_len > self.effective_payload
            && payload_len <= self.fragmentable_payload
    }

    /// Length of the `packet` buffer `udp_send_datagram` needs for a payload:
    /// the complete datagram when it goes whole; when it is split, its UDP
    /// header and payload plus room for one fragment.
    pub fn buffer_len(&self, payload_len: usize) -> usize {
        let transport = ntcp_ip::UDP_HEADER + payload_len;
        if self.fragments(payload_len) {
            self.effective_size as usize + transport
        } else {
            self.path.header_len + transport
        }
    }
}

/// The record of a Probe-mode submission. It proves no delivery and writes
/// no shared state (RFC 4821 section 9). A definite submission carries the
/// one receipt its application reports the outcome with
/// (`Host::udp_report_probe`); an uncertain one carries none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeRecord {
    /// False when the backend outcome was unknown.
    pub definite: bool,
    pub flow_generation: u64,
    pub path: ntcp_path::PathId,
    /// The shared version and negative revision the probe was sized against.
    pub version: u64,
    pub negative_revision: u64,
    /// Complete IP octets, and the estimate it exceeded (None when it did
    /// not exceed the ordinary budget).
    pub size: u32,
    pub above: Option<u32>,
    pub submitted_at: Instant,
    pub receipt: Option<crate::ProbeReceipt>,
}

/// The outcome of a datagram transaction that submitted at least one packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramReport {
    /// Complete datagram length in IP octets (one header).
    pub ip_len: usize,
    /// Physical packets planned: 1 when unfragmented.
    pub fragments: usize,
    pub submitted: usize,
    pub possibly_submitted: usize,
    /// The backend outcome that stopped the transaction early, None when
    /// every fragment was submitted.
    pub terminal: Option<BackendOutcome>,
    /// The leased Identification of a fragmented datagram.
    pub identification: Option<u32>,
    pub probe: Option<ProbeRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramError {
    /// Larger than this mode allows: `max_payload` is the largest UDP payload
    /// accepted now (Refuse keeps today's unfragmented limit).
    TooBig { max_payload: usize },
    /// The datagram would need fragmentation beyond the peer reassembly
    /// guarantee in force; a larger stated capability may permit it.
    PeerLimit { max_payload: usize, guarantee: u32 },
    /// No identifier can be leased now; nothing was submitted.
    Backpressure(IdentifierBackpressure),
    /// Probe mode on a path whose owner disabled discovery (RFC 1191
    /// section 6.6, RFC 8201 section 5.6); nothing was submitted.
    DiscoveryDisabled,
    /// Probe mode while the flow already holds its configured number of
    /// unreported, still usable receipts (`UdpLimits::probe_receipts`);
    /// nothing was submitted. Reporting outcomes, or their expiry, frees them.
    ReceiptsExhausted,
    /// Probe mode at or above `size` complete IP octets before `until`: the
    /// flow's application reported a timeout failure at that size (RFC 4821
    /// section 7.6.3); nothing was submitted. Smaller probes are accepted.
    RetrySuppressed { size: u32, until: Instant },
    /// The first packet was certainly not submitted; nothing was recorded.
    NotSubmitted(BackendOutcome),
    Host(Error),
}
impl From<Error> for DatagramError {
    fn from(error: Error) -> Self {
        Self::Host(error)
    }
}

pub(crate) fn header_len(ipv4: bool) -> usize {
    if ipv4 {
        ntcp_ip::IPV4_HEADER
    } else {
        ntcp_ip6::IPV6_HEADER
    }
}

/// Largest complete datagram (IP octets) one family can carry: IPv4 Total
/// Length, IPv6 Payload Length plus the fixed header.
pub(crate) fn family_max(ipv4: bool) -> usize {
    if ipv4 { 65535 } else { 65535 + 40 }
}

/// One datagram to send: its IP parameters, the transport bytes and how to
/// cut it.
#[derive(Clone, Copy)]
pub(crate) struct Plan {
    pub ip: IpMetadata,
    pub protocol: u8,
    pub dscp: u8,
    pub hop_limit: u8,
    pub data_len: usize,
    /// Cut into fragments of at most this many octets; None sends it whole.
    pub fragment_size: Option<usize>,
    pub snapshot: PathSnapshot,
    pub client: Option<ntcp_path::ClientId>,
    /// IPv4 options sent as is in the first packet (and their copied ones
    /// in later fragments); `ip.destination` is their final destination.
    pub options: Option<EncodedIpv4Options>,
}

impl Plan {
    // A source route takes the datagram off the direct path the Echo
    // adjunct probes.
    fn source_routed(&self) -> bool {
        self.options
            .is_some_and(|o| crate::ingress::source_routed(o.as_bytes()))
    }
}

enum Cutter<'a> {
    V4(ntcp_ip::Fragmenter),
    // Every fragment repeats the base header and any Segment Routing Header.
    V6(ntcp_ip6::Fragmenter<'a>),
}
impl Cutter<'_> {
    fn len(&self, offset: usize, limit: usize) -> Result<usize, Error> {
        Ok(match self {
            Self::V4(f) => f.fragment_len(offset, limit)?,
            Self::V6(f) => f.fragment_len(offset, limit)?,
        })
    }
    fn header(&self, offset: usize) -> usize {
        match self {
            Self::V4(f) => f.header_len(offset),
            Self::V6(f) => f.header_len(),
        }
    }
    fn encode(&self, packet: &mut [u8], offset: usize, data: &[u8]) -> Result<usize, Error> {
        Ok(match self {
            Self::V4(f) => f.encode(packet, offset, data)?,
            Self::V6(f) => f.encode(packet, offset, data)?,
        })
    }
}

// The fragmenter of one datagram: IPv4 with its options, or IPv6 with the
// Segment Routing Header of `segments` (none: the base header alone).
#[allow(clippy::too_many_arguments)]
fn cutter<'a>(
    ip: IpMetadata,
    options: Option<&EncodedIpv4Options>,
    segments: &'a [Ipv6Addr],
    protocol: u8,
    dscp: u8,
    hop_limit: u8,
    identification: u32,
    data_len: usize,
) -> Result<Cutter<'a>, Error> {
    Ok(if ip.source.is_ipv4() {
        let header = ntcp_ip::Header {
            ip,
            hop_limit,
            dscp,
            ecn: 0,
            ipv4_options: Default::default(),
        };
        let identification = identification as u16;
        Cutter::V4(match options {
            Some(options) => ntcp_ip::Fragmenter::with_options(
                header,
                options,
                protocol,
                identification,
                data_len,
            )?,
            None => ntcp_ip::Fragmenter::new(header, protocol, identification, data_len, 0)?,
        })
    } else if options.is_some() {
        return Err(Error::Unsupported);
    } else {
        Cutter::V6(ntcp_ip6::Fragmenter::routed(
            ntcp_ip6::Header {
                ip,
                hop_limit,
                dscp,
                ecn: 0,
            },
            segments,
            protocol,
            identification,
            data_len,
        )?)
    })
}

/// One planned fragment as recorded in the ledger.
#[derive(Clone, Copy)]
pub(crate) struct Piece {
    pub offset: usize,
    pub more: bool,
    pub header_len: usize,
    pub packet_len: usize,
}

impl Host {
    // Count the fragments of `data_len` octets cut to `size`, without
    // allocating; Capacity beyond `max_fragments`.
    fn plan_pieces(
        &self,
        cutter: &Cutter,
        data_len: usize,
        size: usize,
        mut each: impl FnMut(usize, Piece),
    ) -> Result<usize, Error> {
        let mut offset = 0;
        let mut index = 0;
        while offset < data_len {
            let len = cutter.len(offset, size)?;
            if index == self.datagram_limits.max_fragments {
                return Err(Error::Capacity);
            }
            let header_len = cutter.header(offset);
            each(
                index,
                Piece {
                    offset,
                    more: offset + len < data_len,
                    header_len,
                    packet_len: header_len + len,
                },
            );
            offset += len;
            index += 1;
        }
        Ok(index)
    }

    /// The number of fragments a datagram of `data_len` transport octets
    /// between `ip`'s addresses with `options`, or over an SR route of
    /// `segments`, cut to `size`, needs; Capacity beyond `max_fragments`.
    pub(crate) fn fragment_count(
        &self,
        ip: IpMetadata,
        options: Option<&EncodedIpv4Options>,
        segments: &[Ipv6Addr],
        data_len: usize,
        size: usize,
    ) -> Result<usize, Error> {
        let cutter = cutter(ip, options, segments, 17, 0, 1, 0, data_len)?;
        self.plan_pieces(&cutter, data_len, size, |_, _| ())
    }

    // The complete header length of `plan`'s datagram (options included)
    // and the segment list its route generation encodes.
    fn plan_header(&self, plan: &Plan) -> Result<(usize, &[Ipv6Addr]), Error> {
        let header = self.header_plan(plan.snapshot.key())?;
        let options = plan.options.map_or(0, |o| o.as_bytes().len());
        Ok((header.len + options, header.segments))
    }

    // `plan`'s fragmenter under its route generation's header plan.
    fn plan_cutter(&self, plan: &Plan, identification: u32) -> Result<Cutter<'_>, Error> {
        cutter(
            plan.ip,
            plan.options.as_ref(),
            self.plan_header(plan)?.1,
            plan.protocol,
            plan.dscp,
            plan.hop_limit,
            identification,
            plan.data_len,
        )
    }

    // The path authority each fragment is revalidated against: the same
    // live path incarnation, link and next hop the transaction started on.
    fn still_valid(&self, plan: &Plan) -> bool {
        let Some(client) = plan.client else {
            return true;
        };
        self.paths.snapshot(client).is_ok_and(|s| {
            s.status() == PathStatus::Valid
                && s.path() == plan.snapshot.path()
                && s.key() == plan.snapshot.key()
        })
    }

    /// Send `plan`'s datagram. Unfragmented: the complete packet is already
    /// encoded in `packet[..len]` by the caller and `evidence(0)` describes
    /// it. Fragmented: the transport bytes (checksummed over the complete
    /// datagram) are at `packet[size..size + data_len]`; each fragment is
    /// built in `packet[..size]`. `evidence` yields each piece's record, or
    /// None for messages the ledger does not track (Host ICMP output).
    //= https://www.rfc-editor.org/rfc/rfc4821#section-4
    //= reason=Host fragmentation mimics IPv6 and happens only in the host: Host UDP datagrams in Fragment mode and the Host's Echo Replies (a reply to an IPv4 source-routed Echo Request takes the reversed, policy-authorized return route, registers no adjunct demand and is never sized by an adjunct-confirmed bound, while IPv6 Echo Replies use only owner-configured routes) leave through one datagram emitter (Host::transmit, crates/stacks/ntcp-host/src/emitter.rs) that cuts an IPv4 datagram larger than the connectionless effective size with ntcp_ip::Fragmenter, which sets DF on every fragment, just as it cuts IPv6 (every fragment repeats the unfragmentable part, the base header and on an owner-configured Segment Routing route its Segment Routing Header, before the Fragment header, and the first fragment holds the complete upper-layer header); the atomic IPv4 encoder (encode_present) sets DF on every unfragmented packet, and TCP never enters source fragmentation. Host tests assert DF on every IPv4 fragment and packet of a fragmented send, the tun_echo IPv4 path asserts DF on TCP packets and PLPMTUD probes, and the integration/rfc_host fragment, fragment-ptb and adjunct-silence cases check DF on every captured IPv4 fragment and probe. User disposition of the SHOULD (recorded): an application that sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT on a native socket gets its ordinary IPv4 TCP output without DF, an application-requested exception; every such packet carries an Identification leased from the Host allocator for its (source, destination, TCP) tuple, the RFC 6864 ceiling holds the packet instead of reusing a value, its PLPMTUD probes keep DF and TCP is never source-fragmented (ntcp-socket tests managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling and dont_packets_are_identified_from_startup). User disposition for administratively flagged routes (recorded decision B): on an IPv4 route or path whose owner disabled discovery (RFC 1191 section 6.6, which RFC 4821 does not update) every packet of TCP, Host::udp_send, Host::udp_send_datagram and Echo replies, Host source fragments included, leaves DF clear with a leased Identification and a recomputed header checksum under the RFC 1122 section 3.3.3 sending limit, and no probe is sent there; fragments on enabled routes keep DF (ntcp-host tests disabled_ipv4_route_clears_df_on_udp_datagrams_and_source_fragments, disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments and disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams).
    //# All hosts SHOULD use IPv4 fragmentation in a mode that mimics IPv6 functionality. All fragmentation SHOULD be done on the host, and all IPv4 packets, including fragments, SHOULD have the DF bit set such that they will not be fragmented (again) in the network. See Section 8.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        plan: Plan,
        packet: &mut [u8],
        mut evidence: impl FnMut(Piece, &[u8]) -> Option<Evidence>,
        owner: Option<crate::Owner>,
        endpoint: Option<&ntcp::Endpoint>,
        mut submit: impl FnMut(UdpEgress, &[u8]) -> BackendOutcome,
    ) -> Result<DatagramReport, DatagramError> {
        let header = self.plan_header(&plan)?.0;
        let egress = UdpEgress {
            link: plan.snapshot.key().link(),
            next_hop: plan.snapshot.key().next_hop(),
            link_layer: None,
        };
        let Some(size) = plan.fragment_size else {
            let len = header + plan.data_len;
            if packet.len() < len {
                return Err(Error::Capacity.into());
            }
            let piece = Piece {
                offset: 0,
                more: false,
                header_len: header,
                packet_len: len,
            };
            let ticket = match (owner, evidence(piece, &packet[..len])) {
                (Some(owner), Some(e)) => Some(self.reserve_fragments(endpoint, owner, &[e])?),
                _ => None,
            };
            let mut identification = None;
            if plan.snapshot.clears_dont_fragment() {
                // The whole packet leaves without DF, a non-atomic datagram
                // that needs its own leased Identification.
                match self.lease_df_clear(now, &mut packet[..len]) {
                    Ok(id) => identification = Some(u32::from(id)),
                    Err(backpressure) => {
                        if let Some(ticket) = ticket {
                            self.ledger.cancel(ticket);
                        }
                        return Err(DatagramError::Backpressure(backpressure));
                    }
                }
            }
            self.now = self.now.max(now);
            let outcome = submit(egress, &packet[..len]);
            let mut report = self.finish_single(now, ticket, outcome, len)?;
            report.identification = identification;
            return Ok(report);
        };
        if size > packet.len() {
            return Err(Error::Capacity.into());
        }
        // Everything fallible precedes the identifier lease: the plan must
        // fit the fragment limit and the buffer before an identifier is spent.
        let count =
            self.plan_pieces(&self.plan_cutter(&plan, 0)?, plan.data_len, size, |_, _| ())?;
        if packet.len() < size + plan.data_len {
            return Err(Error::Capacity.into());
        }
        let identification = self
            .identifiers
            .issue(
                now,
                plan.ip.source,
                plan.ip.destination,
                plan.protocol,
                self.entropy.as_mut(),
            )
            .map_err(DatagramError::Backpressure)?;
        let (scratch, data) = packet.split_at_mut(size);
        let data = &data[..plan.data_len];
        // One independently sealable ticket per fragment, all reserved
        // before the first submission.
        let mut tickets = alloc::vec::Vec::new();
        if let Some(owner) = owner {
            let mut records = alloc::vec::Vec::new();
            records
                .try_reserve_exact(count)
                .map_err(|_| Error::Allocation)?;
            tickets
                .try_reserve_exact(count)
                .map_err(|_| Error::Allocation)?;
            let mut failed = false;
            let cutter = self.plan_cutter(&plan, identification)?;
            self.plan_pieces(&cutter, plan.data_len, size, |_, piece| {
                let len = piece.packet_len - piece.header_len;
                match evidence(piece, &data[piece.offset..piece.offset + len]) {
                    Some(e) => records.push(e),
                    None => failed = true,
                }
            })?;
            if failed {
                return Err(Error::Obsolete.into());
            }
            for e in &records {
                match self.reserve_fragments(endpoint, owner, core::slice::from_ref(e)) {
                    Ok(ticket) => tickets.push(ticket),
                    Err(error) => {
                        for ticket in tickets {
                            self.ledger.cancel(ticket);
                        }
                        return Err(error.into());
                    }
                }
            }
        }
        self.now = self.now.max(now);
        let mut report = DatagramReport {
            ip_len: header + plan.data_len,
            fragments: count,
            submitted: 0,
            possibly_submitted: 0,
            terminal: None,
            identification: Some(identification),
            probe: None,
        };
        let mut offset = 0;
        let mut index = 0;
        while offset < plan.data_len {
            let (len, outcome) = if index != 0 && !self.still_valid(&plan) {
                // Authority changed: nothing more is sent under it.
                (0, BackendOutcome::NotSubmitted)
            } else {
                // Cut under the header plan of the route generation the
                // transaction holds.
                let cutter = self
                    .plan_cutter(&plan, identification)
                    .map_err(DatagramError::Host)?;
                let len = cutter.len(offset, size).map_err(DatagramError::Host)?;
                let packet_len = cutter
                    .encode(scratch, offset, &data[offset..offset + len])
                    .map_err(DatagramError::Host)?;
                if plan.snapshot.clears_dont_fragment() {
                    // RFC 1191 section 6.6: DF clear on every packet of a
                    // discovery-disabled route, source fragments included;
                    // MF, the offset and the datagram's Identification stay.
                    clear_dont_fragment(&mut scratch[..packet_len]);
                }
                (len, submit(egress, &scratch[..packet_len]))
            };
            let ticket = tickets.get(index).copied();
            match outcome {
                BackendOutcome::Submitted => {
                    if let Some(ticket) = ticket {
                        self.ledger.seal(ticket, now, false);
                    }
                    report.submitted += 1;
                }
                BackendOutcome::Unknown => {
                    if let Some(ticket) = ticket {
                        self.ledger.seal(ticket, now, true);
                    }
                    report.possibly_submitted += 1;
                    report.terminal = Some(outcome);
                }
                _ => report.terminal = Some(outcome),
            }
            index += 1;
            offset += len;
            if report.terminal.is_some() {
                break;
            }
        }
        let attempted_ok = report.submitted + report.possibly_submitted;
        for &ticket in tickets.iter().skip(attempted_ok) {
            self.ledger.cancel(ticket);
        }
        if attempted_ok != 0 && !plan.source_routed() {
            // Fragmentation demand for the Echo adjunct on this path; a
            // source-routed datagram did not take the path it probes.
            self.adjunct_demand(
                now,
                plan.snapshot,
                plan.ip,
                plan.dscp,
                report.ip_len as u32,
            );
        }
        if attempted_ok == 0 {
            // Nothing reached the link; the identifier stays leased (it may
            // not be reissued early) and a retry uses a new one.
            return Err(DatagramError::NotSubmitted(
                report.terminal.unwrap_or(BackendOutcome::NotSubmitted),
            ));
        }
        Ok(report)
    }

    /// Clear DF on one atomically encoded IPv4 packet (DF set,
    /// Identification 0) and give it an Identification leased for its
    /// (source, final destination, protocol) tuple, recomputing the header
    /// checksum. The final destination is the one that reassembles it: the
    /// last address of a source route in its options, otherwise the header
    /// destination (`ntcp_ip::final_destination`), the same tuple a
    /// fragmented datagram to it leases from. A leased 0 is passed over: every atomic datagram of this
    /// stack carries 0, and a middlebox that clears their DF would make
    /// them collide with this one (it stays leased and is never sent).
    /// Backpressure (the RFC 6864 ceiling) leaves the packet unchanged: the
    /// caller holds it, never reusing a value.
    pub fn lease_df_clear(
        &mut self,
        now: Instant,
        ip: &mut [u8],
    ) -> Result<u16, IdentifierBackpressure> {
        let Ok(destination) = ntcp_ip::final_destination(ip) else {
            return Err(IdentifierBackpressure::Unavailable);
        };
        let source = IpAddr::V4(core::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
        let destination = IpAddr::V4(destination);
        let mut identification = 0;
        for _ in 0..2 {
            identification = self.lease_identification(now, source, destination, ip[9])? as u16;
            if identification != 0 {
                break;
            }
        }
        if identification == 0 {
            return Err(IdentifierBackpressure::Exhausted {
                retry_at: now.saturating_add(1),
            });
        }
        ip[4..6].copy_from_slice(&identification.to_be_bytes());
        clear_dont_fragment(ip);
        Ok(identification)
    }

    /// The inverse of `lease_df_clear` for a held packet whose final bytes
    /// must no longer leave DF clear: an embedding rewrote it for a
    /// DF-clear submission that did not happen (the backend would block),
    /// and before its retry the owner re-enabled discovery on its path
    /// while its connection does not ask for IP_PMTUDISC_DONT. When the
    /// packet is a whole IPv4 datagram (MF clear, offset 0) with DF clear,
    /// this restores the atomic header the encoder produced (DF set,
    /// Identification 0, header checksum recomputed) and returns true; the
    /// unused leased Identification stays leased and is never reissued
    /// early. Its submission then proves size like any DF-set packet.
    /// Anything else (IPv6, DF already set, a fragment, a short buffer) is
    /// left unchanged and returns false.
    pub fn restore_atomic_header(ip: &mut [u8]) -> bool {
        if ip.len() < ntcp_ip::IPV4_HEADER
            || ip[0] >> 4 != 4
            || ip[0] & 0x0f < 5
            || usize::from(ip[0] & 0x0f) * 4 > ip.len()
            || ip[6] & 0x40 != 0
            || ip[6] & 0x3f != 0
            || ip[7] != 0
        {
            return false;
        }
        let header = usize::from(ip[0] & 0x0f) * 4;
        ip[4..6].fill(0);
        ip[6] |= 0x40;
        ip[10..12].fill(0);
        let checksum = ntcp_ip_common::checksum(&ip[..header]);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        true
    }

    fn finish_single(
        &mut self,
        now: Instant,
        ticket: Option<u64>,
        outcome: BackendOutcome,
        len: usize,
    ) -> Result<DatagramReport, DatagramError> {
        let mut report = DatagramReport {
            ip_len: len,
            fragments: 1,
            submitted: 0,
            possibly_submitted: 0,
            terminal: None,
            identification: None,
            probe: None,
        };
        match outcome {
            BackendOutcome::Submitted => {
                if let Some(ticket) = ticket {
                    self.ledger.seal(ticket, now, false);
                }
                report.submitted = 1;
            }
            BackendOutcome::Unknown => {
                if let Some(ticket) = ticket {
                    self.ledger.seal(ticket, now, true);
                }
                report.possibly_submitted = 1;
                report.terminal = Some(outcome);
            }
            outcome => {
                if let Some(ticket) = ticket {
                    self.ledger.cancel(ticket);
                }
                return Err(DatagramError::NotSubmitted(outcome));
            }
        }
        Ok(report)
    }

    // One ledger ticket for `evidence`, reclaiming dead generations once
    // before backpressuring.
    fn reserve_fragments(
        &mut self,
        endpoint: Option<&ntcp::Endpoint>,
        owner: crate::Owner,
        evidence: &[Evidence],
    ) -> Result<u64, Error> {
        let reserve = |host: &mut Self| {
            let index = host.ledger.admit(owner)?;
            host.ledger.reserve_group(index, evidence)
        };
        match (reserve(self), endpoint) {
            (Err(Error::Capacity), Some(endpoint)) => {
                self.maintain_ledger(endpoint);
                reserve(self)
            }
            (result, _) => result,
        }
    }
}

// Clear DF on one encoded IPv4 header, keeping MF, the fragment offset and
// the Identification, and recompute the header checksum.
pub(crate) fn clear_dont_fragment(ip: &mut [u8]) {
    let header = usize::from(ip[0] & 0x0f) * 4;
    ip[6] &= !0x40;
    ip[10..12].fill(0);
    let checksum = ntcp_ip_common::checksum(&ip[..header]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
}
