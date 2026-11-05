#![no_std]
use core::net::IpAddr;
use ntcp::{IpMetadata, Ipv4Options};
pub use ntcp_ip_common::{Error, PROTOCOL_TCP, PROTOCOL_UDP, checksum};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackKind {
    DestinationUnreachable,
    TimeExceeded,
    ParameterProblem,
    PacketTooBig,
    SourceQuench,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpQuote {
    pub ip: IpMetadata,
    pub ip_packet_len: u32,
    pub ip_header_len: u16,
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
}
/// Transport fields a quote carries. Only TCP and UDP have selectors; any
/// other protocol is kept structurally, without transport semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotedTransport {
    Tcp {
        source_port: u16,
        destination_port: u16,
        sequence: u32,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
        // Raw field: zero is an IPv4 datagram sent without a checksum. The
        // quote may be truncated, so the checksum itself cannot be verified.
        checksum: u16,
    },
    Other,
}

/// Protocol-generic quote of the offending datagram. `ip.destination` is the
/// final destination, recovered from an unfinished IPv4 source route or from
/// the type-specific fields of an IPv6 Routing header
/// (`ntcp_ip6::Chain::final_destination`). `ip_header_len` is the complete
/// header length, IPv6 extension headers included. For a quoted fragment,
/// `ip_packet_len` and `ip_header_len` are that fragment's physical lengths
/// (an IPv6 later fragment's header ends with its Fragment header) and
/// `protocol` is the fragment's own selector, which is opaque for a later
/// IPv6 fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quote {
    pub ip: IpMetadata,
    pub ip_packet_len: u32,
    pub ip_header_len: u16,
    pub protocol: u8,
    pub transport: QuotedTransport,
    /// Present only when the quoted packet is a fragment.
    pub fragment: Option<QuotedFragment>,
}

/// Identification of a quoted fragment. IPv4's is reported for structure
/// only: RFC 6864 section 4.1 limits it to fragmentation and reassembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentIdentification {
    Ipv4 {
        identification: u16,
        dont_fragment: bool,
    },
    Ipv6 {
        identification: u32,
    },
}

/// Position, flags and leading data of a quoted fragment. Transport fields
/// are parsed only from the fragment at offset zero; a later fragment's data
/// carries no transport header, so `transport` is then `Other` and only these
/// octets describe its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotedFragment {
    pub identification: FragmentIdentification,
    /// Data offset in octets.
    pub offset: u16,
    pub more_fragments: bool,
    /// The first `data_len` fragment data octets present in the quote, at
    /// most eight: the amount every IPv4 error quotes (RFC 1122 3.2.2).
    pub data: [u8; 8],
    pub data_len: u8,
}

impl QuotedFragment {
    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.data_len)]
    }
}

impl Quote {
    /// Exact projection used by TCP-only consumers. TCP never sends
    /// fragments, so a quoted fragment has no TCP projection.
    pub fn tcp(self) -> Option<TcpQuote> {
        if self.fragment.is_some() {
            return None;
        }
        let QuotedTransport::Tcp {
            source_port,
            destination_port,
            sequence,
        } = self.transport
        else {
            return None;
        };
        Some(TcpQuote {
            ip: self.ip,
            ip_packet_len: self.ip_packet_len,
            ip_header_len: self.ip_header_len,
            source_port,
            destination_port,
            sequence,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback<Q = TcpQuote> {
    pub outer: IpMetadata,
    /// Every option of the outer IPv4 header except NOP and EOL, as the
    /// receiver processed it (`decode_error`); empty for IPv6. Options of
    /// the quoted header are historical and never appear here.
    pub outer_options: Ipv4Options,
    pub kind: FeedbackKind,
    pub code: u8,
    // Untrusted candidate only; caller must correlate tuple/sequence with a
    // live transmission and apply path policy. This is not autonomous PMTUD.
    pub candidate_mtu: Option<u32>,
    pub quoted: Q,
}

impl Feedback<Quote> {
    /// Exact TCP view: present only when the quote is TCP.
    pub fn tcp(self) -> Option<Feedback> {
        Some(Feedback {
            outer: self.outer,
            outer_options: self.outer_options,
            kind: self.kind,
            code: self.code,
            candidate_mtu: self.candidate_mtu,
            quoted: self.quoted.tcp()?,
        })
    }
}

impl<Q: Copy> Feedback<Q> {
    // RFC9293 3.9.2.2: IPv6 unreachable0/3 and time/parameter errors
    // are soft. Other recognized policy/reachability failures remain soft
    // unless the protocol explicitly identifies a hard unreachable2/4.
    pub fn ipv6_network_error(self) -> Option<ntcp::NetworkError> {
        if !self.outer.source.is_ipv6() {
            return None;
        }
        Some(match self.kind {
            FeedbackKind::DestinationUnreachable => match self.code {
                2 | 4 => ntcp::NetworkError::HardUnreachable,
                0 | 1 | 3 | 5..=7 => ntcp::NetworkError::SoftUnreachable,
                _ => return None,
            },
            FeedbackKind::TimeExceeded => ntcp::NetworkError::TimeExceeded,
            FeedbackKind::ParameterProblem => ntcp::NetworkError::ParameterProblem,
            _ => return None,
        })
    }
    // Classify validated IPv4 errors, not their connection-specific effect.
    // PTB remains on the PMTU path. IPv6 consumers need their own mapping.
    // Unlisted IPv4 unreachable codes stay nonterminal rather than becoming
    // fatal merely because the decoder recognizes their wire format.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2
    //= reason=IPv4 codes0/1/5, TimeExceeded and ParameterProblem classify as soft; only codes2/3 classify as HardUnreachable. Code4 is separately PacketTooBig.
    //# For IPv4 ICMP, these include: Destination Unreachable -- codes 0,
    //# 1, 5; Time Exceeded -- codes 0, 1; and Parameter Problem.
    pub fn ipv4_network_error(self) -> Option<ntcp::NetworkError> {
        if !self.outer.source.is_ipv4() {
            return None;
        }
        Some(match self.kind {
            FeedbackKind::DestinationUnreachable => match self.code {
                2 | 3 => ntcp::NetworkError::HardUnreachable,
                0 | 1 | 5..=15 => ntcp::NetworkError::SoftUnreachable,
                _ => return None,
            },
            FeedbackKind::TimeExceeded => ntcp::NetworkError::TimeExceeded,
            FeedbackKind::ParameterProblem => ntcp::NetworkError::ParameterProblem,
            FeedbackKind::SourceQuench => ntcp::NetworkError::SourceQuench,
            FeedbackKind::PacketTooBig => return None,
        })
    }
}

// Decode a complete outer IP frame; the inner IP frame may be a partial quote,
// but must contain its entire header and at least TCP's ports and sequence.
//= https://www.rfc-editor.org/rfc/rfc1191#section-4
//= reason=Decoded quote length is complete original IP length, not quoted byte count or Ethernet frame size; no router-generation claim.
//# The size includes the IP header and IP data, and does not include any lower-level
//# headers.
//= https://www.rfc-editor.org/rfc/rfc5927#section-4.3
//= reason=Informational rationale: outer source may be a router, not the peer. Runtime fixture sends PTB from10.73.0.1 for peer10.73.0.3; quoted tuple/live sequence and checksums still gate acceptance.
//# The source address of ICMP error messages does not need to be spoofed to perform the
//# attacks described in this document, as the ICMP error messages might legitimately come
//# from an intermediate system.
pub fn decode_icmp(bytes: &[u8]) -> Result<Feedback, Error> {
    let feedback = decode_icmp_quote(bytes)?;
    if feedback.quoted.fragment.is_some() {
        return Err(Error::FragmentationUnsupported);
    }
    feedback.tcp().ok_or(Error::Quote)
}

/// Decode an ICMP error quoting any protocol. Validation is identical to
/// `decode_icmp` except that the quoted protocol is not required to be TCP
/// and the quoted packet may be a fragment.
///
/// A stateless compatibility wrapper over `decode_error`: the outer header
/// is parsed from `bytes` with source routes refused, and its options are
/// reported as received, without any destination processing.
pub fn decode_icmp_quote(bytes: &[u8]) -> Result<Feedback<Quote>, Error> {
    let (outer, outer_options, protocol, icmp) = parse_outer(bytes)?;
    if protocol != if outer.source.is_ipv6() { 58 } else { 1 } {
        return Err(Error::ProtocolUnsupported);
    }
    decode_error(outer, outer_options, icmp)
}

/// Decode an ICMP error message (the complete IP payload of an ICMP or
/// ICMPv6 datagram) whose outer header the receiver has already validated
/// and processed: `outer` and `outer_options` are that result, carried into
/// the feedback unchanged and never reparsed here. The quote is validated as
/// historical data: its header, options included, is read but never
/// modified or reported as outer metadata.
pub fn decode_error(
    outer: IpMetadata,
    outer_options: Ipv4Options,
    icmp: &[u8],
) -> Result<Feedback<Quote>, Error> {
    if icmp.len() < 8 {
        return Err(Error::Truncated);
    }
    let ipv6 = outer.source.is_ipv6();
    if ipv6 && !outer_options.is_empty() {
        return Err(Error::Options);
    }
    if if ipv6 {
        icmpv6_checksum(outer, icmp)?
    } else {
        checksum(icmp)
    } != 0
    {
        return Err(Error::Checksum);
    }
    let (kind, candidate_mtu) = if ipv6 {
        icmpv6_feedback(icmp)?
    } else {
        icmpv4_feedback(icmp)?
    };
    let quoted = quote(&icmp[8..], ipv6)?;
    // Error must be addressed back to the sender of the quoted transmission.
    if outer.destination != quoted.ip.source {
        return Err(Error::Quote);
    }
    Ok(Feedback {
        outer,
        outer_options,
        kind,
        code: icmp[1],
        candidate_mtu,
        quoted,
    })
}
// Every quote carries the complete inner header (checksummed IPv4 with
// recovered source-route destination, or an IPv6 header chain through the
// upper-layer header, or through the Fragment header of a later fragment,
// with a resolved final destination) and no more than the declared original
// packet. A complete datagram or the fragment at offset zero additionally
// needs TCP's or UDP's first eight transport bytes: ports plus sequence or
// length/checksum. A later fragment's data holds no transport header and is
// never parsed. Missing bytes decline attribution (RFC 4443 section 2.4(d));
// no offset is guessed.
fn quote(b: &[u8], ipv6: bool) -> Result<Quote, Error> {
    let (ip, header, total, protocol, fragment) = quote_header(b, ipv6)?;
    if b.len() > total {
        return Err(Error::Quote);
    }
    // Quoted headers lie within the quote, so a header length above u16
    // only arises from an oversized caller slice.
    let header_len = u16::try_from(header).map_err(|_| Error::Length)?;
    let fragment = fragment.map(|(identification, offset, more_fragments, data)| {
        let present = &b[data..];
        let mut data = [0; 8];
        let data_len = present.len().min(8);
        data[..data_len].copy_from_slice(&present[..data_len]);
        QuotedFragment {
            identification,
            offset,
            more_fragments,
            data,
            data_len: data_len as u8,
        }
    });
    let transport = match protocol {
        _ if fragment.is_some_and(|f| f.offset != 0) => QuotedTransport::Other,
        PROTOCOL_TCP => {
            if total < header + 20 || b.len() < header + 8 {
                return Err(Error::Quote);
            }
            let tcp = &b[header..];
            let source_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            if source_port == 0 || destination_port == 0 {
                return Err(Error::Quote);
            }
            QuotedTransport::Tcp {
                source_port,
                destination_port,
                sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            }
        }
        PROTOCOL_UDP => {
            if b.len() < header + 8 {
                return Err(Error::Quote);
            }
            let udp = &b[header..];
            let length = u16::from_be_bytes([udp[4], udp[5]]);
            // Same length rule as received datagrams: the header must fit
            // and the datagram cannot exceed the original IP payload. A first
            // fragment's datagram continues in later fragments, so only its
            // header has to be present.
            let continued = fragment.is_some_and(|f| f.more_fragments);
            if usize::from(length) < 8 || (!continued && header + usize::from(length) > total) {
                return Err(Error::Quote);
            }
            let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
            // Source port zero is RFC 768's unused value; no datagram is
            // sent to destination port zero.
            if destination_port == 0 {
                return Err(Error::Quote);
            }
            QuotedTransport::Udp {
                source_port: u16::from_be_bytes([udp[0], udp[1]]),
                destination_port,
                length,
                checksum: u16::from_be_bytes([udp[6], udp[7]]),
            }
        }
        _ => QuotedTransport::Other,
    };
    Ok(Quote {
        ip,
        ip_packet_len: u32::try_from(total).map_err(|_| Error::Length)?,
        ip_header_len: header_len,
        protocol,
        transport,
        fragment,
    })
}

// Checked quoted header with its fragment identity, offset, MF and data
// offset, present only for an actual fragment: an IPv4 datagram with MF or an
// offset, or any IPv6 packet with a Fragment header (an atomic fragment
// included).
type QuotedHeader = (
    IpMetadata,
    usize,
    usize,
    u8,
    Option<(FragmentIdentification, u16, bool, usize)>,
);

fn quote_header(b: &[u8], ipv6: bool) -> Result<QuotedHeader, Error> {
    let _ = b;
    match ipv6 {
        #[cfg(feature = "ipv6")]
        true => {
            let (ip, chain) = ntcp_ip6::quote_fragment_header(b)?;
            Ok((
                ip,
                chain.header_len(),
                chain.declared_len(),
                chain.protocol(),
                chain.fragment().map(|f| {
                    (
                        FragmentIdentification::Ipv6 {
                            identification: f.identification,
                        },
                        f.fragment_offset,
                        f.more_fragments,
                        f.data(),
                    )
                }),
            ))
        }
        #[cfg(feature = "ipv4")]
        false => {
            let (ip, header, total, protocol, f) = ntcp_ip::quote_fragment_header(b)?;
            Ok((
                ip,
                header,
                total,
                protocol,
                (!f.is_complete()).then_some((
                    FragmentIdentification::Ipv4 {
                        identification: f.identification,
                        dont_fragment: f.dont_fragment,
                    },
                    f.offset,
                    f.more_fragments,
                    header,
                )),
            ))
        }
        #[allow(unreachable_patterns)]
        _ => Err(Error::Version),
    }
}

fn parse_outer(bytes: &[u8]) -> Result<(IpMetadata, Ipv4Options, u8, &[u8]), Error> {
    match bytes.first().ok_or(Error::Truncated)? >> 4 {
        #[cfg(feature = "ipv4")]
        4 => {
            let p = ntcp_ip::parse(bytes, false)?;
            Ok((p.ip, p.ipv4_options, p.protocol, p.payload))
        }
        #[cfg(feature = "ipv6")]
        6 => {
            let p = ntcp_ip6::parse(bytes)?;
            Ok((p.ip, Ipv4Options::default(), p.protocol, p.payload))
        }
        _ => Err(Error::Version),
    }
}

fn icmpv4_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
    Ok(match (icmp[0], icmp[1]) {
        (3, 4) => (
            FeedbackKind::PacketTooBig,
            match u16::from_be_bytes([icmp[6], icmp[7]]) {
                0 => None,
                mtu => Some(u32::from(mtu)),
            },
        ),
        (3, 0..=15) => (FeedbackKind::DestinationUnreachable, None),
        (4, 0) => (FeedbackKind::SourceQuench, None),
        (11, 0..=1) => (FeedbackKind::TimeExceeded, None),
        (12, 0..=2) => (FeedbackKind::ParameterProblem, None),
        _ => return Err(Error::ProtocolUnsupported),
    })
}

fn icmpv6_feedback(icmp: &[u8]) -> Result<(FeedbackKind, Option<u32>), Error> {
    Ok(match (icmp[0], icmp[1]) {
        (1, 0..=7) => (FeedbackKind::DestinationUnreachable, None),
        (3, 0..=1) => (FeedbackKind::TimeExceeded, None),
        // Code 3 is RFC 7112's incomplete header chain in a first fragment.
        (4, 0..=3) => (FeedbackKind::ParameterProblem, None),
        (2, 0) => (
            FeedbackKind::PacketTooBig,
            Some(u32::from_be_bytes(
                icmp[4..8].try_into().map_err(|_| Error::Truncated)?,
            )),
        ),
        _ => return Err(Error::ProtocolUnsupported),
    })
}

pub fn icmpv6_checksum(ip: IpMetadata, bytes: &[u8]) -> Result<u16, Error> {
    let (IpAddr::V6(_), IpAddr::V6(_)) = (ip.source, ip.destination) else {
        return Err(Error::Version);
    };
    ntcp_ip_common::pseudo_header_checksum(ip.source, ip.destination, 58, bytes)
}

// RFC 792 checksums the ICMP message alone; RFC 4443 section 2.3 prepends the
// IPv6 pseudo-header. Both cover the complete (possibly reassembled) message.
fn message_checksum(ip: IpMetadata, message: &[u8]) -> Result<u16, Error> {
    match (ip.source, ip.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(checksum(message)),
        (IpAddr::V6(_), IpAddr::V6(_)) => icmpv6_checksum(ip, message),
        _ => Err(Error::Version),
    }
}

/// Echo Request or Echo Reply (RFC 792; RFC 4443 sections 4.1 and 4.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchoKind {
    Request,
    Reply,
}

impl EchoKind {
    fn message_type(self, ipv6: bool) -> u8 {
        match (self, ipv6) {
            (Self::Request, false) => 8,
            (Self::Reply, false) => 0,
            (Self::Request, true) => 128,
            (Self::Reply, true) => 129,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Echo<'a> {
    pub kind: EchoKind,
    pub identifier: u16,
    pub sequence: u16,
    pub data: &'a [u8],
}

/// Decode a complete ICMP message, received from `ip.source` for
/// `ip.destination`, as an Echo Request or Reply. Unlike errors, an Echo is
/// decoded from the IP payload so that a reassembled message is handled like
/// an unfragmented one. Both families define only code 0.
pub fn decode_echo(ip: IpMetadata, message: &[u8]) -> Result<Echo<'_>, Error> {
    if message.len() < 8 {
        return Err(Error::Truncated);
    }
    if message_checksum(ip, message)? != 0 {
        return Err(Error::Checksum);
    }
    let ipv6 = ip.source.is_ipv6();
    let kind = [EchoKind::Request, EchoKind::Reply]
        .into_iter()
        .find(|kind| kind.message_type(ipv6) == message[0])
        .ok_or(Error::ProtocolUnsupported)?;
    if message[1] != 0 {
        return Err(Error::Invalid);
    }
    Ok(Echo {
        kind,
        identifier: u16::from_be_bytes([message[4], message[5]]),
        sequence: u16::from_be_bytes([message[6], message[7]]),
        data: &message[8..],
    })
}

/// Encode an Echo message sent from `ip.source` to `ip.destination` whose
/// `data_len` data octets are resident at `message[8..]`; returns the message
/// length. The data is never modified, so a reply built over a request's data
/// echoes it exactly (RFC 1122 section 3.2.2.6, RFC 4443 section 4.2). The
/// message may later be fragmented: its checksum covers all of it.
pub fn encode_echo(
    ip: IpMetadata,
    kind: EchoKind,
    identifier: u16,
    sequence: u16,
    message: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    message_checksum(ip, &[])?;
    let len = data_len
        .checked_add(8)
        .filter(|len| *len <= usize::from(u16::MAX))
        .ok_or(Error::Length)?;
    let message = message.get_mut(..len).ok_or(Error::Length)?;
    message[0] = kind.message_type(ip.source.is_ipv6());
    message[1] = 0;
    message[2..4].fill(0);
    message[4..6].copy_from_slice(&identifier.to_be_bytes());
    message[6..8].copy_from_slice(&sequence.to_be_bytes());
    let sum = message_checksum(ip, message)?;
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}

/// ICMP errors a host originates about fragments it could not reassemble.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorMessage {
    /// Fragment reassembly time exceeded: ICMPv4 type 11 code 1 (RFC 792,
    /// RFC 1122 section 3.3.2) or ICMPv6 type 3 code 1 (RFC 4443 section
    /// 3.3, RFC 8200 section 4.5).
    ReassemblyTimeExceeded,
    /// ICMPv6 Parameter Problem (RFC 4443 section 3.4); code 3 is RFC 7112's
    /// incomplete header chain in a first fragment. `pointer` is the octet
    /// offset of the problem within the invoking packet.
    Ipv6ParameterProblem { code: u8, pointer: u32 },
}

/// An ICMPv6 error carries as much of the invoking packet as fits without
/// exceeding the IPv6 minimum MTU (RFC 4443 section 2.4(c)). An ICMPv4 error
/// carries the invoking header and at least 8 data octets (RFC 1122 section
/// 3.2.2); quoting up to a 576-octet datagram keeps it within the size every
/// IPv4 host must accept (RFC 1122 section 3.3.3), so no error ever needs
/// fragmentation.
const IPV4_ERROR_PACKET: usize = 576;
const IPV6_ERROR_PACKET: usize = 1280;

/// Largest ICMP error message (ICMP header plus quote) for each family,
/// reached with a minimal (option- or extension-free) originating header.
pub const ICMPV4_ERROR_LIMIT: usize = IPV4_ERROR_PACKET - 20;
pub const ICMPV6_ERROR_LIMIT: usize = IPV6_ERROR_PACKET - 40;

/// Encode an error sent from `ip.source` to `ip.destination` about
/// `invoking`, the received packet as it arrived (for reassembly errors, the
/// fragment at offset zero). `outer_header` is the complete length of the IP
/// header (options or extension headers included) that will carry the
/// message. The quote is truncated so that the packet fits the family limit,
/// and to `message`'s length, never split; an ICMPv4 quote that would lose
/// part of the invoking header or its first 8 data octets is refused.
/// Returns the message length.
pub fn encode_error(
    ip: IpMetadata,
    error: ErrorMessage,
    invoking: &[u8],
    outer_header: usize,
    message: &mut [u8],
) -> Result<usize, Error> {
    message_checksum(ip, &[])?;
    let ipv6 = ip.source.is_ipv6();
    let (kind, code, word) = match error {
        ErrorMessage::ReassemblyTimeExceeded => (if ipv6 { 3 } else { 11 }, 1, 0),
        ErrorMessage::Ipv6ParameterProblem { code, pointer } if ipv6 => {
            if code > 3 {
                return Err(Error::Invalid);
            }
            (4, code, pointer)
        }
        ErrorMessage::Ipv6ParameterProblem { .. } => return Err(Error::Version),
    };
    let (packet, minimum_header) = if ipv6 {
        (IPV6_ERROR_PACKET, 40)
    } else {
        (IPV4_ERROR_PACKET, 20)
    };
    if outer_header < minimum_header {
        return Err(Error::Invalid);
    }
    // The ICMP header itself must fit; only the quote is truncated.
    let limit = packet
        .checked_sub(outer_header)
        .filter(|room| *room >= 8)
        .ok_or(Error::Length)?
        .min(message.len());
    let quote = invoking.len().min(limit.saturating_sub(8));
    if !ipv6 {
        let required = invoking
            .first()
            .map_or(0, |b| usize::from(b & 15) * 4 + 8)
            .min(invoking.len());
        if quote < required {
            return Err(Error::Length);
        }
    }
    let len = 8 + quote;
    let message = message.get_mut(..len).ok_or(Error::Length)?;
    message[0] = kind;
    message[1] = code;
    message[2..4].fill(0);
    message[4..8].copy_from_slice(&word.to_be_bytes());
    message[8..].copy_from_slice(&invoking[..quote]);
    let sum = message_checksum(ip, message)?;
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}
