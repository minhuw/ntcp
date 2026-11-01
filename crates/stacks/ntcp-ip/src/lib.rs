#![no_std]
use core::net::{IpAddr, Ipv4Addr};
use ntcp::{IpMetadata, Ipv4Options, OutgoingIpv4Options};

pub use ntcp_ip_common::{Error, PROTOCOL_TCP, PROTOCOL_UDP, UDP_HEADER, checksum};
pub const IPV4_HEADER: usize = 20;

/// Per-datagram IPv4 send parameters shared by every transport protocol.
/// `ip.destination` is the final destination; a source route option places its
/// first hop in the header while transport checksums keep the final address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub ip: IpMetadata,
    pub hop_limit: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub ipv4_options: OutgoingIpv4Options,
}

impl From<ntcp::Transmit> for Header {
    fn from(t: ntcp::Transmit) -> Self {
        Self {
            ip: t.ip,
            hop_limit: t.hop_limit,
            dscp: t.dscp,
            ecn: t.ecn,
            ipv4_options: t.ipv4_options,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub ipv4_options: Ipv4Options,
    pub payload: &'a [u8],
}

const IP_HEADER: usize = IPV4_HEADER;

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//= reason=Endpoint parsing accepts every TTL, including zero and one, after structural and checksum validation; originating TTL zero remains invalid.
//# A host MUST NOT discard a datagram just because it was received with TTL
//# less than 2.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//# A host MUST support originating a source route and MUST be able to act as
//# the final destination of a source route.

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//# The IPv4 ID field MUST NOT be used for purposes other than fragmentation
//# and reassembly.

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//# All devices that examine IPv4 headers MUST ignore the IPv4 ID field of
//# atomic datagrams.
// Atomic endpoint codec: options are exposed in Packet; no ID is exposed. Only
// the structural fragment API below reports Identification, for reassembly.
//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//= reason=Opaque TLVs now survive bounded parsing and real TCP handoff in core, codec, example and native input. Native and disabled example profiles still discard known RR/Timestamp metadata, and the ICMP feedback decoder does not expose option metadata to its consumer; complete all-option TCP/ICMP handoff needs those capability/interface contracts.
//# All IP options (except NOP or END-OF-LIST) received in datagrams MUST be
//# passed to the transport layer (or to ICMP processing when the datagram is
//# an ICMP message). The IP and transport layer MUST each interpret those IP
//# options that they understand and silently ignore the others.
pub fn parse(bytes: &[u8], source_routes_enabled: bool) -> Result<Packet<'_>, Error> {
    let (header, total) = ipv4_bounds(bytes)?;
    if total != bytes.len() {
        return Err(Error::Length);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //# When received options are passed up to TCP from the IP layer, a TCP
    //# implementation MUST ignore options that it does not understand (MUST-
    //# 50).
    let options = Ipv4Options::parse(&bytes[20..header], source_routes_enabled)
        .map_err(|_| Error::Options)?;
    Ok(Packet {
        ip: IpMetadata {
            source: v4(&bytes[12..16]).into(),
            destination: v4(&bytes[16..20]).into(),
        },
        traffic_class: bytes[1],
        hop_limit: bytes[8],
        protocol: bytes[9],
        ipv4_options: options,
        payload: &bytes[header..],
    })
}
fn v4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}
// Validate a complete header; declared packet length may exceed the supplied
// bytes for ICMP quotes. Callers must check it before slicing packet data.
//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# The Version field indicates the format of the internet header. This
//# document describes version 4.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# Internet Header Length is the length of the internet header in 32 bit
//# words, and thus points to the beginning of the data. Note that the
//# minimum value for a correct header is 5.

//= https://www.rfc-editor.org/rfc/rfc791#section-1.4
//# The Header Checksum provides a verification that the information used in
//# processing internet datagram has been transmitted correctly. The data may
//# contain errors. If the header checksum fails, the internet datagram is
//# discarded at once by the entity which detects the error.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.1
//# A datagram whose version number is not 4 MUST be silently discarded.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.2
//# A host MUST verify the IP header checksum on every received datagram and
//# silently discard every datagram that has a bad checksum.
pub fn ipv4_bounds(b: &[u8]) -> Result<(usize, usize), Error> {
    let (header, total, _) = bounds(b, false)?;
    Ok((header, total))
}

/// `ipv4_bounds` for a packet that may be a fragment (MF or a nonzero
/// offset): the validated header and total lengths with its fragmentation
/// fields. Link framing uses it to delimit packets that reassembly accepts.
pub fn ipv4_fragment_bounds(b: &[u8]) -> Result<(usize, usize, Fragmentation), Error> {
    bounds(b, true)
}

// Shared header validation. The atomic entrypoints refuse every flag but DF
// exactly as before; the fragment API admits MF and offsets.
fn bounds(b: &[u8], fragments: bool) -> Result<(usize, usize, Fragmentation), Error> {
    if b.len() < 20 {
        return Err(Error::Truncated);
    }
    if b[0] >> 4 != 4 {
        return Err(Error::Version);
    }
    let header = usize::from(b[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if header < 20 || total < header {
        return Err(Error::Length);
    }
    if b.len() < header {
        return Err(Error::Truncated);
    }
    let flags = u16::from_be_bytes([b[6], b[7]]);
    if !fragments && flags & !0x4000 != 0 {
        return Err(Error::FragmentationUnsupported);
    }
    // RFC 791 section 3.1: flag bit 0 is reserved and must be zero.
    if flags & 0x8000 != 0 {
        return Err(Error::Invalid);
    }
    if checksum(&b[..header]) != 0 {
        return Err(Error::Checksum);
    }
    // Destination packets and ICMP quotes may both have an expired TTL.
    Ok((
        header,
        total,
        Fragmentation {
            identification: u16::from_be_bytes([b[4], b[5]]),
            dont_fragment: flags & 0x4000 != 0,
            more_fragments: flags & 0x2000 != 0,
            offset: (flags & 0x1fff) * 8,
        },
    ))
}

/// Fragmentation fields of one IPv4 header (RFC 791 section 3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragmentation {
    /// Meaningful only for non-atomic datagrams (RFC 6864 section 4.1).
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Position of this fragment's data in octets; the wire field counts
    /// 8-octet units, so this is always a multiple of 8.
    pub offset: u16,
}

impl Fragmentation {
    /// No offset and no further fragments: the packet is a complete datagram
    /// that bypasses reassembly whatever its DF bit.
    pub fn is_complete(&self) -> bool {
        !self.more_fragments && self.offset == 0
    }
}

/// One received IPv4 datagram or fragment. `header` is the fragment's actual
/// header including options: fragment zero's becomes the reassembled
/// datagram's header (RFC 791 section 3.2, RFC 815) and is kept for quoting.
/// `ipv4_options` are this fragment's options, structurally validated; later
/// fragments carry only the copied subset.
#[derive(Clone, Copy, Debug)]
pub struct FragmentPacket<'a> {
    pub ip: IpMetadata,
    pub traffic_class: u8,
    pub hop_limit: u8,
    pub protocol: u8,
    pub ipv4_options: Ipv4Options,
    pub fragmentation: Fragmentation,
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

/// Parse one complete IPv4 packet that may be a fragment. Validation equals
/// `parse` except that MF and a nonzero offset are reported, not refused;
/// alignment, overlap and reconstructed-size rules belong to reassembly,
/// which sees every fragment of the datagram.
pub fn parse_fragment(
    bytes: &[u8],
    source_routes_enabled: bool,
) -> Result<FragmentPacket<'_>, Error> {
    let (header, total, fragmentation) = bounds(bytes, true)?;
    if total != bytes.len() {
        return Err(Error::Length);
    }
    let options = Ipv4Options::parse(&bytes[20..header], source_routes_enabled)
        .map_err(|_| Error::Options)?;
    Ok(FragmentPacket {
        ip: IpMetadata {
            source: v4(&bytes[12..16]).into(),
            destination: v4(&bytes[16..20]).into(),
        },
        traffic_class: bytes[1],
        hop_limit: bytes[8],
        protocol: bytes[9],
        ipv4_options: options,
        fragmentation,
        header: &bytes[..header],
        payload: &bytes[header..],
    })
}

/// Source fragmentation of one complete IPv4 datagram (RFC 791 section 3.2).
/// Built once from the datagram's header and encoded options: the first
/// fragment carries every option, later fragments only the copied ones.
/// Every fragment has DF set, so the network never fragments it again (RFC
/// 4821 section 8 recommends host fragmentation mimicking IPv6), and all
/// share the caller's Identification, which must be unique for the
/// (source, destination, protocol) tuple within the maximum datagram lifetime
/// (RFC 6864 section 4.3).
#[derive(Clone, Copy, Debug)]
pub struct Fragmenter {
    first: [u8; 60],
    first_len: u8,
    later: [u8; 60],
    later_len: u8,
    data_len: u16,
}

impl Fragmenter {
    /// `data_len` is the length of the complete datagram's data (transport
    /// header and payload, whose checksum already covers all of it).
    pub fn new(
        header: Header,
        protocol: u8,
        identification: u16,
        data_len: usize,
        timestamp: u32,
    ) -> Result<Self, Error> {
        let Header {
            ip,
            hop_limit,
            dscp,
            ecn,
            ipv4_options,
        } = header;
        let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
            return Err(Error::Version);
        };
        if hop_limit == 0 || dscp > 63 || ecn > 3 {
            return Err(Error::Invalid);
        }
        let mut options = [0; 40];
        let (destination, option_len) = ipv4_options
            .encode(source, destination, timestamp, &mut options)
            .map_err(|_| Error::Options)?;
        // The reassembled datagram's Total Length is at most 65535 octets.
        if data_len > usize::from(u16::MAX) - IP_HEADER - option_len {
            return Err(Error::Length);
        }
        let mut copied = [0; 40];
        let copied_len = ntcp::copied_fragment_options(&options[..option_len], &mut copied)
            .map_err(|_| Error::Options)?;
        let template = |options: &[u8]| {
            let mut h = [0; 60];
            h[0] = 0x40 | ((IP_HEADER + options.len()) / 4) as u8;
            h[1] = (dscp << 2) | ecn;
            h[4..6].copy_from_slice(&identification.to_be_bytes());
            h[8] = hop_limit;
            h[9] = protocol;
            h[12..16].copy_from_slice(&source.octets());
            h[16..20].copy_from_slice(&destination.octets());
            h[IP_HEADER..IP_HEADER + options.len()].copy_from_slice(options);
            h
        };
        Ok(Self {
            first: template(&options[..option_len]),
            first_len: (IP_HEADER + option_len) as u8,
            later: template(&copied[..copied_len]),
            later_len: (IP_HEADER + copied_len) as u8,
            data_len: data_len as u16,
        })
    }

    /// Header length of the fragment whose data starts at `offset`.
    pub fn header_len(&self, offset: usize) -> usize {
        usize::from(if offset == 0 {
            self.first_len
        } else {
            self.later_len
        })
    }

    /// Data octets of the fragment starting at `offset` within packets of at
    /// most `packet_limit` octets: all remaining data if it fits, otherwise
    /// the largest multiple of 8, because every later fragment's offset
    /// counts 8-octet units (RFC 791 section 3.2).
    pub fn fragment_len(&self, offset: usize, packet_limit: usize) -> Result<usize, Error> {
        let remaining = usize::from(self.data_len)
            .checked_sub(offset)
            .filter(|n| *n != 0 && offset.is_multiple_of(8))
            .ok_or(Error::Invalid)?;
        let room = packet_limit
            .checked_sub(self.header_len(offset))
            .ok_or(Error::Length)?;
        if remaining <= room {
            return Ok(remaining);
        }
        match room & !7 {
            0 => Err(Error::Length),
            len => Ok(len),
        }
    }

    /// Write the fragment holding `data`, the complete datagram's data at
    /// `offset`, into `packet`; returns the packet length. Header length,
    /// Total Length, MF and the header checksum are computed per fragment.
    /// A datagram that needs no fragmentation is not a fragment: encode it
    /// with the atomic entrypoints instead.
    pub fn encode(&self, packet: &mut [u8], offset: usize, data: &[u8]) -> Result<usize, Error> {
        let end = offset.checked_add(data.len()).ok_or(Error::Length)?;
        let total = usize::from(self.data_len);
        let more = end < total;
        if data.is_empty()
            || end > total
            || !offset.is_multiple_of(8)
            || (more && !data.len().is_multiple_of(8))
            || (offset == 0 && !more)
        {
            return Err(Error::Invalid);
        }
        let (template, header_len) = if offset == 0 {
            (&self.first, usize::from(self.first_len))
        } else {
            (&self.later, usize::from(self.later_len))
        };
        let len = header_len + data.len();
        let packet = packet.get_mut(..len).ok_or(Error::Length)?;
        packet[..header_len].copy_from_slice(&template[..header_len]);
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        let flags = 0x4000 | if more { 0x2000 } else { 0 } | (offset / 8) as u16;
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        let sum = checksum(&packet[..header_len]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet[header_len..].copy_from_slice(data);
        Ok(len)
    }
}
//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= reason=The atomic IPv4 codec sets DF on every packet it encodes and ntcp_ip::Fragmenter sets DF on every Host-originated fragment; the codec's ECN/DSCP matrix asserts 0x4000 with no fragment offset. Keeping DF is the selected behavior wherever the host performs Path MTU Discovery, not optional clear-DF termination. User disposition (recorded): a native connection whose application sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT does not perform Path MTU Discovery with its ordinary output, which it sends as IPv4 TCP packets without DF, each carrying an Identification leased from the Host allocator for its (source, destination, TCP) tuple; its PLPMTUD probes keep DF.
//# and sends all datagrams on that path with the DF bit set.

//= https://www.rfc-editor.org/rfc/rfc1191#section-2
//= reason=Enabled IPv4 PMTUD retains DF in the codec and reacts to validated lower-MTU feedback; zero-MTU and family-floor tests exercise decrease and bounded repair. This is not a claim about arbitrary external embeddings.
//# Normally, the host continues to set DF in all datagrams, so that if the route
//# changes and the new PMTU is lower, it will be discovered.

pub fn encode(packet: &mut [u8], transmit: ntcp::Transmit, timestamp: u32) -> Result<usize, Error> {
    let len = transmit.len;
    encode_present(packet, transmit.into(), PROTOCOL_TCP, len, timestamp, len)
}

/// Encode IP around `len` transport bytes of `protocol` resident at
/// `packet[IPV4_HEADER..]`; they move behind any options. Returns stored length.
pub fn encode_datagram(
    packet: &mut [u8],
    header: Header,
    protocol: u8,
    len: usize,
    timestamp: u32,
) -> Result<usize, Error> {
    encode_present(packet, header, protocol, len, timestamp, len)
}

/// Encode a checksummed UDP datagram whose `payload_len` data bytes are
/// resident at `packet[IPV4_HEADER + UDP_HEADER..]`. Returns the packet length.
/// The payload is never modified; on error only header bytes may be.
pub fn encode_udp(
    packet: &mut [u8],
    header: Header,
    source_port: u16,
    destination_port: u16,
    payload_len: usize,
    timestamp: u32,
) -> Result<usize, Error> {
    let len = ntcp_ip_common::encode_udp(
        header.ip.source,
        header.ip.destination,
        source_port,
        destination_port,
        packet.get_mut(IP_HEADER..).ok_or(Error::Length)?,
        payload_len,
    )?;
    encode_datagram(packet, header, PROTOCOL_UDP, len, timestamp)
}

/// Encode IP around an already checksummed TCP header. The remaining TCP bytes
/// reside in immutable external payload ranges; only present header bytes move.
pub fn encode_shared_header(
    packet: &mut [u8],
    transmit: ntcp::Transmit,
    timestamp: u32,
    tcp_header_len: usize,
) -> Result<usize, Error> {
    if !(20..=60).contains(&tcp_header_len)
        || !tcp_header_len.is_multiple_of(4)
        || tcp_header_len > transmit.len
    {
        return Err(Error::Length);
    }
    let len = transmit.len;
    encode_present(
        packet,
        transmit.into(),
        PROTOCOL_TCP,
        len,
        timestamp,
        tcp_header_len,
    )
}
//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# Total Length is the length of the datagram, measured in octets, including
//# internet header and data. This field allows the length of a datagram to
//# be up to 65,535 octets.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# Bit 0: reserved, must be zero
//# Bit 1: (DF) 0 = May Fragment, 1 = Don't Fragment.
//# Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# This field indicates the next level protocol used in the data portion of
//# the internet datagram. The values for various protocols are specified in
//# "Assigned Numbers" [9].

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//# A host MUST NOT send a datagram with a Time-to-Live (TTL) value of zero.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.7
//# The IP layer MUST provide a means for the transport layer to set the TTL
//# field of every datagram that is sent. When a fixed TTL value is used, it
//# MUST be configurable. The current suggested value will be published in
//# the "Assigned Numbers" RFC.

//= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
//# There MUST be a means for the transport layer to specify IP options to be
//# included in transmitted IP datagrams (see Section 3.4).

//= https://www.rfc-editor.org/rfc/rfc6864#section-4
//# Atomic datagrams: (DF==1)&&(MF==0)&&(frag_offset==0)

//= https://www.rfc-editor.org/rfc/rfc6864#section-4.1
//# Originating sources MAY set the IPv4 ID field of atomic datagrams to any
//# value.
//= https://www.rfc-editor.org/rfc/rfc4821#section-4
//= reason=Host fragmentation mimics IPv6 and happens only in the host: Host UDP datagrams in Fragment mode and the Host's Echo Replies (the Echo service does not answer an IPv4 Echo Request carrying a source route until T14 delivers received option metadata to Host-originated replies) leave through one datagram emitter (Host::transmit, crates/stacks/ntcp-host/src/emitter.rs) that cuts an IPv4 datagram larger than the connectionless effective size with ntcp_ip::Fragmenter, which sets DF on every fragment, just as it cuts IPv6 (base header, Fragment header, upper layer); the atomic IPv4 encoder (encode_present) sets DF on every unfragmented packet, and TCP never enters source fragmentation. Host tests assert DF on every IPv4 fragment and packet of a fragmented send, the tun_echo IPv4 path asserts DF on TCP packets and PLPMTUD probes, and the integration/rfc_host fragment, fragment-ptb and adjunct-silence cases check DF on every captured IPv4 fragment and probe. User disposition of the SHOULD (recorded): an application that sets IP_MTU_DISCOVER=IP_PMTUDISC_DONT on a native socket gets its ordinary IPv4 TCP output without DF, an application-requested exception; every such packet carries an Identification leased from the Host allocator for its (source, destination, TCP) tuple, the RFC 6864 ceiling holds the packet instead of reusing a value, its PLPMTUD probes keep DF and TCP is never source-fragmented (ntcp-socket tests managed_dont_leases_identifiers_keeps_df_on_probes_and_holds_at_the_ceiling and dont_packets_follow_the_source_quiet_assertion).
//# All hosts SHOULD use IPv4 fragmentation in a mode that mimics IPv6 functionality. All fragmentation SHOULD be done on the host, and all IPv4 packets, including fragments, SHOULD have the DF bit set such that they will not be fragmented (again) in the network. See Section 8.
fn encode_present(
    packet: &mut [u8],
    header: Header,
    protocol: u8,
    transport_len: usize,
    timestamp: u32,
    present: usize,
) -> Result<usize, Error> {
    let Header {
        ip,
        hop_limit,
        dscp,
        ecn,
        ipv4_options,
    } = header;
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (ip.source, ip.destination) else {
        return Err(Error::Version);
    };
    let mut options = [0; 40];
    let (destination, option_len) = ipv4_options
        .encode(source, destination, timestamp, &mut options)
        .map_err(|_| Error::Options)?;
    let header_len = IP_HEADER + option_len;
    let total_len = transport_len.checked_add(header_len).ok_or(Error::Length)?;
    let stored_len = header_len.checked_add(present).ok_or(Error::Length)?;
    if total_len > usize::from(u16::MAX) || stored_len > packet.len() {
        return Err(Error::Length);
    }
    if hop_limit == 0 || dscp > 63 || ecn > 3 {
        return Err(Error::Invalid);
    }
    packet.copy_within(IP_HEADER..IP_HEADER + present, header_len);
    let header = &mut packet[..header_len];
    header.fill(0);
    header[0] = 0x40 | (header_len / 4) as u8;
    header[IP_HEADER..].copy_from_slice(&options[..option_len]);
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.8.1
    //# RFC 1122 allows that if a retransmitted packet is identical to the
    //# original packet (which implies not only that the data boundaries have
    //# not changed, but also that none of the headers have changed), then
    //# the same IPv4 Identification field MAY be used (see Section 3.2.1.5
    //# of RFC 1122) (MAY-4).
    // Atomic IPv4 datagrams need no unique ID (RFC 6864); ID remains zero.
    //= https://www.rfc-editor.org/rfc/rfc3168#section-5.3
    //= reason=IPv4 example sets DF for all packets; ECN/DSCP matrix explicitly asserts DF and no fragment offset, including both ECT codepoints.
    //# ECN-capable packets MAY have the DF (Don't Fragment) bit set.
    header[6] = 0x40; // DF: this codec never fragments.

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //# Time to Live (TTL):  The TTL value used to send TCP segments MUST be
    //# configurable (MUST-49).
    header[8] = hop_limit;
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.1.9
    //# TCP implementations
    //# SHOULD pass the current Differentiated Services field value without
    //# change to the IP layer, when it sends segments on the connection
    //# (SHLD-22).
    header[1] = (dscp << 2) | (ecn & 3);
    header[9] = protocol;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());
    let sum = checksum(header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Ok(stored_len)
}

// Checked quoted header: returns metadata, header length, original packet
// length, and protocol. Expired hop limits are valid in error quotes.
pub fn quote_header(b: &[u8]) -> Result<(IpMetadata, usize, usize, u8), Error> {
    let (ip, header, total, protocol, _) = quote(b, false)?;
    Ok((ip, header, total, protocol))
}

/// `quote_header` for a quoted datagram that may be a fragment; also returns
/// its fragmentation fields. Later fragments carry the copied source route,
/// so the final destination is recovered the same way.
pub fn quote_fragment_header(
    b: &[u8],
) -> Result<(IpMetadata, usize, usize, u8, Fragmentation), Error> {
    quote(b, true)
}

fn quote(
    b: &[u8],
    fragments: bool,
) -> Result<(IpMetadata, usize, usize, u8, Fragmentation), Error> {
    let (header, total, fragmentation) = bounds(b, fragments)?;
    let mut destination = v4(&b[16..20]);
    // Quotes can catch source-routed datagrams before their final hop. Core
    // options parse intentionally rejects unfinished routes, so validate a
    // bounded copy with its pointer completed and recover logical destination.
    let mut options = [0; 40];
    options[..header - 20].copy_from_slice(&b[20..header]);
    let mut offset = 0;
    while offset < header - 20 {
        let kind = options[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let len = usize::from(*options.get(offset + 1).ok_or(Error::Options)?);
        if len < 2 || len > header - 20 - offset {
            return Err(Error::Options);
        }
        if matches!(kind, 131 | 137) {
            if len < 3 || (len - 3) % 4 != 0 {
                return Err(Error::Options);
            }
            let pointer = usize::from(options[offset + 2]);
            if pointer < 4 || (pointer <= len && (pointer - 4) % 4 != 0) {
                return Err(Error::Options);
            }
            if pointer <= len {
                destination = v4(&options[offset + len - 4..offset + len]);
            }
            options[offset + 2] = (len + 1) as u8;
        }
        offset += len;
    }
    Ipv4Options::parse(&options[..header - 20], true).map_err(|_| Error::Options)?;
    Ok((
        IpMetadata {
            source: v4(&b[12..16]).into(),
            destination: destination.into(),
        },
        header,
        total,
        b[9],
        fragmentation,
    ))
}
