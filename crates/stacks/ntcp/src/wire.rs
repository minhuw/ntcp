use core::net::IpAddr;
use ntcp_buffer::TxPart;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1
//= reason=TCP flag layout: existing endpoint parses emitted SYN/SYN-ACK ECE/CWR; wire constants and encoder use the assigned low-byte positions. Erratum 2307 corrects only the RFC793 figure reference.
//# Bit 9 in the Reserved field of the TCP header is designated as the ECN-Echo flag.
// Actor/condition: TCP endpoint; selected mitigation.
pub const ECE: u8 = 0x40;
//= https://www.rfc-editor.org/rfc/rfc3168#section-6.1
//= reason=TCP flag layout: existing endpoint asserts emitted CWR in setup SYN and fresh data, absent from SYN-ACK/retransmissions.
//# The CWR flag is assigned to Bit 8 in the Reserved field of the TCP header.
// Actor/condition: TCP endpoint; selected mitigation.
pub const CWR: u8 = 0x80;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IpMetadata {
    pub source: IpAddr,
    pub destination: IpAddr,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The window size MUST be treated as an unsigned number, or else large window sizes
    //# will appear like negative windows and TCP will not work (MUST-1).
    pub window: u16,
    pub urgent_pointer: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FastOpenCookie {
    bytes: [u8; 16],
    len: u8,
}

impl FastOpenCookie {
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //= reason=Original published table interpreted with verified erratum 4238: Length 2 requests an empty cookie; nonempty cookies have even Length 6..18.
    //# Kind 1 byte: value = 34 Length 1 byte: range 6 to 18 (bytes); limited by remaining space in the
    //# options field. The number MUST be even. Cookie 0, or 4 to 16 bytes (Length - 2)
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //# The minimum cookie size is 4 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, WireError> {
        // RFC 7413 section 4.1.1, with verified errata 4238/4239:
        // length 2 requests a cookie; cookie-bearing lengths are even 6..=18.
        if !matches!(bytes.len(), 0 | 4 | 6 | 8 | 10 | 12 | 14 | 16) {
            return Err(WireError::InvalidOption);
        }
        let mut cookie = Self::request();
        cookie.bytes[..bytes.len()].copy_from_slice(bytes);
        cookie.len = bytes.len() as u8;
        Ok(cookie)
    }

    pub const fn request() -> Self {
        Self {
            bytes: [0; 16],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub invalid_window_scale: Option<u8>,
    pub timestamps: Option<(u32, u32)>,
    pub fast_open: Option<FastOpenCookie>,
    pub sack_permitted: bool,
    pub sack_blocks: [Option<(u32, u32)>; 4],
}

pub struct Segment<'a> {
    pub header: Header,
    pub options: Options,
    pub raw_options: &'a [u8],
    pub payload: &'a [u8],
}

impl Segment<'_> {
    // The parser fills a contiguous prefix in wire order, starting with
    // the DSACK block when present.
    pub(crate) fn carries_sack(&self) -> bool {
        let present = self.options.sack_blocks[0].is_some();
        debug_assert_eq!(present, self.options.sack_blocks.iter().any(Option::is_some));
        present
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    InvalidHeader,
    InvalidOption,
    InvalidChecksum,
    AddressFamily,
    TooLong,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PseudoHeader {
    limit: u32,
    sum: u32,
}

impl PseudoHeader {
    pub(crate) fn new(ip: IpMetadata) -> Result<Self, WireError> {
        let (limit, addresses) = match (ip.source, ip.destination) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (
                u32::from(u16::MAX) - 20,
                u64::from(u32::from(src)) + u64::from(u32::from(dst)),
            ),
            (IpAddr::V6(src), IpAddr::V6(dst)) => (
                u32::MAX,
                u64::from(add_words(add_words(0, &src.octets()), &dst.octets())),
            ),
            _ => return Err(WireError::AddressFamily),
        };
        let sum = addresses + 6;
        let sum = (sum & 0xffff) + (sum >> 16);
        let sum = (sum & 0xffff) + (sum >> 16);
        Ok(Self {
            limit,
            sum: ((sum & 0xffff) + (sum >> 16)) as u32,
        })
    }

    pub(crate) fn address_protocol_sum(self) -> u16 {
        self.sum as u16
    }

    pub(crate) fn parse(self, bytes: &[u8], verified: bool) -> Result<Segment<'_>, WireError> {
        if bytes.len() > self.limit as usize {
            return Err(WireError::TooLong);
        }
        parse_segment(
            bytes,
            (!verified).then(|| u64::from(self.sum) + bytes.len() as u64),
        )
    }

    fn sum(self, len: u32) -> u32 {
        let sum = self.sum + (len & 0xffff) + (len >> 16);
        let sum = (sum & 0xffff) + (sum >> 16);
        (sum & 0xffff) + (sum >> 16)
    }

    fn checked_sum(self, len: usize) -> Result<u32, WireError> {
        if len > self.limit as usize {
            return Err(WireError::TooLong);
        }
        Ok(self.sum(len as u32))
    }
}

fn checked_length(ip: IpMetadata, len: usize) -> Result<u32, WireError> {
    let limit = match (ip.source, ip.destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => u16::MAX as u32 - 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => u32::MAX,
        _ => return Err(WireError::AddressFamily),
    };
    let len = u32::try_from(len).map_err(|_| WireError::TooLong)?;
    if len > limit {
        return Err(WireError::TooLong);
    }
    Ok(len)
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//# If a segment contains an odd number of header and text octets, alignment can be achieved
//# by padding the last octet with zeros on its right to form a 16-bit word for checksum
//# purposes. The pad is not transmitted as part of the segment.
// Add the folded sum of a slice to the folded sum of its prefix.
fn add_words(sum: u32, bytes: &[u8]) -> u32 {
    debug_assert!(sum <= 0xffff);
    let sum = sum + u32::from(!ntcp_ip_common::checksum(bytes));
    (sum & 0xffff) + (sum >> 16)
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//# The checksum field is the 16-bit ones' complement of the ones' complement sum of all
//# 16-bit words in the header and text.
pub fn checksum(ip: IpMetadata, segment: &[u8]) -> Result<u16, WireError> {
    let sum = PseudoHeader::new(ip)?.checked_sum(segment.len())?;
    Ok(!(add_words(sum, segment) as u16))
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//# The checksum also covers a pseudo-header (Figure 2) conceptually prefixed to the TCP
//# header. The pseudo-header is 96 bits for IPv4 and 320 bits for IPv6.
fn pseudo_header_sum(ip: IpMetadata, len: u32) -> Result<u32, WireError> {
    Ok(PseudoHeader::new(ip)?.sum(len))
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
//# There is no guarantee that senders will use this option, so receivers MUST
//# be prepared to process options even if they do not begin on a word
//# boundary (MUST-64).
//= https://www.rfc-editor.org/rfc/rfc2018#section-2
//= reason=Kind 4 accepts exactly length 2; malformed lengths/truncation are rejected. SYN authorization is separately cited.
//# This two-byte option may be sent in a SYN by a TCP that has been extended to
//# receive (and presumably process) the SACK option once the connection has
//# opened.
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= reason=Codec decodes two full-width big-endian u32 edges per block and preserves wire order, including wrapping values.
//# Each contiguous block of data queued at the data receiver is defined in the
//# SACK option by two 32-bit unsigned integers in network byte order:
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= reason=Parser accepts lengths 10/18/26/34; encoder 40-byte option cap admits 3 with padded timestamps and rejects 4.
//# A SACK option that specifies n blocks will have a length of 8*n+2 bytes, so
//# the 40 bytes available for TCP options can specify a maximum of 4 blocks. It
//# is expected that SACK will often be used in conjunction with the Timestamp
//# option used for RTTM [Jacobson92], which takes an additional 10 bytes (plus
//# two bytes of padding); thus a maximum of 3 SACK blocks will be allowed in
//# this case.
//= https://www.rfc-editor.org/rfc/rfc2018#section-2
//= reason=Wire codec recognizes the specified option kind; tests parse literal raw kind bytes and round-trip them.
//# Kind: 4
//= https://www.rfc-editor.org/rfc/rfc2018#section-3
//= reason=Wire codec recognizes the specified option kind; tests parse literal raw kind bytes and round-trip them.
//# Kind: 5
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
//= reason=Verified erratum 4238 permits the empty Length 2 request; this published table is retained for provenance.
//# Kind 1 byte: value = 34 Length 1 byte: range 6 to 18 (bytes); limited by remaining space in the
//# options field. The number MUST be even. Cookie 0, or 4 to 16 bytes (Length - 2)
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
//# Although the diagram shows a cookie aligned on 32-bit boundaries, alignment is not required.
//= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
//= reason=Invalid incoming Kind 34 lengths discard credential metadata; an unframeable suffix stops traversal without guessing boundaries, preserving validated prefix options and DataOffset payload. Non-SYN credentials are ignored. Strict output, checksum/header and unrelated malformed-option rejection remain enforced.
//# Options with invalid Length values or without the SYN flag set MUST be ignored.
fn walk_options(mut bytes: &[u8], outgoing: bool) -> Result<Options, WireError> {
    let mut options = Options::default();
    let mut fast_open_seen = false;
    while let Some(&kind) = bytes.first() {
        // Codec support for EOL, NOP, and MSS; connection-level MSS negotiation is
        // separate.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //# A given TCP implementation can support any currently defined options, but the
        //# following options MUST be supported (MUST-4 -- note Maximum Segment Size Option
        //# support is also part of MUST-14 in Section 3.7.1):
        match kind {
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
            //# This option code indicates the end of the option list.
            0 => {
                if outgoing && bytes.iter().any(|&byte| byte != 0) {
                    return Err(WireError::InvalidOption);
                }
                break;
            }
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
            //# Case 1: A single octet of option-kind.
            1 => bytes = &bytes[1..],
            _ => {
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //# All TCP Options except End of Option List Option (EOL) and No-Operation
                //# (NOP) MUST have length fields, including all future options (MUST-68).
                if kind == 34
                    && !outgoing
                    && !bytes
                        .get(1)
                        .is_some_and(|&len| len >= 2 && usize::from(len) <= bytes.len())
                {
                    // DataOffset already frames the payload. An unframeable
                    // credential suffix cannot authorize data or supply a next
                    // TLV boundary; retain only validated ordinary prefix options.
                    options.fast_open = None;
                    break;
                }
                let len = *bytes.get(1).ok_or(WireError::InvalidOption)? as usize;
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //# TCP implementations MUST be prepared to handle
                //# an illegal option length (e.g., zero); a suggested procedure is to
                //# reset the connection and log the error cause (MUST-7).
                if len < 2 || len > bytes.len() {
                    return Err(WireError::InvalidOption);
                }
                match kind {
                    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
                    //# Length: 1 byte; Length == 4.
                    2 if len == 4 => {
                        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
                        //# Maximum Segment Size (MSS): 2 bytes.
                        options.mss = Some(u16::from_be_bytes([bytes[2], bytes[3]]));
                    }
                    3 if len == 3 => {
                        if outgoing && bytes[2] > 14 {
                            return Err(WireError::InvalidOption);
                        }
                        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
                        //= reason=Parser clamps peer exponent to 14; local exponent search bounded 0..=14. Erratum 5585 is editorial; rejected 5586 does not replace the <2^30 requirement.
                        //# Thus, the shift count
                        //# MUST be limited to 14 (which allows windows of 2^30 = 1 GiB).
                        //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
                        //= reason=Parser preserves one invalid raw exponent for the bounded connection diagnostic while keeping the effective WS clamp at 14. Wire 15/255 vectors and connection event coalescing test the notification path.
                        //# If a
                        //# Window Scale option is received with a shift.cnt value larger than
                        //# 14, the TCP SHOULD log the error but MUST use 14 instead of the
                        //# specified value.
                        options.window_scale = Some(bytes[2].min(14));
                        if bytes[2] > 14 {
                            options.invalid_window_scale.get_or_insert(bytes[2]);
                        }
                    }
                    4 if len == 2 => options.sack_permitted = true,
                    // RFC 2018 section 3: "A SACK option that specifies n blocks
                    // will have a length of 8*n+2 bytes" (at most four blocks).
                    5 if matches!(len, 10 | 18 | 26 | 34) && options.sack_blocks[0].is_none() => {
                        // Preserve wire order, including a possible DSACK first block.
                        // Range validity needs connection state; wrapping edges are valid.
                        for (slot, block) in options
                            .sack_blocks
                            .iter_mut()
                            .zip(bytes[2..len].chunks_exact(8))
                        {
                            *slot = Some((
                                u32::from_be_bytes(block[..4].try_into().unwrap()),
                                u32::from_be_bytes(block[4..].try_into().unwrap()),
                            ));
                        }
                    }
                    //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
                    //= reason=TS parser/output literal kind 8.
                    //# Kind: 8
                    //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
                    //= reason=TS has two four-byte fields plus kind/length, padding external to length.
                    //# Length: 10 bytes
                    8 if len == 10 && options.timestamps.is_none() => {
                        options.timestamps = Some((
                            u32::from_be_bytes(bytes[2..6].try_into().unwrap()),
                            u32::from_be_bytes(bytes[6..10].try_into().unwrap()),
                        ));
                    }
                    34 => {
                        let cookie = FastOpenCookie::new(&bytes[2..len]);
                        if outgoing && (cookie.is_err() || fast_open_seen) {
                            return Err(WireError::InvalidOption);
                        }
                        // Ignore bounded invalid cookie lengths (RFC 7413 4.1.1).
                        // Duplicate kind 34 is ambiguous: discard all TFO metadata
                        // on input, even if one occurrence has an invalid length.
                        options.fast_open = if fast_open_seen { None } else { cookie.ok() };
                        fast_open_seen = true;
                    }
                    2 | 3 | 4 | 5 | 8 => return Err(WireError::InvalidOption),
                    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                    //# A TCP implementation MUST (MUST-6) ignore without error any TCP
                    //# Option it does not implement, assuming that the option has a length
                    //# field.
                    _ => {}
                }
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //# The option-length counts the two octets of option-kind and option-
                //# length as well as the option-data octets.
                bytes = &bytes[len..];
            }
        }
    }
    Ok(options)
}

// Established segments carry timestamps alone, aligned behind two NOPs
// (RFC 7323 Appendix A): read that layout directly, as Linux's
// tcp_fast_parse_options does (tcp_parse_aligned_timestamp), and walk
// anything else. The walk reads the same bytes into the same Options.
#[inline]
fn aligned_timestamp(options: &[u8]) -> bool {
    options.len() == 12 && options.starts_with(&[1, 1, 8, 10])
}

#[inline]
fn read_options(bytes: &[u8], outgoing: bool) -> Result<Options, WireError> {
    if bytes.is_empty() {
        return Ok(Options::default());
    }
    if aligned_timestamp(bytes) {
        let ts = &bytes[4..];
        return Ok(Options {
            timestamps: Some((
                u32::from_be_bytes(ts[..4].try_into().unwrap()),
                u32::from_be_bytes(ts[4..].try_into().unwrap()),
            )),
            ..Options::default()
        });
    }
    walk_options(bytes, outgoing)
}

/// Write `options` in the one layout every outgoing segment uses, as Linux's
/// tcp_options_write lays out a struct tcp_out_options on each transmit:
/// MSS; Timestamps behind SACK-permitted or two NOPs, so TSval and TSecr are
/// 32-bit aligned (RFC 7323 Appendix A), or else SACK-permitted behind two
/// NOPs; Window Scale behind a NOP; a Fast Open cookie padded with NOPs; SACK
/// blocks behind two NOPs, up to the first absent one. Returns the length
/// written, a multiple of 4. `invalid_window_scale` is input only. The
/// caller sizes the set: at most 40 bytes.
pub(crate) fn write_options(options: &Options, out: &mut [u8; 40]) -> usize {
    let mut n = 0;
    if let Some(mss) = options.mss {
        let mss = mss.to_be_bytes();
        out[..4].copy_from_slice(&[2, 4, mss[0], mss[1]]);
        n = 4;
    }
    if let Some((value, echo)) = options.timestamps {
        // SACK-permitted replaces timestamp padding on SYN, as in Linux.
        out[n..n + 4].copy_from_slice(if options.sack_permitted {
            &[4, 2, 8, 10]
        } else {
            &[1, 1, 8, 10]
        });
        out[n + 4..n + 8].copy_from_slice(&value.to_be_bytes());
        out[n + 8..n + 12].copy_from_slice(&echo.to_be_bytes());
        n += 12;
    } else if options.sack_permitted {
        out[n..n + 4].copy_from_slice(&[1, 1, 4, 2]);
        n += 4;
    }
    if let Some(scale) = options.window_scale {
        out[n..n + 4].copy_from_slice(&[1, 3, 3, scale]);
        n += 4;
    }
    if let Some(cookie) = &options.fast_open {
        let bytes = cookie.as_bytes();
        let length = bytes.len() + 2;
        out[n] = 34;
        out[n + 1] = length as u8;
        out[n + 2..n + length].copy_from_slice(bytes);
        n += length;
        while n % 4 != 0 {
            out[n] = 1;
            n += 1;
        }
    }
    let blocks = options.sack_blocks.iter().map_while(|block| *block).count();
    if blocks != 0 {
        out[n..n + 4].copy_from_slice(&[1, 1, 5, (2 + blocks * 8) as u8]);
        for (index, (left, right)) in options.sack_blocks[..blocks].iter().flatten().enumerate() {
            let at = n + 4 + index * 8;
            out[at..at + 4].copy_from_slice(&left.to_be_bytes());
            out[at + 4..at + 8].copy_from_slice(&right.to_be_bytes());
        }
        n += 4 + blocks * 8;
    }
    n
}

pub fn parse(ip: IpMetadata, bytes: &[u8]) -> Result<Segment<'_>, WireError> {
    PseudoHeader::new(ip)?.parse(bytes, false)
}

/// `parse` of a segment whose checksum is not this call's to verify: the
/// receiving device verified it (`RxPacketMetadata::tcp_checksum_verified`),
/// or this Endpoint encoded it, its checksum perhaps left for a device to
/// complete (`ConnectionConfig::tcp_checksum_offload`).
pub(crate) fn parse_unchecked(ip: IpMetadata, bytes: &[u8]) -> Result<Segment<'_>, WireError> {
    checked_length(ip, bytes.len())?;
    parse_segment(bytes, None)
}

#[inline]
fn parse_segment(bytes: &[u8], pseudo: Option<u64>) -> Result<Segment<'_>, WireError> {
    if bytes.len() < 20 {
        return Err(WireError::Truncated);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The number of 32-bit words in the TCP header. This indicates where the data begins.
    //# The TCP header (even one including options) is an integer multiple of 32 bits long.
    let header_len = (bytes[12] >> 4) as usize * 4;
    if header_len < 20 {
        return Err(WireError::InvalidHeader);
    }
    if header_len > bytes.len() {
        return Err(WireError::Truncated);
    }
    // A device that verified it checked it, as Linux trusts
    // CHECKSUM_UNNECESSARY.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# and the receiver MUST check it (MUST-3).
    if pseudo.is_some_and(|sum| ntcp_ip_common::checksum_with_sum(bytes, sum) != 0) {
        return Err(WireError::InvalidChecksum);
    }
    let raw_options = &bytes[20..header_len];
    // Other options remain flag-independent; Fast Open is only meaningful on SYN.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# A TCP implementation MUST be able to receive a TCP Option in any segment (MUST-5).
    let mut options = read_options(raw_options, false)?;
    if bytes[13] & SYN == 0 {
        options.fast_open = None;
    }
    Ok(Segment {
        header: Header {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            acknowledgment: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            // The reserved low nibble of byte 12 is not exposed or interpreted.
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
            //# Must be zero in generated segments and must be ignored in received segments
            //# if the corresponding future features are not implemented by the sending or
            //# receiving host.
            flags: bytes[13],
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
        },
        options,
        raw_options,
        payload: &bytes[header_len..],
    })
}

//= https://www.rfc-editor.org/rfc/rfc2018#section-2
//= reason=Output rejects kind 4 without SYN; parsing remains flag-independent.
//# It MUST NOT be sent on non-SYN segments.
pub fn encode(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    encode_with(ip, header, options, payload, out, false)
}

fn validate_output_options(flags: u8, options: &[u8]) -> Result<(), WireError> {
    if options.len() > 40 {
        return Err(WireError::TooLong);
    }
    let parsed_options = read_options(options, true)?;
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
    //# This field may be sent in the initial connection request (i.e., in
    //# segments with the SYN control bit set) and MUST NOT be sent in other
    //# segments (MUST-65).
    // RFC 2018 section 2: "It MUST NOT be sent on non-SYN segments."
    if flags & SYN == 0
        && (parsed_options.mss.is_some()
            || parsed_options.window_scale.is_some()
            || parsed_options.sack_permitted
            || parsed_options.fast_open.is_some())
    {
        return Err(WireError::InvalidOption);
    }
    Ok(())
}

/// `encode`, or with `partial` for a device that completes the checksum
/// (`ConnectionConfig::tcp_checksum_offload`): the checksum field then
/// holds the pseudo-header sum, as Linux's __tcp_v4_send_check and
/// __tcp_v6_send_check leave it for CHECKSUM_PARTIAL, and the segment is
/// not summed.
pub(crate) fn encode_with(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    payload: &[u8],
    out: &mut [u8],
    partial: bool,
) -> Result<usize, WireError> {
    // An empty option list and the aligned Timestamp layout are valid on
    // every segment. Other layouts need the full option and SYN checks.
    if !options.is_empty() && !aligned_timestamp(options) {
        validate_output_options(header.flags, options)?;
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The number of 32-bit words in the TCP header. This indicates where the data begins.
    //# The TCP header (even one including options) is an integer multiple of 32 bits long.
    let pseudo = PseudoHeader::new(ip)?;
    let option_len = options.len().div_ceil(4) * 4;
    let ports = (u32::from(header.source_port) << 16) | u32::from(header.destination_port);
    encode_segment(pseudo, ports, header, option_len, payload, out, partial, |area| {
        let (encoded, padding) = area.split_at_mut(options.len());
        encoded.copy_from_slice(options);
        padding.fill(0);
        None
    })
}

/// Encode established stream output with the already negotiated options.
/// The aligned timestamp can be written directly into the TCP header.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_stream(
    pseudo_header: PseudoHeader,
    ports: u32,
    header: Header,
    timestamps: Option<(u32, u32)>,
    payload: &[u8],
    out: &mut [u8],
    partial: bool,
) -> Result<usize, WireError> {
    let option_len = if timestamps.is_some() { 12 } else { 0 };
    encode_segment(pseudo_header, ports, header, option_len, payload, out, partial, |area| {
        if let Some((value, echo)) = timestamps {
            area[..4].copy_from_slice(&[1, 1, 8, 10]);
            area[4..8].copy_from_slice(&value.to_be_bytes());
            area[8..12].copy_from_slice(&echo.to_be_bytes());
            Some(0x0101 + 0x080a + u64::from(value) + u64::from(echo))
        } else {
            Some(0)
        }
    })
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn encode_segment(
    pseudo_header: PseudoHeader,
    ports: u32,
    header: Header,
    option_len: usize,
    payload: &[u8],
    out: &mut [u8],
    partial: bool,
    write_options: impl FnOnce(&mut [u8]) -> Option<u64>,
) -> Result<usize, WireError> {
    let header_len = 20 + option_len;
    let len = header_len
        .checked_add(payload.len())
        .ok_or(WireError::TooLong)?;
    if len > pseudo_header.limit as usize {
        return Err(WireError::TooLong);
    }
    if out.len() < len {
        return Err(WireError::OutputTooSmall);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The content of the header beyond the End of Option List Option MUST
    //# be header padding of zeros (MUST-69).
    out[..4].copy_from_slice(&ports.to_be_bytes());
    out[4..8].copy_from_slice(&header.sequence.to_be_bytes());
    out[8..12].copy_from_slice(&header.acknowledgment.to_be_bytes());
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# Must be zero in generated segments and must be ignored in received segments if the
    //# corresponding future features are not implemented by the sending or receiving host.
    out[12] = ((header_len / 4) as u8) << 4;
    out[13] = header.flags;
    out[14..16].copy_from_slice(&header.window.to_be_bytes());
    out[18..20].copy_from_slice(&header.urgent_pointer.to_be_bytes());
    let option_sum = write_options(&mut out[20..header_len]);
    out[header_len..len].copy_from_slice(payload);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= reason=encode generates the checksum; parse rejects a nonzero checksum before exposing a segment.
    //# The sender MUST generate it
    //# (MUST-2) and the receiver MUST check it (MUST-3).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# While computing the checksum, the checksum field itself is replaced with zeros.
    let sum = if partial {
        pseudo_header.sum(len as u32) as u16
    } else if let Some(options) = option_sum {
        // The TCP header is an even number of words. Sum the known
        // header fields before folding with the immutable payload,
        // without rereading the stores that constructed the header.
        // Each 32-bit header field already represents the sum of its
        // two 16-bit words modulo 65535, including the paired ports
        // and the IPv6 pseudo-header's full length.
        let fixed = pseudo_header.sum
            + u32::from(u16::from_be_bytes([out[12], header.flags]))
            + u32::from(header.window)
            + u32::from(header.urgent_pointer);
        let wide = u64::from(fixed)
            + u64::from(ports)
            + len as u64
            + options
            + u64::from(header.sequence)
            + u64::from(header.acknowledgment);
        ntcp_ip_common::checksum_with_sum(payload, wide)
    } else {
        out[16..18].fill(0);
        !(add_words(pseudo_header.sum(len as u32), &out[..len]) as u16)
    };
    out[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}

// The checksum field of a `len`-octet segment whose device completes the
// checksum: the folded pseudo-header sum, which the device's one's
// complement sum over the segment, this field included, completes.
fn partial_checksum(ip: IpMetadata, len: usize) -> Result<u16, WireError> {
    Ok(PseudoHeader::new(ip)?.checked_sum(len)? as u16)
}

/// Encode a TCP header while checksumming immutable payload slices in place.
/// Returns header length only; no payload bytes are copied into `out`.
pub fn encode_shared(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    payload: &[crate::Payload],
    out: &mut [u8],
) -> Result<usize, WireError> {
    encode_shared_with(ip, header, options, payload, out, false)
}

/// `encode_shared`, `partial` as for `encode_with`.
pub(crate) fn encode_shared_with(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    payload: &[crate::Payload],
    out: &mut [u8],
    partial: bool,
) -> Result<usize, WireError> {
    let payload_len = payload.iter().try_fold(0usize, |n, p| {
        n.checked_add(p.len()).ok_or(WireError::TooLong)
    })?;
    let header_len = 20 + options.len().div_ceil(4) * 4;
    let total = header_len
        .checked_add(payload_len)
        .ok_or(WireError::TooLong)?;
    let len = checked_length(ip, total)?;
    // The header alone, its checksum field set below.
    let n = encode_with(ip, header, options, &[], out, true)?;
    if partial {
        out[16..18].copy_from_slice(&partial_checksum(ip, total)?.to_be_bytes());
        return Ok(n);
    }
    out[16..18].fill(0);
    let mut sum = pseudo_header_sum(ip, len)?;
    // A word may straddle two slices: an odd slice's last octet waits for
    // the next slice's first.
    let mut odd = None;
    for mut bytes in core::iter::once(&out[..n]).chain(payload.iter().map(|p| p.as_slice())) {
        if let Some(high) = odd
            && let Some((&low, rest)) = bytes.split_first()
        {
            sum = add_words(sum, &[high, low]);
            bytes = rest;
            odd = None;
        }
        let even = bytes.len() & !1;
        sum = add_words(sum, &bytes[..even]);
        if let Some(&last) = bytes.get(even) {
            odd = Some(last);
        }
    }
    if let Some(high) = odd {
        sum = add_words(sum, &[high]);
    }
    out[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(n)
}

/// Encode a TCP header (and optionally gather `payload` parts into `out`).
///
/// When `gather` is true, `out` must hold `header_len + payload_len` bytes and
/// `payload` is copied after the header; returns `header_len + payload_len`.
/// When `gather` is false, `out` need only hold `header_len` bytes; returns
/// `header_len`. When `partial && !gather`, `payload` is not read at all (and
/// may be empty).
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_parts_with(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    payload: &[TxPart<'_>],
    payload_len: usize,
    out: &mut [u8],
    partial: bool,
    gather: bool,
) -> Result<usize, WireError> {
    if !options.is_empty() && !aligned_timestamp(options) {
        validate_output_options(header.flags, options)?;
    }
    let pseudo = PseudoHeader::new(ip)?;
    let option_len = options.len().div_ceil(4) * 4;
    let ports = (u32::from(header.source_port) << 16) | u32::from(header.destination_port);
    encode_segment_parts(
        pseudo,
        ports,
        header,
        option_len,
        payload,
        payload_len,
        out,
        partial,
        gather,
        |area| {
            let (encoded, padding) = area.split_at_mut(options.len());
            encoded.copy_from_slice(options);
            padding.fill(0);
            None
        },
    )
}

/// Stream fast-path counterpart of `encode_parts_with` for established
/// segments carrying no options or an aligned Timestamps option.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_stream_parts(
    pseudo_header: PseudoHeader,
    ports: u32,
    header: Header,
    timestamps: Option<(u32, u32)>,
    payload: &[TxPart<'_>],
    payload_len: usize,
    out: &mut [u8],
    partial: bool,
    gather: bool,
) -> Result<usize, WireError> {
    let option_len = if timestamps.is_some() { 12 } else { 0 };
    encode_segment_parts(
        pseudo_header,
        ports,
        header,
        option_len,
        payload,
        payload_len,
        out,
        partial,
        gather,
        |area| {
            if let Some((value, echo)) = timestamps {
                area[..4].copy_from_slice(&[1, 1, 8, 10]);
                area[4..8].copy_from_slice(&value.to_be_bytes());
                area[8..12].copy_from_slice(&echo.to_be_bytes());
                Some(0x0101 + 0x080a + u64::from(value) + u64::from(echo))
            } else {
                Some(0)
            }
        },
    )
}

/// Encode a TCP header and options with the checksum field zeroed, skipping
/// checksum computation (used for TSO template headers). Returns header length.
pub fn encode_header_zero_checksum(
    ip: IpMetadata,
    header: Header,
    options: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    if !options.is_empty() && !aligned_timestamp(options) {
        validate_output_options(header.flags, options)?;
    }
    let pseudo = PseudoHeader::new(ip)?;
    let option_len = options.len().div_ceil(4) * 4;
    let header_len = 20 + option_len;
    if header_len > pseudo.limit as usize {
        return Err(WireError::TooLong);
    }
    if out.len() < header_len {
        return Err(WireError::OutputTooSmall);
    }
    let ports = (u32::from(header.source_port) << 16) | u32::from(header.destination_port);
    out[..4].copy_from_slice(&ports.to_be_bytes());
    out[4..8].copy_from_slice(&header.sequence.to_be_bytes());
    out[8..12].copy_from_slice(&header.acknowledgment.to_be_bytes());
    out[12] = ((header_len / 4) as u8) << 4;
    out[13] = header.flags;
    out[14..16].copy_from_slice(&header.window.to_be_bytes());
    out[16..18].fill(0);
    out[18..20].copy_from_slice(&header.urgent_pointer.to_be_bytes());
    let (encoded, padding) = out[20..header_len].split_at_mut(options.len());
    encoded.copy_from_slice(options);
    padding.fill(0);
    Ok(header_len)
}

fn sum_tx_parts(mut sum: u32, payload: &[TxPart<'_>]) -> u32 {
    let mut odd = None;
    for part in payload {
        let mut bytes = part.bytes();
        if let Some(high) = odd
            && let Some((&low, rest)) = bytes.split_first()
        {
            sum = add_words(sum, &[high, low]);
            bytes = rest;
            odd = None;
        }
        let even = bytes.len() & !1;
        if even != 0 {
            sum = add_words(sum, &bytes[..even]);
        }
        if let Some(&last) = bytes.get(even) {
            odd = Some(last);
        }
    }
    if let Some(high) = odd {
        sum = add_words(sum, &[high]);
    }
    sum
}

#[inline]
fn fold_wide(wide: u64) -> u32 {
    let folded = (wide & 0xffff_ffff) + (wide >> 32);
    let folded = (folded & 0xffff) + (folded >> 16);
    let folded = ((folded & 0xffff) + (folded >> 16)) as u32;
    (folded & 0xffff) + (folded >> 16)
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn encode_segment_parts(
    pseudo_header: PseudoHeader,
    ports: u32,
    header: Header,
    option_len: usize,
    payload: &[TxPart<'_>],
    payload_len: usize,
    out: &mut [u8],
    partial: bool,
    gather: bool,
    write_options: impl FnOnce(&mut [u8]) -> Option<u64>,
) -> Result<usize, WireError> {
    let header_len = 20 + option_len;
    let total = header_len
        .checked_add(payload_len)
        .ok_or(WireError::TooLong)?;
    if total > pseudo_header.limit as usize {
        return Err(WireError::TooLong);
    }
    let required = if gather { total } else { header_len };
    if out.len() < required {
        return Err(WireError::OutputTooSmall);
    }
    debug_assert!(
        (partial && !gather)
            || payload.iter().map(TxPart::len).sum::<usize>() == payload_len,
        "TxPart payload length mismatch"
    );
    out[..4].copy_from_slice(&ports.to_be_bytes());
    out[4..8].copy_from_slice(&header.sequence.to_be_bytes());
    out[8..12].copy_from_slice(&header.acknowledgment.to_be_bytes());
    out[12] = ((header_len / 4) as u8) << 4;
    out[13] = header.flags;
    out[14..16].copy_from_slice(&header.window.to_be_bytes());
    out[18..20].copy_from_slice(&header.urgent_pointer.to_be_bytes());
    let option_sum = write_options(&mut out[20..header_len]);
    let sum = if partial {
        pseudo_header.sum(total as u32) as u16
    } else if let Some(options) = option_sum {
        let fixed = pseudo_header.sum
            + u32::from(u16::from_be_bytes([out[12], header.flags]))
            + u32::from(header.window)
            + u32::from(header.urgent_pointer);
        let wide = u64::from(fixed)
            + u64::from(ports)
            + total as u64
            + options
            + u64::from(header.sequence)
            + u64::from(header.acknowledgment);
        match payload {
            [] => ntcp_ip_common::checksum_with_sum(&[], wide),
            [only] => ntcp_ip_common::checksum_with_sum(only.bytes(), wide),
            many => !(sum_tx_parts(fold_wide(wide), many) as u16),
        }
    } else {
        out[16..18].fill(0);
        let header_sum = add_words(pseudo_header.sum(total as u32), &out[..header_len]);
        match payload {
            [] => !(header_sum as u16),
            [only] => ntcp_ip_common::checksum_with_sum(only.bytes(), u64::from(header_sum)),
            many => !(sum_tx_parts(header_sum, many) as u16),
        }
    };
    out[16..18].copy_from_slice(&sum.to_be_bytes());
    if gather {
        let mut at = header_len;
        for part in payload {
            let bytes = part.bytes();
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
        debug_assert_eq!(at, total);
        Ok(total)
    } else {
        Ok(header_len)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use std::{vec, vec::Vec};

    fn ips() -> [IpMetadata; 2] {
        [
            IpMetadata {
                source: Ipv4Addr::new(192, 0, 2, 1).into(),
                destination: Ipv4Addr::new(198, 51, 100, 2).into(),
            },
            IpMetadata {
                source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
                destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).into(),
            },
        ]
    }

    #[test]
    fn shared_checksum_matches_contiguous_for_odd_ranges_and_options() {
        use crate::Payload;
        use alloc::{vec, vec::Vec};
        for ip in ips() {
            for len in 1..70 {
                let data: Vec<u8> = (0..len).map(|n| (n * 17) as u8).collect();
                let base = Payload::from_vec(data.clone());
                for chunk in [1, 3, 7, 16] {
                    let parts: Vec<_> = (0..len)
                        .step_by(chunk)
                        .map(|n| base.slice(n..(n + chunk).min(len)).unwrap())
                        .collect();
                    for options in [&[][..], &[1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9][..]] {
                        let mut ordinary = vec![0; 20 + options.len() + len];
                        encode(ip, header(), options, &data, &mut ordinary).unwrap();
                        let mut shared = vec![0xa5; ordinary.len()];
                        let n = encode_shared(ip, header(), options, &parts, &mut shared).unwrap();
                        assert_eq!(&shared[..n], &ordinary[..n]);
                        assert!(shared[n..].iter().all(|&v| v == 0xa5));
                        shared.truncate(n);
                        shared.extend_from_slice(&data);
                        assert_eq!(shared, ordinary);
                        parse(ip, &shared).unwrap();
                    }
                }
            }
        }
    }

    // A device completing the checksum of a segment encoded with `partial`
    // (its field holding the pseudo-header sum) writes exactly what
    // software computes, contiguous and shared alike; parse refuses the
    // partial segment, as its checksum is not final.
    #[test]
    fn a_device_completing_a_partial_checksum_writes_what_software_computes() {
        use crate::Payload;
        for ip in ips() {
            for len in [0, 1, 2, 31, 1000] {
                let data: Vec<u8> = (0..len).map(|n| (n * 29 + 3) as u8).collect();
                let options = [1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9];
                let mut full = vec![0; 32 + len];
                encode(ip, header(), &options, &data, &mut full).unwrap();
                let mut partial = vec![0; 32 + len];
                encode_with(ip, header(), &options, &data, &mut partial, true).unwrap();
                let pseudo = pseudo_header_sum(ip, partial.len() as u32).unwrap() as u16;
                assert_eq!(partial[16..18], pseudo.to_be_bytes());
                assert_eq!(parse(ip, &partial).err(), Some(WireError::InvalidChecksum));
                let mut shared = vec![0; 32];
                let parts = [Payload::from_vec(data.clone())];
                let n = encode_shared_with(ip, header(), &options, &parts, &mut shared, true);
                assert_eq!(n, Ok(32));
                shared.extend_from_slice(&data);
                assert_eq!(shared, partial);
                // The device's one's complement sum over the segment, its
                // checksum field included.
                let device = !(add_words(0, &partial) as u16);
                partial[16..18].copy_from_slice(&device.to_be_bytes());
                assert_eq!(partial, full);
                parse(ip, &partial).unwrap();
            }
        }
    }

    fn header() -> Header {
        Header {
            source_port: 12345,
            destination_port: 80,
            sequence: 0x12345678,
            acknowledgment: 0xabcdef01,
            flags: SYN | ACK | ECE | CWR,
            window: 0xfedc,
            urgent_pointer: 0x3456,
        }
    }

    // Independent reference: concatenate the actual pseudo-header and packet,
    // accumulate bytes in a wide integer, and fold only at the end.
    fn reference(ip: IpMetadata, packet: &[u8]) -> u16 {
        let mut bytes = Vec::new();
        match (ip.source, ip.destination) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                bytes.extend(a.octets());
                bytes.extend(b.octets());
                bytes.extend([0, 6]);
                bytes.extend((packet.len() as u16).to_be_bytes());
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                bytes.extend(a.octets());
                bytes.extend(b.octets());
                bytes.extend((packet.len() as u32).to_be_bytes());
                bytes.extend([0, 0, 0, 6]);
            }
            _ => panic!("mixed addresses in reference"),
        }
        bytes.extend(packet);
        let mut sum = 0u64;
        for (index, byte) in bytes.into_iter().enumerate() {
            sum += (byte as u64) << if index % 2 == 0 { 8 } else { 0 };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn seal(ip: IpMetadata, packet: &mut [u8]) {
        packet[16..18].fill(0);
        let sum = reference(ip, packet);
        packet[16..18].copy_from_slice(&sum.to_be_bytes());
    }

    fn packet(ip: IpMetadata, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20 + options.len().div_ceil(4) * 4 + payload.len()];
        encode(ip, header(), options, payload, &mut bytes).unwrap();
        bytes
    }

    fn parse_error(ip: IpMetadata, bytes: &[u8], error: WireError) {
        assert_eq!(parse(ip, bytes).err(), Some(error));
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# The sender MUST generate it (MUST-2) and the receiver MUST check it
    //# (MUST-3).
    #[test]
    fn checksum_reference_and_round_trip() {
        for ip in ips() {
            for payload in [&b""[..], &b"a"[..], &b"ab"[..], &b"abc"[..]] {
                let options = [1, 2, 4, 0x05, 0xb4, 3, 3, 14];
                let bytes = packet(ip, &options, payload);
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# The checksum field is the 16-bit ones' complement of the ones'
                //# complement sum of all 16-bit words in the header and text.
                assert_eq!(reference(ip, &bytes), 0);
                assert_eq!(checksum(ip, &bytes), Ok(0));
                let parsed = parse(ip, &bytes).unwrap();
                // The round trip includes window 0xfedc, above the signed 16-bit range.
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# The window size MUST be treated as an unsigned number, or else large
                //# window sizes will appear like negative windows and TCP will not work
                //# (MUST-1).
                assert_eq!(parsed.header, header());
                assert_eq!(parsed.raw_options, options);
                assert_eq!(
                    parsed.options,
                    Options {
                        mss: Some(1460),
                        window_scale: Some(14),
                        ..Options::default()
                    }
                );
                // Odd and even payloads have a valid independent checksum and no
                // transmitted pad byte.
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# If a segment contains an odd number of header and text octets, alignment
                //# can be achieved by padding the last octet with zeros on its right to
                //# form a 16-bit word for checksum purposes. The pad is not transmitted as
                //# part of the segment.
                assert_eq!(parsed.payload, payload);
                assert_eq!(parsed.payload.as_ptr(), bytes[28..].as_ptr());
                for index in 0..bytes.len() {
                    let mut corrupt = bytes.clone();
                    corrupt[index] ^= 1;
                    assert_ne!(checksum(ip, &corrupt), Ok(0));
                    assert!(parse(ip, &corrupt).is_err());
                }
                // IPv4 and IPv6 reference checksums cover both pseudo-header addresses.
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# The checksum also covers a pseudo-header (Figure 2) conceptually
                //# prefixed to the TCP header. The pseudo-header is 96 bits for IPv4 and
                //# 320 bits for IPv6.
                for source in [true, false] {
                    let mut wrong = ip;
                    let addr = if source {
                        &mut wrong.source
                    } else {
                        &mut wrong.destination
                    };
                    *addr = match *addr {
                        IpAddr::V4(_) => Ipv4Addr::new(192, 0, 2, 99).into(),
                        IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
                    };
                    parse_error(wrong, &bytes, WireError::InvalidChecksum);
                }
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# The number of 32-bit words in the TCP header. This indicates where the data begins.
    //# The TCP header (even one including options) is an integer multiple of 32 bits long.
    fn all_offsets_and_truncations() {
        let ip = ips()[0];
        let mut bytes = packet(ip, &[1; 40], &[]);
        for end in 0..bytes.len() {
            parse_error(ip, &bytes[..end], WireError::Truncated);
        }
        for offset in 0..=15 {
            bytes[12] = offset << 4;
            seal(ip, &mut bytes);
            if offset < 5 {
                parse_error(ip, &bytes, WireError::InvalidHeader);
            } else {
                let parsed = parse(ip, &bytes).unwrap();
                assert_eq!(parsed.raw_options.len(), (offset as usize - 5) * 4);
                assert_eq!(parsed.payload.len(), 60 - offset as usize * 4);
            }
        }
        for offset in 6..=15 {
            let mut short = packet(ip, &[], &[]);
            short[12] = offset << 4;
            seal(ip, &mut short);
            parse_error(ip, &short, WireError::Truncated);
        }
    }

    // Selection and every rebuild write options through write_options: one
    // layout per set, TSval and TSecr 32-bit aligned, padding by NOPs.
    #[test]
    fn written_options_keep_one_aligned_layout() {
        let cookie = FastOpenCookie::new(&[9, 8, 7, 6]).unwrap();
        let cases: [(Options, &[u8]); 5] = [
            (
                Options {
                    mss: Some(1460),
                    sack_permitted: true,
                    timestamps: Some((7, 0)),
                    window_scale: Some(7),
                    ..Options::default()
                },
                &[
                    2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 0, 1, 3, 3, 7,
                ],
            ),
            (
                Options {
                    mss: Some(536),
                    sack_permitted: true,
                    window_scale: Some(0),
                    fast_open: Some(cookie),
                    ..Options::default()
                },
                &[2, 4, 2, 24, 1, 1, 4, 2, 1, 3, 3, 0, 34, 6, 9, 8, 7, 6, 1, 1],
            ),
            (
                Options {
                    timestamps: Some((1, 2)),
                    ..Options::default()
                },
                &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2],
            ),
            (
                Options {
                    timestamps: Some((1, 2)),
                    sack_blocks: [Some((10, 20)), Some((30, 40)), Some((50, 60)), None],
                    ..Options::default()
                },
                &[
                    1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1, 5, 26, 0, 0, 0, 10, 0, 0, 0, 20, 0,
                    0, 0, 30, 0, 0, 0, 40, 0, 0, 0, 50, 0, 0, 0, 60,
                ],
            ),
            (
                Options {
                    sack_blocks: [Some((10, 20)); 4],
                    ..Options::default()
                },
                &[
                    1, 1, 5, 34, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 10,
                    0, 0, 0, 20, 0, 0, 0, 10, 0, 0, 0, 20,
                ],
            ),
        ];
        for (set, layout) in cases {
            let mut out = [0xff; 40];
            let n = write_options(&set, &mut out);
            assert_eq!(&out[..n], layout);
            assert_eq!(n % 4, 0);
            // Read back (as on a SYN, which alone may carry them all), the
            // set is the one written.
            assert_eq!(walk_options(&out[..n], true).unwrap(), set);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# A TCP implementation MUST (MUST-6) ignore without error any TCP
    //# Option it does not implement, assuming that the option has a length
    //# field.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
    //= type=test
    //# There is no guarantee that senders will use this option, so receivers MUST
    //# be prepared to process options even if they do not begin on a word
    //# boundary (MUST-64).
    #[test]
    fn option_alignment_unknowns_and_input_tolerance() {
        let ip = ips()[0];
        // Assertions cover NOP traversal, MSS decoding, and zero padding; EOL termination
        // is checked below.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //= type=test
        //# A given TCP implementation can support any currently defined options, but the
        //# following options MUST be supported (MUST-4 -- note Maximum Segment Size Option
        //# support is also part of MUST-14 in Section 3.7.1):
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //= type=test
        //# Case 1: A single octet of option-kind.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //= type=test
        //# The option-length counts the two octets of option-kind and option-
        //# length as well as the option-data octets.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
        //= type=test
        //# Length: 1 byte; Length == 4.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
        //= type=test
        //# Maximum Segment Size (MSS): 2 bytes.
        for prefix in 0..4 {
            let mut options = vec![1; prefix];
            options.extend([254, 3, 77, 2, 4, 0x12, 0x34, 3, 3, 7]);
            let bytes = packet(ip, &options, b"payload");
            let parsed = parse(ip, &bytes).unwrap();
            assert_eq!(
                parsed.options,
                Options {
                    mss: Some(0x1234),
                    window_scale: Some(7),
                    ..Options::default()
                }
            );
            assert!(
                parsed.raw_options[options.len()..]
                    .iter()
                    .all(|&byte| byte == 0)
            );
        }
        // Exercises options on a non-SYN segment, not all TCP state/flag combinations.
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
        //= type=test
        //# A TCP implementation MUST be able to receive a TCP Option in any segment
        //# (MUST-5).
        for scale in [0, 14, 15, 255] {
            let mut bytes = packet(ip, &[2, 4, 0, 0, 3, 3, 0], &[]);
            bytes[26] = scale;
            // Parsing succeeds with reserved input bits set; output zeroing is asserted in
            // the padding test.
            //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
            //= type=test
            //# Must be zero in generated segments and must be ignored in received segments
            //# if the corresponding future features are not implemented by the sending or
            //# receiving host.
            bytes[12] |= 0x0f;
            bytes[13] = ACK | FIN | RST | PSH | URG;
            seal(ip, &mut bytes);
            let parsed = parse(ip, &bytes).unwrap();
            assert_eq!(parsed.options.mss, Some(0));
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
            //= type=test
            //= reason=Parser clamps peer exponent to 14; local exponent search bounded 0..=14. Erratum 5585 is editorial; rejected 5586 does not replace the <2^30 requirement.
            //# Thus, the shift count
            //# MUST be limited to 14 (which allows windows of 2^30 = 1 GiB).
            //= https://www.rfc-editor.org/rfc/rfc7323#section-2.3
            //= type=test
            //= reason=Parser preserves one invalid raw exponent for the bounded connection diagnostic while keeping the effective WS clamp at 14. Wire 15/255 vectors and connection event coalescing test the notification path.
            //# If a
            //# Window Scale option is received with a shift.cnt value larger than
            //# 14, the TCP SHOULD log the error but MUST use 14 instead of the
            //# specified value.
            assert_eq!(parsed.options.window_scale, Some(scale.min(14)));
            assert_eq!(
                parsed.options.invalid_window_scale,
                (scale > 14).then_some(scale)
            );
            assert_eq!(parsed.header.flags, ACK | FIN | RST | PSH | URG);
        }
        let mut bytes = packet(ip, &[0; 4], &[]);
        bytes[21..24].copy_from_slice(&[2, 255, 255]);
        seal(ip, &mut bytes);
        //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
        //= type=test
        //# This option code indicates the end of the option list.
        assert_eq!(parse(ip, &bytes).unwrap().options, Options::default());
        assert_eq!(parse(ip, &bytes).unwrap().raw_options, [0, 2, 255, 255]);
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# TCP implementations MUST be prepared to handle
    //# an illegal option length (e.g., zero); a suggested procedure is to
    //# reset the connection and log the error cause (MUST-7).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
    //= type=test
    //# This field may be sent in the initial connection request (i.e., in
    //# segments with the SYN control bit set) and MUST NOT be sent in other
    //# segments (MUST-65).
    #[test]
    // Missing, undersized, and overrunning length fields are rejected for known and
    // unknown options.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# All TCP Options except End of Option List Option (EOL) and No-Operation (NOP) MUST
    //# have length fields, including all future options (MUST-68).
    fn malformed_options_and_atomic_output_errors() {
        let ip = ips()[0];
        for raw in [
            &b"\x02"[..],
            &b"\x03"[..],
            &b"\xfe"[..],
            &b"\xfe\x00"[..],
            &b"\xfe\x01"[..],
            &b"\xfe\x05\x00\x00"[..],
            &b"\x02\x03\x00"[..],
            &b"\x02\x05\x00\x00\x00"[..],
            &b"\x03\x02"[..],
            &b"\x03\x04\x00\x00"[..],
        ] {
            assert_eq!(read_options(raw, false), Err(WireError::InvalidOption));
            let mut out = [0xa5; 80];
            assert_eq!(
                encode(ip, header(), raw, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            assert_eq!(out, [0xa5; 80]);
            // Put the malformed option at the very end, avoiding padding that
            // could turn a truncated option into a valid one.
            let prefix = (4 - raw.len() % 4) % 4;
            let mut bytes = packet(ip, &vec![1; prefix + raw.len()], &[]);
            bytes[20 + prefix..].copy_from_slice(raw);
            seal(ip, &mut bytes);
            parse_error(ip, &bytes, WireError::InvalidOption);
        }
        for raw in [&[0, 1][..], &[3, 3, 15][..], &[3, 3, 255][..]] {
            let mut out = [0xa5; 80];
            assert_eq!(
                encode(ip, header(), raw, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            assert_eq!(out, [0xa5; 80]);
        }
        for raw in [&[2, 4, 5, 180][..], &[3, 3, 0][..]] {
            let mut out = [0xa5; 80];
            let mut h = header();
            h.flags = ACK;
            assert_eq!(
                encode(ip, h, raw, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            assert_eq!(out, [0xa5; 80]);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= type=test
    //# The content of the header beyond the End of Option List Option MUST
    //# be header padding of zeros (MUST-69).
    #[test]
    fn output_padding_capacity_and_max_options() {
        for ip in ips() {
            for option_len in 0..=40 {
                let options = vec![1; option_len];
                let expected = 20 + option_len.div_ceil(4) * 4 + 3;
                for capacity in 0..expected {
                    let mut out = vec![0xa5; capacity];
                    assert_eq!(
                        encode(ip, header(), &options, b"odd", &mut out),
                        Err(WireError::OutputTooSmall)
                    );
                    assert!(out.iter().all(|&byte| byte == 0xa5));
                }
                let mut out = vec![0xa5; expected + 8];
                assert_eq!(
                    encode(ip, header(), &options, b"odd", &mut out),
                    Ok(expected)
                );
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# Must be zero in generated segments and must be ignored in received
                //# segments if the corresponding future features are not implemented by the
                //# sending or receiving host.
                assert_eq!(out[12] & 0x0f, 0);
                // The output started nonzero, including the checksum field.
                //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
                //= type=test
                //# While computing the checksum, the checksum field itself is replaced with zeros.
                let encoded_sum = u16::from_be_bytes([out[16], out[17]]);
                let mut zeroed = out[..expected].to_vec();
                zeroed[16..18].fill(0);
                assert_eq!(encoded_sum, reference(ip, &zeroed));
                assert_eq!(reference(ip, &out[..expected]), 0);
                assert_eq!(&out[expected..], &[0xa5; 8]);
                let parsed = parse(ip, &out[..expected]).unwrap();
                assert_eq!(&parsed.raw_options[..option_len], &options);
                assert!(
                    parsed.raw_options[option_len..]
                        .iter()
                        .all(|&byte| byte == 0)
                );
                assert_eq!(parsed.payload, b"odd");
            }
        }
        let mut out = [0xa5; 80];
        assert_eq!(
            encode(ips()[0], header(), &[1; 41], &[], &mut out),
            Err(WireError::TooLong)
        );
        assert_eq!(out, [0xa5; 80]);
    }

    #[test]
    fn wide_sums_match_the_word_reference_at_every_length_and_alignment() {
        let mut state = 0x2545_f491_u32;
        let bytes: Vec<u8> = (0..1600)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        for ip in ips() {
            for start in 0..4 {
                for len in (0..300).chain([1459, 1460, 1461, 1595]) {
                    let segment = &bytes[start..start + len];
                    assert_eq!(checksum(ip, segment), Ok(reference(ip, segment)));
                }
            }
        }
    }

    #[test]
    fn length_limits_address_families_and_long_sums() {
        let [v4, v6] = ips();
        for len in [0, 1, 2, 65515, 65516, 65535, 65536, 131073, 262144] {
            let bytes = vec![0xff; len];
            assert_eq!(checksum(v6, &bytes), Ok(reference(v6, &bytes)));
            if len <= 65515 {
                assert_eq!(checksum(v4, &bytes), Ok(reference(v4, &bytes)));
            } else {
                assert_eq!(checksum(v4, &bytes), Err(WireError::TooLong));
                parse_error(v4, &bytes, WireError::TooLong);
            }
        }
        for ip in [v4, v6] {
            let payload = vec![0xff; if ip == v4 { 65495 } else { 131053 }];
            let bytes = packet(ip, &[], &payload);
            assert_eq!(reference(ip, &bytes), 0);
            assert_eq!(parse(ip, &bytes).unwrap().payload, payload);
        }
        let mut out = [0xa5; 80];
        assert_eq!(
            encode(v4, header(), &[], &vec![0; 65496], &mut out),
            Err(WireError::TooLong)
        );
        assert_eq!(out, [0xa5; 80]);
        assert_eq!(checked_length(v6, u32::MAX as usize), Ok(u32::MAX));
        if let Some(too_long) = (u32::MAX as usize).checked_add(1) {
            assert_eq!(checked_length(v6, too_long), Err(WireError::TooLong));
        }
        for mixed in [
            IpMetadata {
                source: v4.source,
                destination: v6.destination,
            },
            IpMetadata {
                source: v6.source,
                destination: v4.destination,
            },
        ] {
            assert_eq!(checksum(mixed, &[]), Err(WireError::AddressFamily));
            parse_error(mixed, &[0; 20], WireError::AddressFamily);
            assert_eq!(
                encode(mixed, header(), &[], &[], &mut out),
                Err(WireError::AddressFamily)
            );
            assert_eq!(out, [0xa5; 80]);
        }
    }
    fn sack_option(blocks: &[(u32, u32)]) -> Vec<u8> {
        let mut raw = vec![5, (8 * blocks.len() + 2) as u8];
        for &(left, right) in blocks {
            raw.extend(left.to_be_bytes());
            raw.extend(right.to_be_bytes());
        }
        raw
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Codec decodes two full-width big-endian u32 edges per block and preserves wire order, including wrapping values.
    //# Each contiguous block of data queued at the data receiver is defined in the
    //# SACK option by two 32-bit unsigned integers in network byte order:
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=One through four blocks retain full edges across alignment offsets, IPv4/IPv6 and independent checksum checks.
    //# A SACK option that specifies n blocks will have a length of 8*n+2 bytes, so
    //# the 40 bytes available for TCP options can specify a maximum of 4 blocks. It
    //# is expected that SACK will often be used in conjunction with the Timestamp
    //# option used for RTTM [Jacobson92], which takes an additional 10 bytes (plus
    //# two bytes of padding); thus a maximum of 3 SACK blocks will be allowed in
    //# this case.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Wire codec recognizes the specified option kind; tests parse literal raw kind bytes and round-trip them.
    //# Kind: 5
    fn sack_round_trip_preserves_full_edges_and_dsack_order() {
        // First block below the cumulative ACK is deliberately left first (DSACK).
        let blocks = [
            (0x01234567, 0x89abcdef),
            (u32::MAX - 7, 8),
            (0xf1234567, 0xf2345678),
            (0, u32::MAX),
        ];
        for ip in ips() {
            for count in 1..=4 {
                for prefix in 0..4 {
                    let mut raw = vec![1; prefix];
                    raw.extend(sack_option(&blocks[..count]));
                    let mut h = header();
                    h.flags = ACK;
                    let mut out = [0xa5; 80];
                    let len = encode(ip, h, &raw, b"odd", &mut out).unwrap();
                    let parsed = parse(ip, &out[..len]).unwrap();
                    let mut expected = Options::default();
                    for (slot, &block) in expected.sack_blocks.iter_mut().zip(&blocks[..count]) {
                        *slot = Some(block);
                    }
                    assert_eq!(parsed.options, expected);
                    assert_eq!(&parsed.raw_options[..raw.len()], raw);
                    assert_eq!(parsed.payload, b"odd");
                    assert_eq!(reference(ip, &out[..len]), 0);
                    let mut small = vec![0xa5; len - 1];
                    assert_eq!(
                        encode(ip, h, &raw, b"odd", &mut small),
                        Err(WireError::OutputTooSmall)
                    );
                    assert!(small.iter().all(|&byte| byte == 0xa5));
                }
            }
        }
        // The wire codec does not decide whether zero-width or reversed ranges
        // are meaningful to the connection.
        let raw = sack_option(&[(7, 7), (9, 3)]);
        assert_eq!(
            read_options(&raw, false).unwrap().sack_blocks[..2],
            [Some((7, 7)), Some((9, 3))]
        );
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-2
    //= type=test
    //= reason=Output rejects kind 4 without SYN; parsing remains flag-independent.
    //# It MUST NOT be sent on non-SYN segments.
    //= https://www.rfc-editor.org/rfc/rfc2018#section-2
    //= type=test
    //= reason=Wire codec recognizes the specified option kind; tests parse literal raw kind bytes and round-trip them.
    //# Kind: 4
    fn sack_permitted_syn_only_on_output_and_idempotent() {
        let raw = [4, 2, 4, 2];
        for ip in ips() {
            let mut bytes = packet(ip, &raw, &[]);
            assert!(parse(ip, &bytes).unwrap().options.sack_permitted);
            bytes[13] = ACK;
            seal(ip, &mut bytes);
            assert!(parse(ip, &bytes).unwrap().options.sack_permitted);
            let mut h = header();
            h.flags = ACK;
            let mut out = [0xa5; 80];
            assert_eq!(
                encode(ip, h, &raw, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            assert_eq!(out, [0xa5; 80]);
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-2
    //= type=test
    //= reason=Kind 4 accepts exactly length 2; malformed lengths/truncation are rejected. SYN authorization is separately cited.
    //# This two-byte option may be sent in a SYN by a TCP that has been extended to
    //# receive (and presumably process) the SACK option once the connection has
    //# opened.
    fn sack_malformed_lengths_truncation_and_repeated_option() {
        let ip = ips()[0];
        let mut malformed = vec![
            vec![4],
            vec![4, 0],
            vec![4, 1],
            vec![4, 3, 0],
            vec![5],
            vec![5, 2],
        ];
        for len in [3, 9, 11, 18, 26, 34] {
            let mut raw = vec![5, len];
            raw.resize(
                if len % 8 == 2 {
                    len as usize - 1
                } else {
                    len as usize
                },
                1,
            );
            malformed.push(raw);
        }
        let block = sack_option(&[(1, 2)]);
        let mut repeated = block.clone();
        repeated.extend(&block);
        malformed.push(repeated);
        for raw in malformed {
            for outgoing in [false, true] {
                assert_eq!(read_options(&raw, outgoing), Err(WireError::InvalidOption));
            }
            let mut out = [0xa5; 80];
            assert_eq!(
                encode(ip, header(), &raw, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            assert_eq!(out, [0xa5; 80]);
            let prefix = (4 - raw.len() % 4) % 4;
            let mut bytes = packet(ip, &vec![1; prefix + raw.len()], &[]);
            bytes[20 + prefix..].copy_from_slice(&raw);
            seal(ip, &mut bytes);
            parse_error(ip, &bytes, WireError::InvalidOption);
        }
        let extra = sack_option(&[(1, 2); 5]);
        assert_eq!(read_options(&extra, false), Err(WireError::InvalidOption));
        let mut out = [0xa5; 80];
        assert_eq!(
            encode(ip, header(), &extra, &[], &mut out),
            Err(WireError::TooLong)
        );
        assert_eq!(out, [0xa5; 80]);
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc2018#section-3
    //= type=test
    //= reason=Parser accepts lengths 10/18/26/34; encoder 40-byte option cap admits 3 with padded timestamps and rejects 4.
    //# A SACK option that specifies n blocks will have a length of 8*n+2 bytes, so
    //# the 40 bytes available for TCP options can specify a maximum of 4 blocks. It
    //# is expected that SACK will often be used in conjunction with the Timestamp
    //# option used for RTTM [Jacobson92], which takes an additional 10 bytes (plus
    //# two bytes of padding); thus a maximum of 3 SACK blocks will be allowed in
    //# this case.
    fn sack_timestamp_option_budget() {
        let ip = ips()[0];
        for count in 1..=4 {
            let mut raw = vec![1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9];
            raw.extend(sack_option(&[(u32::MAX, 1); 4][..count]));
            let mut out = [0xa5; 80];
            let mut h = header();
            h.flags = ACK;
            if count == 4 {
                assert_eq!(encode(ip, h, &raw, &[], &mut out), Err(WireError::TooLong));
                assert_eq!(out, [0xa5; 80]);
            } else {
                let len = encode(ip, h, &raw, &[], &mut out).unwrap();
                let parsed = parse(ip, &out[..len]).unwrap();
                assert_eq!(parsed.options.timestamps, Some((7, 9)));
                assert_eq!(parsed.options.sack_blocks.iter().flatten().count(), count);
                assert!(parsed.raw_options.len() <= 40);
                if count == 3 {
                    assert_eq!(parsed.raw_options.len(), 40);
                }
            }
        }
    }

    // The aligned-timestamp fast path reads what the walk reads: every
    // single-byte change, truncation and extension of the aligned layout,
    // and random option bytes seeded with it, in both directions.
    #[test]
    fn aligned_timestamp_fast_path_matches_the_walk() {
        let aligned = [1, 1, 8, 10, 0x80, 1, 2, 3, 0xff, 4, 5, 6];
        let check = |raw: &[u8]| {
            for outgoing in [false, true] {
                assert_eq!(
                    read_options(raw, outgoing),
                    walk_options(raw, outgoing),
                    "{raw:?} {outgoing}"
                );
            }
        };
        let mut fast = 0;
        for at in 0..aligned.len() {
            for value in 0..=255u8 {
                let mut raw = aligned;
                raw[at] = value;
                check(&raw);
                fast += usize::from(raw[..4] == [1, 1, 8, 10]);
            }
        }
        for len in 0..=40 {
            let mut raw = vec![0; len];
            for (i, byte) in raw.iter_mut().enumerate() {
                *byte = *aligned.get(i).unwrap_or(&1);
            }
            check(&raw);
            raw.iter_mut().skip(12).for_each(|byte| *byte = 0);
            check(&raw);
        }
        let mut state = 0x2545_f491_u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..200_000 {
            let seeded = next() % 2 == 0;
            // Seeded options keep the aligned length half the time.
            let len = if seeded && next() % 2 == 0 {
                12
            } else {
                next() as usize % 41
            };
            let mut raw: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if seeded {
                let n = len.min(12);
                raw[..n].copy_from_slice(&aligned[..n]);
                // A few bytes changed, often a small option kind or length.
                for _ in 0..next() % 3 {
                    let at = next() as usize % len.max(1);
                    if at < len {
                        raw[at] = if next() % 2 == 0 {
                            next() as u8 % 12
                        } else {
                            next() as u8
                        };
                    }
                }
            }
            check(&raw);
            fast += usize::from(raw.len() == 12 && raw[..4] == [1, 1, 8, 10]);
        }
        assert!(fast > 20_000, "{fast}");
    }

    #[test]
    fn sack_parser_deterministic_bounds() {
        // Exhaust declared lengths against every available bounded option size.
        for kind in [4, 5] {
            for len in 0..=255u8 {
                for available in 2..=40 {
                    let mut raw = vec![1; available];
                    raw[0] = kind;
                    raw[1] = len;
                    let valid = len as usize <= available
                        && if kind == 4 {
                            len == 2
                        } else {
                            (10..=34).contains(&len) && (len - 2) % 8 == 0
                        };
                    for outgoing in [false, true] {
                        assert_eq!(read_options(&raw, outgoing).is_ok(), valid);
                    }
                }
            }
        }
        // Mixed arbitrary options, with checksum repaired so parsing reaches them.
        let ip = ips()[0];
        let mut state = 0x12345678u32;
        for size in 0..=40 {
            for _ in 0..64 {
                let mut bytes = packet(ip, &vec![1; size], &[]);
                for byte in &mut bytes[20..] {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    *byte = (state >> 24) as u8;
                }
                seal(ip, &mut bytes);
                let decoded = read_options(&bytes[20..], false);
                assert_eq!(parse(ip, &bytes).map(|segment| segment.options), decoded);
            }
        }
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
    //= type=test
    //= reason=TS parser/output literal kind 8.
    //# Kind: 8
    //= https://www.rfc-editor.org/rfc/rfc7323#section-3.2
    //= type=test
    //= reason=TS has two four-byte fields plus kind/length, padding external to length.
    //# Length: 10 bytes
    fn timestamp_option_parses_and_rejects_malformed_or_duplicate_values() {
        let option = [8, 10, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 7];
        assert_eq!(
            read_options(&option, false).unwrap().timestamps,
            Some((u32::MAX, 7))
        );
        assert_eq!(
            read_options(&option[..9], false),
            Err(WireError::InvalidOption)
        );
        assert_eq!(read_options(&[8, 2], false), Err(WireError::InvalidOption));
        let mut duplicate = option.to_vec();
        duplicate.extend_from_slice(&option);
        assert_eq!(
            read_options(&duplicate, false),
            Err(WireError::InvalidOption)
        );
    }

    fn fast_open_option(cookie: &[u8]) -> Vec<u8> {
        let mut raw = vec![34, (cookie.len() + 2) as u8];
        raw.extend_from_slice(cookie);
        raw
    }

    // Bypass output validation, placing raw options at the end of the header
    // so zero padding cannot hide a truncated TLV.
    fn incoming_options(ip: IpMetadata, raw: &[u8], flags: u8) -> Vec<u8> {
        let prefix = (4 - raw.len() % 4) % 4;
        let mut bytes = packet(ip, &vec![1; prefix + raw.len()], b"odd");
        bytes[20 + prefix..20 + prefix + raw.len()].copy_from_slice(raw);
        bytes[13] = flags;
        seal(ip, &mut bytes);
        bytes
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //= type=test
    //# The minimum cookie size is 4 bytes.
    #[test]
    fn fast_open_cookie_checked_value() {
        fn assert_value_traits<T: Copy + Eq + core::fmt::Debug>() {}
        assert_value_traits::<FastOpenCookie>();
        assert_value_traits::<Options>();
        assert_eq!(FastOpenCookie::request().as_bytes(), &[]);
        assert_eq!(FastOpenCookie::new(&[]), Ok(FastOpenCookie::request()));
        for len in 0..=64 {
            let bytes = vec![0xa5; len];
            let cookie = FastOpenCookie::new(&bytes);
            if len == 0 || ((4..=16).contains(&len) && len % 2 == 0) {
                assert_eq!(cookie.unwrap().as_bytes(), bytes);
                let copy = cookie.unwrap();
                assert_eq!(copy, FastOpenCookie::new(&bytes).unwrap());
            } else {
                assert_eq!(cookie, Err(WireError::InvalidOption));
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //= type=test
    //= reason=Verified erratum 4238 permits empty requests of Length 2; the original table is retained and the corrected behavior is asserted.
    //# Kind 1 byte: value = 34 Length 1 byte: range 6 to 18 (bytes); limited by remaining space in the
    //# options field. The number MUST be even. Cookie 0, or 4 to 16 bytes (Length - 2)
    //= https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1
    //= type=test
    //# Although the diagram shows a cookie aligned on 32-bit boundaries, alignment is not required.
    #[test]
    fn fast_open_ipv4_ipv6_round_trip_and_syn_only() {
        for ip in ips() {
            for cookie_len in [0, 4, 6, 8, 10, 12, 14, 16] {
                let cookie: Vec<u8> = (0..cookie_len).collect();
                let option = fast_open_option(&cookie);
                assert_eq!(option[1] as usize, cookie.len() + 2);
                for prefix in 0..4 {
                    let mut raw = vec![1; prefix];
                    raw.extend_from_slice(&option);
                    for flags in [SYN, SYN | ACK] {
                        let mut h = header();
                        h.flags = flags;
                        let mut out = [0xa5; 80];
                        let len = encode(ip, h, &raw, b"odd", &mut out).unwrap();
                        assert_eq!(reference(ip, &out[..len]), 0);
                        let parsed = parse(ip, &out[..len]).unwrap();
                        assert_eq!(parsed.header, h);
                        assert_eq!(
                            parsed.options.fast_open,
                            Some(FastOpenCookie::new(&cookie).unwrap())
                        );
                        assert_eq!(&parsed.raw_options[..raw.len()], raw);
                        assert_eq!(parsed.payload, b"odd");
                    }
                }
                for flags in [0, ACK, FIN | ACK, RST] {
                    let bytes = incoming_options(ip, &option, flags);
                    assert_eq!(parse(ip, &bytes).unwrap().options.fast_open, None);
                    let mut h = header();
                    h.flags = flags;
                    let mut out = [0xa5; 80];
                    assert_eq!(
                        encode(ip, h, &option, &[], &mut out),
                        Err(WireError::InvalidOption)
                    );
                    assert_eq!(out, [0xa5; 80]);
                }
            }
        }
    }

    #[test]
    fn fast_open_invalid_bounded_lengths_ignored() {
        for ip in ips() {
            for len in 2..=36 {
                if matches!(len, 2 | 6 | 8 | 10 | 12 | 14 | 16 | 18) {
                    continue;
                }
                let mut raw = vec![0xa5; len];
                raw[..2].copy_from_slice(&[34, len as u8]);
                // Ignoring kind 34 must still reach a subsequent valid option.
                raw.extend_from_slice(&[2, 4, 5, 180]);
                for flags in [SYN, ACK] {
                    let bytes = incoming_options(ip, &raw, flags);
                    let parsed = parse(ip, &bytes).unwrap();
                    assert_eq!(parsed.options.fast_open, None);
                    assert_eq!(parsed.options.mss, Some(1460));
                    assert_eq!(parsed.payload, b"odd");
                }
                let mut out = [0xa5; 80];
                assert_eq!(
                    encode(ip, header(), &raw, &[], &mut out),
                    Err(WireError::InvalidOption)
                );
                assert_eq!(out, [0xa5; 80]);
            }
        }
    }

    #[test]
    fn fast_open_tlv_bounds_and_truncation() {
        for declared in 0..=255u8 {
            for available in 1..=40 {
                let mut raw = vec![1; available];
                raw[0] = 34;
                if available > 1 {
                    raw[1] = declared;
                }
                let parsed = read_options(&raw, false).unwrap();
                let bounded = available > 1 && declared >= 2 && declared as usize <= available;
                let valid = bounded && matches!(declared, 2 | 6 | 8 | 10 | 12 | 14 | 16 | 18);
                assert_eq!(parsed.fast_open.is_some(), valid);
                assert_eq!(read_options(&raw, true).is_ok(), valid);
                for ip in ips() {
                    for flags in [SYN, ACK] {
                        let bytes = incoming_options(ip, &raw, flags);
                        let segment = parse(ip, &bytes).unwrap();
                        assert_eq!(
                            segment.options.fast_open.is_some(),
                            valid && flags & SYN != 0
                        );
                        assert_eq!(segment.payload, b"odd");
                    }
                    let mut out = [0xa5; 80];
                    let result = encode(ip, header(), &raw, b"odd", &mut out);
                    assert_eq!(result.is_ok(), valid);
                    if !valid {
                        assert_eq!(out, [0xa5; 80]);
                    }
                }
            }
        }
        for ip in ips() {
            for raw in [&[34][..], &[34, 0], &[34, 1], &[34, 6, 1, 2, 3], &[34, 255]] {
                for flags in [SYN, ACK] {
                    let bytes = incoming_options(ip, raw, flags);
                    let parsed = parse(ip, &bytes).unwrap();
                    assert_eq!(parsed.options.fast_open, None);
                    assert_eq!(parsed.payload, b"odd");
                }
                let mut out = [0xa5; 80];
                assert_eq!(
                    encode(ip, header(), raw, &[], &mut out),
                    Err(WireError::InvalidOption)
                );
                assert_eq!(out, [0xa5; 80]);
            }
            let bytes = packet(ip, &fast_open_option(&[0xa5; 16]), &[]);
            for end in 0..bytes.len() {
                parse_error(ip, &bytes[..end], WireError::Truncated);
            }
        }
    }

    #[test]
    fn fast_open_malformed_suffix_retains_prefix_and_payload_boundary() {
        let prefix = [2, 4, 5, 180, 3, 3, 7, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9];
        for ip in ips() {
            for suffix in [
                &[34][..],
                &[34, 0],
                &[34, 1],
                &[34, 6, 2, 4, 0],
                &[34, 255],
                // These apparent ordinary TLVs are an unframeable suffix,
                // not permission to replace validated prefix MSS/WS/SACK.
                &[34, 0, 2, 4, 0, 64, 3, 3, 9, 4, 2],
                &[34, 1, 2, 4, 0, 64, 3, 3, 9, 4, 2],
                &[34, 255, 2, 4, 0, 64, 3, 3, 9, 4, 2],
            ] {
                for prior_cookie in [false, true] {
                    let mut raw = prefix.to_vec();
                    if prior_cookie {
                        raw.extend_from_slice(&[34, 6, 1, 2, 3, 4]);
                    }
                    raw.extend_from_slice(suffix);
                    for flags in [SYN, SYN | ACK, ACK, FIN | ACK, RST] {
                        let bytes = incoming_options(ip, &raw, flags);
                        let parsed = parse(ip, &bytes).unwrap();
                        assert_eq!(parsed.options.fast_open, None);
                        assert_eq!(parsed.options.mss, Some(1460));
                        assert_eq!(parsed.options.window_scale, Some(7));
                        assert!(parsed.options.sack_permitted);
                        assert_eq!(parsed.options.timestamps, Some((7, 9)));
                        assert_eq!(parsed.payload, b"odd");
                        assert_eq!(parsed.raw_options.len(), (raw.len() + 3) / 4 * 4);
                        let mut bad = bytes.clone();
                        *bad.last_mut().unwrap() ^= 1;
                        parse_error(ip, &bad, WireError::InvalidChecksum);
                        bad = bytes.clone();
                        bad[12] = 4 << 4;
                        seal(ip, &mut bad);
                        parse_error(ip, &bad, WireError::InvalidHeader);
                        bad[12] = 15 << 4;
                        seal(ip, &mut bad);
                        parse_error(ip, &bad, WireError::Truncated);
                    }
                    let mut out = [0xa5; 100];
                    assert_eq!(
                        encode(ip, header(), &raw, b"odd", &mut out),
                        Err(WireError::InvalidOption)
                    );
                    assert_eq!(out, [0xa5; 100]);
                }
            }
            // The tolerance is specific to Kind 34, including after a valid TS.
            for suffix in [&[2, 3, 0][..], &[8, 0], &[254, 255]] {
                let mut raw = prefix.to_vec();
                raw.extend_from_slice(suffix);
                parse_error(
                    ip,
                    &incoming_options(ip, &raw, SYN),
                    WireError::InvalidOption,
                );
            }
        }
    }

    #[test]
    fn fast_open_duplicates_discard_metadata_and_output_rejects() {
        let variants = [
            fast_open_option(&[]),
            fast_open_option(&[1; 4]),
            fast_open_option(&[2; 4]),
            fast_open_option(&[3]),
            vec![34],
            vec![34, 0],
            vec![34, 1],
            vec![34, 255],
        ];
        for ip in ips() {
            for first in &variants {
                for second in &variants {
                    let mut raw = first.clone();
                    raw.extend_from_slice(second);
                    // A third valid occurrence must not restore metadata.
                    for third in [false, true] {
                        if third {
                            raw.extend_from_slice(&[34, 2]);
                        }
                        let bytes = incoming_options(ip, &raw, SYN);
                        assert_eq!(parse(ip, &bytes).unwrap().options.fast_open, None);
                        let mut out = [0xa5; 80];
                        assert_eq!(
                            encode(ip, header(), &raw, &[], &mut out),
                            Err(WireError::InvalidOption)
                        );
                        assert_eq!(out, [0xa5; 80]);
                    }
                }
            }
        }
    }

    #[test]
    fn fast_open_option_budget() {
        for ip in ips() {
            let mut raw = fast_open_option(&[0xa5; 16]);
            raw.extend_from_slice(&[2, 4, 5, 180, 3, 3, 7, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9]);
            raw.resize(40, 1);
            let bytes = packet(ip, &raw, b"odd");
            let parsed = parse(ip, &bytes).unwrap();
            assert_eq!(parsed.raw_options.len(), 40);
            assert_eq!(parsed.options.fast_open.unwrap().as_bytes(), &[0xa5; 16]);
            assert_eq!(parsed.options.mss, Some(1460));
            assert_eq!(parsed.options.window_scale, Some(7));
            assert!(parsed.options.sack_permitted);
            assert_eq!(parsed.options.timestamps, Some((7, 9)));
            raw.push(1);
            let mut out = [0xa5; 80];
            assert_eq!(
                encode(ip, header(), &raw, &[], &mut out),
                Err(WireError::TooLong)
            );
            assert_eq!(out, [0xa5; 80]);
        }
    }

    #[test]
    fn encode_overwrites_dirty_buffer_and_pads_options() {
        let payload = b"hello-tcp";
        let aligned_ts = [1, 1, 8, 10, 0, 0, 1, 2, 0, 0, 3, 4];
        let cases: &[(&[u8], u8)] = &[
            (&[], ACK),
            (&[1], ACK),
            (&[1, 1], ACK),
            (&[1, 1, 1], ACK),
            (&aligned_ts, ACK),
            (&[8, 10, 0, 0, 1, 2, 0, 0, 3, 4], ACK),
            (&[2, 4, 5, 180], SYN),
        ];
        for ip in ips() {
            for &(opts, flags) in cases {
                let mut hdr = header();
                hdr.flags = flags;
                hdr.urgent_pointer = 0;

                let mut out = [0xffu8; 96];
                let len = encode(ip, hdr, opts, payload, &mut out).unwrap();
                let header_len = 20 + opts.len().div_ceil(4) * 4;
                assert_eq!(len, header_len + payload.len());
                assert_eq!(out[12], ((header_len / 4) as u8) << 4);
                assert_eq!(&out[18..20], &[0, 0]);
                assert!(out[20 + opts.len()..header_len].iter().all(|&b| b == 0));
                assert_eq!(checksum(ip, &out[..len]).unwrap(), 0);
                let parsed = parse(ip, &out[..len]).unwrap();
                assert_eq!(parsed.header, hdr);
                assert_eq!(parsed.payload, payload);
            }
        }
    }

    #[test]
    fn option_fast_paths_match_walk_and_output_validation() {
        let aligned_ts = [
            1u8, 1, 8, 10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let unaligned_ts = [
            8u8, 10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 1,
        ];
        let mss = [2u8, 4, 5, 180];
        let bad_ts = [1u8, 1, 8, 9, 0, 0, 0, 1, 0, 0, 0, 2];

        for &opts in &[
            &[][..],
            &aligned_ts[..],
            &unaligned_ts[..],
            &mss[..],
            &bad_ts[..],
        ] {
            for outgoing in [false, true] {
                assert_eq!(read_options(opts, outgoing), walk_options(opts, outgoing));
            }
        }

        for flags in [0, ACK, SYN, SYN | ACK] {
            assert_eq!(validate_output_options(flags, &[]), Ok(()));
            assert_eq!(validate_output_options(flags, &aligned_ts), Ok(()));
            assert_eq!(validate_output_options(flags, &unaligned_ts), Ok(()));
            assert_eq!(
                validate_output_options(flags, &bad_ts),
                Err(WireError::InvalidOption)
            );
            let expected_mss = if flags & SYN != 0 {
                Ok(())
            } else {
                Err(WireError::InvalidOption)
            };
            assert_eq!(validate_output_options(flags, &mss), expected_mss);
        }

        // Verify encode_with exercises the same rejection for MSS on non-SYN and acceptance on SYN.
        for ip in ips() {
            let mut out = [0u8; 64];
            let mut hdr = header();
            hdr.flags = ACK;
            assert_eq!(
                encode(ip, hdr, &mss, &[], &mut out),
                Err(WireError::InvalidOption)
            );
            hdr.flags = SYN;
            assert!(encode(ip, hdr, &mss, &[], &mut out).is_ok());
        }
    }

    #[test]
    fn encode_stream_matches_encode_with_across_options_lengths_partial_and_families() {
        let family_cases = [
            IpMetadata {
                source: Ipv4Addr::new(192, 0, 2, 1).into(),
                destination: Ipv4Addr::new(198, 51, 100, 2).into(),
            },
            IpMetadata {
                source: Ipv4Addr::new(255, 255, 255, 254).into(),
                destination: Ipv4Addr::new(255, 255, 255, 253).into(),
            },
            IpMetadata {
                source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
                destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).into(),
            },
            IpMetadata {
                source: Ipv6Addr::new(0xffff, 0xfffe, 0xabcd, 0x1234, 0x5678, 0x9abc, 0xdef0, 0xffff)
                    .into(),
                destination: Ipv6Addr::new(
                    0xffff, 0xffff, 0x4321, 0x8765, 0xcba9, 0x0fed, 0xffff, 0xfffe,
                )
                .into(),
            },
        ];
        let headers = [
            header(),
            Header {
                source_port: u16::MAX,
                destination_port: u16::MAX,
                sequence: u32::MAX,
                acknowledgment: u32::MAX,
                flags: ACK | PSH | FIN | URG | ECE | CWR,
                window: u16::MAX,
                urgent_pointer: u16::MAX,
            },
            Header {
                source_port: 80,
                destination_port: 54321,
                sequence: 0,
                acknowledgment: 0,
                flags: ACK,
                window: 0,
                urgent_pointer: 0,
            },
        ];
        let timestamp_cases = [
            None,
            Some((0u32, 0u32)),
            Some((0x1234_5678, 0x9abc_def0)),
            Some((u32::MAX, u32::MAX)),
        ];
        let payload_lens = [0, 1, 2, 3, 7, 15, 63, 64, 65, 127, 128, 129, 255, 1448, 1449];

        let mut payload_buf = [0u8; 1449];
        for (i, b) in payload_buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(53).wrapping_add(11);
        }

        for ip in family_cases {
            let pseudo = PseudoHeader::new(ip).unwrap();
            for hdr in headers {
                let ports = (u32::from(hdr.source_port) << 16) | u32::from(hdr.destination_port);
                for timestamps in timestamp_cases {
                    let mut opts = [0u8; 40];
                    let opt_len = write_options(
                        &Options {
                            timestamps,
                            ..Options::default()
                        },
                        &mut opts,
                    );
                    for &len in &payload_lens {
                        let payload = &payload_buf[..len];
                        for partial in [false, true] {
                            let mut expected = vec![0xa5; 32 + len];
                            let mut actual = vec![0x5a; 32 + len];
                            let expected_len = encode_with(
                                ip,
                                hdr,
                                &opts[..opt_len],
                                payload,
                                &mut expected,
                                partial,
                            )
                            .unwrap();
                            let actual_len = encode_stream(
                                pseudo,
                                ports,
                                hdr,
                                timestamps,
                                payload,
                                &mut actual,
                                partial,
                            )
                            .unwrap();
                            assert_eq!(actual_len, expected_len);
                            assert_eq!(&actual[..actual_len], &expected[..expected_len]);
                            if !partial {
                                let parsed = pseudo.parse(&actual[..actual_len], false).unwrap();
                                assert_eq!(parsed.header, hdr);
                                assert_eq!(parsed.options.timestamps, timestamps);
                                assert_eq!(parsed.payload, payload);
                            }
                        }
                    }
                }
            }
        }

        // Error paths: OutputTooSmall and TooLong
        let v4 = family_cases[0];
        let pseudo_v4 = PseudoHeader::new(v4).unwrap();
        let hdr = header();
        let ports = (u32::from(hdr.source_port) << 16) | u32::from(hdr.destination_port);
        let mut small = [0u8; 31];
        assert_eq!(
            encode_stream(pseudo_v4, ports, hdr, Some((1, 2)), &[], &mut small, false),
            Err(WireError::OutputTooSmall)
        );
        let oversize = vec![0u8; usize::from(u16::MAX) - 20];
        let mut big = vec![0u8; oversize.len() + 32];
        assert_eq!(
            encode_stream(pseudo_v4, ports, hdr, None, &oversize, &mut big, false),
            Err(WireError::TooLong)
        );
    }

    #[test]
    fn pseudo_header_parse_and_seed_validate_checksum_and_length() {
        let mixed = IpMetadata {
            source: Ipv4Addr::new(192, 0, 2, 1).into(),
            destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
        };
        assert_eq!(PseudoHeader::new(mixed).err(), Some(WireError::AddressFamily));

        for ip in ips() {
            let pseudo = PseudoHeader::new(ip).unwrap();
            let mut raw = [0u8; 64];
            let len = encode(ip, header(), &[], b"pseudo-parse-test", &mut raw).unwrap();

            let verified = pseudo.parse(&raw[..len], false).unwrap();
            assert_eq!(verified.header, header());
            assert_eq!(verified.payload, b"pseudo-parse-test");

            // Corrupt checksum: rejected when verified == false, accepted when verified == true.
            raw[16] ^= 0x01;
            assert_eq!(
                pseudo.parse(&raw[..len], false).err(),
                Some(WireError::InvalidChecksum)
            );
            let unchecked = pseudo.parse(&raw[..len], true).unwrap();
            assert_eq!(unchecked.header, header());
            assert_eq!(unchecked.payload, b"pseudo-parse-test");
        }

        // IPv4 length limit check (65535 - 20 = 65515 max TCP segment length).
        let v4 = ips()[0];
        let pseudo_v4 = PseudoHeader::new(v4).unwrap();
        let too_long = vec![0u8; usize::from(u16::MAX) - 20 + 1];
        assert_eq!(
            pseudo_v4.parse(&too_long, true).err(),
            Some(WireError::TooLong)
        );
        assert_eq!(
            pseudo_v4.parse(&too_long, false).err(),
            Some(WireError::TooLong)
        );
    }

    #[test]
    fn carries_sack_reflects_parsed_sack_blocks() {
        let ip = ips()[0];
        let pseudo = PseudoHeader::new(ip).unwrap();

        // No options
        let mut buf = [0u8; 80];
        let len = encode(ip, header(), &[], b"data", &mut buf).unwrap();
        assert!(!pseudo.parse(&buf[..len], false).unwrap().carries_sack());

        // Timestamps only
        let mut opts = [0u8; 40];
        let opt_len = write_options(
            &Options {
                timestamps: Some((10, 20)),
                ..Options::default()
            },
            &mut opts,
        );
        let len = encode(ip, header(), &opts[..opt_len], b"data", &mut buf).unwrap();
        assert!(!pseudo.parse(&buf[..len], false).unwrap().carries_sack());

        // SACK-permitted on SYN (no SACK blocks)
        let mut syn = header();
        syn.flags = SYN;
        let opt_len = write_options(
            &Options {
                sack_permitted: true,
                ..Options::default()
            },
            &mut opts,
        );
        let len = encode(ip, syn, &opts[..opt_len], &[], &mut buf).unwrap();
        assert!(!pseudo.parse(&buf[..len], false).unwrap().carries_sack());

        // 1..=4 SACK blocks (and 1..=3 with timestamps)
        for count in 1..=4usize {
            for with_ts in [false, true] {
                if with_ts && count == 4 {
                    continue;
                }
                let mut sack_blocks = [None; 4];
                for (i, slot) in sack_blocks[..count].iter_mut().enumerate() {
                    let base = 1000 + (i as u32) * 100;
                    *slot = Some((base, base + 50));
                }
                let opt_len = write_options(
                    &Options {
                        timestamps: with_ts.then_some((11, 22)),
                        sack_blocks,
                        ..Options::default()
                    },
                    &mut opts,
                );
                let len = encode(ip, header(), &opts[..opt_len], b"data", &mut buf).unwrap();
                let seg = pseudo.parse(&buf[..len], false).unwrap();
                assert!(seg.carries_sack());
                assert_eq!(seg.options.sack_blocks, sack_blocks);
            }
        }
    }

    #[test]
    fn encode_parts_and_stream_parts_match_encode_with_across_parts_families_partial_and_gather() {
        use crate::Payload;
        use ntcp_buffer::{ChunkSlice, PayloadSlice, TxChunk};

        let mut chunk = TxChunk::heap(256);
        let all_data: Vec<u8> = (0..180u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
        chunk.append(&all_data);
        let shared = Payload::from_vec(all_data.clone());

        let hdr = Header {
            source_port: 44321,
            destination_port: 8080,
            sequence: 0x1234_5678,
            acknowledgment: 0x9abc_def0,
            flags: ACK | PSH,
            window: 0x4321,
            urgent_pointer: 0,
        };
        let ports = (u32::from(hdr.source_port) << 16) | u32::from(hdr.destination_port);
        let ts = Some((0x1122_3344, 0x5566_7788));
        let mut ts_opts = [0u8; 40];
        let ts_len = write_options(
            &Options {
                timestamps: ts,
                ..Options::default()
            },
            &mut ts_opts,
        );
        let mut sack_opts = [0u8; 40];
        let sack_len = write_options(
            &Options {
                timestamps: ts,
                sack_blocks: [Some((100, 200)), Some((300, 450)), None, None],
                ..Options::default()
            },
            &mut sack_opts,
        );

        // Part-split cases: 0 parts, 1 part (even & odd), 2 parts (odd+odd, odd+even),
        // 3 parts (odd+odd+odd, mixed Chunk+Shared), plus empty interior part.
        let splits: &[&[(usize, usize, bool)]] = &[
            &[],
            &[(0, 16, false)],
            &[(0, 17, true)],
            &[(0, 3, false), (3, 10, true)],
            &[(0, 5, false), (5, 11, false)],
            &[(0, 1, false), (1, 4, true), (4, 15, false)],
            &[(0, 7, false), (7, 7, true), (7, 20, true), (20, 63, false)],
        ];

        for ip in ips() {
            let pseudo = PseudoHeader::new(ip).unwrap();
            for &split in splits {
                let mut parts = Vec::new();
                let mut flat = Vec::new();
                for &(start, end, is_shared) in split {
                    flat.extend_from_slice(&all_data[start..end]);
                    if is_shared {
                        parts.push(TxPart::Shared(PayloadSlice::new(&shared, start..end).unwrap()));
                    } else {
                        parts.push(TxPart::Chunk(ChunkSlice::new(&chunk, start..end).unwrap()));
                    }
                }
                let payload_len = flat.len();

                for &(opt_slice, stream_ts) in &[
                    (&[][..], Some(None)),
                    (&ts_opts[..ts_len], Some(ts)),
                    (&sack_opts[..sack_len], None),
                ] {
                    let header_len = 20 + opt_slice.len();
                    for partial in [false, true] {
                        let mut expected = vec![0u8; header_len + payload_len];
                        let exp_len =
                            encode_with(ip, hdr, opt_slice, &flat, &mut expected, partial).unwrap();
                        assert_eq!(exp_len, header_len + payload_len);

                        for gather in [false, true] {
                            let buf_len = if gather { exp_len } else { header_len };
                            let pass_parts: &[TxPart<'_>] = if partial && !gather {
                                &[]
                            } else {
                                &parts
                            };

                            let mut out = vec![0xaa; buf_len + 8];
                            let n = encode_parts_with(
                                ip,
                                hdr,
                                opt_slice,
                                pass_parts,
                                payload_len,
                                &mut out[..buf_len],
                                partial,
                                gather,
                            )
                            .unwrap();
                            assert_eq!(n, buf_len);
                            assert_eq!(&out[..buf_len], &expected[..buf_len]);
                            assert!(out[buf_len..].iter().all(|&b| b == 0xaa));

                            if let Some(ts_arg) = stream_ts {
                                let mut stream_out = vec![0x55; buf_len + 8];
                                let sn = encode_stream_parts(
                                    pseudo,
                                    ports,
                                    hdr,
                                    ts_arg,
                                    pass_parts,
                                    payload_len,
                                    &mut stream_out[..buf_len],
                                    partial,
                                    gather,
                                )
                                .unwrap();
                                assert_eq!(sn, buf_len);
                                assert_eq!(&stream_out[..buf_len], &expected[..buf_len]);
                                assert!(stream_out[buf_len..].iter().all(|&b| b == 0x55));
                            }
                        }
                    }

                    // Verify encode_header_zero_checksum matches header bytes except zeroed checksum.
                    let mut zero_out = vec![0xcc; header_len];
                    let zn = encode_header_zero_checksum(ip, hdr, opt_slice, &mut zero_out).unwrap();
                    assert_eq!(zn, header_len);
                    let mut ref_hdr = vec![0u8; header_len];
                    encode_with(ip, hdr, opt_slice, &[], &mut ref_hdr, true).unwrap();
                    ref_hdr[16..18].fill(0);
                    assert_eq!(zero_out, ref_hdr);
                }
            }
        }
    }
}
