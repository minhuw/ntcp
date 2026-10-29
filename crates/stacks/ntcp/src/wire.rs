use core::net::IpAddr;

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
fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    for word in bytes.chunks(2) {
        sum += u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]) as u32;
        // Fold each word so even the largest IPv6 segment cannot overflow.
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//# The checksum field is the 16-bit ones' complement of the ones' complement sum of all
//# 16-bit words in the header and text.
pub fn checksum(ip: IpMetadata, segment: &[u8]) -> Result<u16, WireError> {
    let len = checked_length(ip, segment.len())?;
    let mut sum = pseudo_header_sum(ip, len)?;
    // Only the segment's final octet can require virtual zero padding.
    sum = add_words(sum, segment);
    Ok(!(sum as u16))
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
//# The checksum also covers a pseudo-header (Figure 2) conceptually prefixed to the TCP
//# header. The pseudo-header is 96 bits for IPv4 and 320 bits for IPv6.
fn pseudo_header_sum(ip: IpMetadata, len: u32) -> Result<u32, WireError> {
    let mut sum = match (ip.source, ip.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            add_words(add_words(0, &source.octets()), &destination.octets())
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            add_words(add_words(0, &source.octets()), &destination.octets())
        }
        _ => return Err(WireError::AddressFamily),
    };
    // Each pseudo-header chunk is even-sized, so none needs virtual zero
    // padding. The extra IPv4 length word is zero.
    sum = add_words(sum, &len.to_be_bytes());
    sum = add_words(sum, &[0, 6]);
    Ok(sum)
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
fn read_options(mut bytes: &[u8], outgoing: bool) -> Result<Options, WireError> {
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

pub fn parse(ip: IpMetadata, bytes: &[u8]) -> Result<Segment<'_>, WireError> {
    checked_length(ip, bytes.len())?;
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
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# and the receiver MUST check it (MUST-3).
    if checksum(ip, bytes)? != 0 {
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
    if options.len() > 40 {
        return Err(WireError::TooLong);
    }
    let parsed_options = read_options(options, true)?;
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
    //# This field may be sent in the initial connection request (i.e., in
    //# segments with the SYN control bit set) and MUST NOT be sent in other
    //# segments (MUST-65).
    // RFC 2018 section 2: "It MUST NOT be sent on non-SYN segments."
    if header.flags & SYN == 0
        && (parsed_options.mss.is_some()
            || parsed_options.window_scale.is_some()
            || parsed_options.sack_permitted
            || parsed_options.fast_open.is_some())
    {
        return Err(WireError::InvalidOption);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The number of 32-bit words in the TCP header. This indicates where the data begins.
    //# The TCP header (even one including options) is an integer multiple of 32 bits long.
    let header_len = 20 + options.len().div_ceil(4) * 4;
    let len = header_len
        .checked_add(payload.len())
        .ok_or(WireError::TooLong)?;
    checked_length(ip, len)?;
    if out.len() < len {
        return Err(WireError::OutputTooSmall);
    }
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The content of the header beyond the End of Option List Option MUST
    //# be header padding of zeros (MUST-69).
    out[..header_len].fill(0);
    out[0..2].copy_from_slice(&header.source_port.to_be_bytes());
    out[2..4].copy_from_slice(&header.destination_port.to_be_bytes());
    out[4..8].copy_from_slice(&header.sequence.to_be_bytes());
    out[8..12].copy_from_slice(&header.acknowledgment.to_be_bytes());
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# Must be zero in generated segments and must be ignored in received segments if the
    //# corresponding future features are not implemented by the sending or receiving host.
    out[12] = ((header_len / 4) as u8) << 4;
    out[13] = header.flags;
    out[14..16].copy_from_slice(&header.window.to_be_bytes());
    out[18..20].copy_from_slice(&header.urgent_pointer.to_be_bytes());
    out[20..20 + options.len()].copy_from_slice(options);
    out[header_len..len].copy_from_slice(payload);
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //= reason=encode generates the checksum; parse rejects a nonzero checksum before exposing a segment.
    //# The sender MUST generate it
    //# (MUST-2) and the receiver MUST check it (MUST-3).
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# While computing the checksum, the checksum field itself is replaced with zeros.
    let sum = checksum(ip, &out[..len])?;
    out[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
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
    let payload_len = payload.iter().try_fold(0usize, |n, p| {
        n.checked_add(p.len()).ok_or(WireError::TooLong)
    })?;
    let header_len = 20 + options.len().div_ceil(4) * 4;
    let total = header_len
        .checked_add(payload_len)
        .ok_or(WireError::TooLong)?;
    let len = checked_length(ip, total)?;
    let n = encode(ip, header, options, &[], out)?;
    out[16..18].fill(0);
    let mut sum = pseudo_header_sum(ip, len)?;
    let mut odd = None;
    for bytes in core::iter::once(&out[..n]).chain(payload.iter().map(|p| p.as_slice())) {
        for &byte in bytes {
            if let Some(high) = odd.take() {
                sum += u32::from(u16::from_be_bytes([high, byte]));
                sum = (sum & 0xffff) + (sum >> 16);
            } else {
                odd = Some(byte);
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(high) << 8;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    out[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(n)
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
}
