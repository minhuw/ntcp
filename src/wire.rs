use core::net::IpAddr;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
pub const ECE: u8 = 0x40;
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
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
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# The checksum also covers a pseudo-header (Figure 2) conceptually prefixed to the TCP
    //# header. The pseudo-header is 96 bits for IPv4 and 320 bits for IPv6.
    let mut sum = match (ip.source, ip.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            add_words(add_words(0, &source.octets()), &destination.octets())
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            add_words(add_words(0, &source.octets()), &destination.octets())
        }
        _ => return Err(WireError::AddressFamily),
    };
    // Each pseudo-header chunk is even-sized; only the segment's final
    // octet can require virtual zero padding. The extra IPv4 length word is zero.
    sum = add_words(sum, &len.to_be_bytes());
    sum = add_words(sum, &[0, 6]);
    sum = add_words(sum, segment);
    Ok(!(sum as u16))
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.2
//# There is no guarantee that senders will use this option, so receivers MUST
//# be prepared to process options even if they do not begin on a word
//# boundary (MUST-64).
fn read_options(mut bytes: &[u8], outgoing: bool) -> Result<Options, WireError> {
    let mut options = Options::default();
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
                        options.window_scale = Some(bytes[2].min(14));
                    }
                    2 | 3 => return Err(WireError::InvalidOption),
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
    // The codec parses options independently of flags; connection-state interpretation is
    // separate.
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# A TCP implementation MUST be able to receive a TCP Option in any segment (MUST-5).
    let options = read_options(raw_options, false)?;
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
    if header.flags & SYN == 0
        && (parsed_options.mss.is_some() || parsed_options.window_scale.is_some())
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
    //# The sender MUST generate it (MUST-2)
    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    //# While computing the checksum, the checksum field itself is replaced with zeros.
    let sum = checksum(ip, &out[..len])?;
    out[16..18].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
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
                        window_scale: Some(14)
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
        for prefix in 0..4 {
            let mut options = vec![1; prefix];
            options.extend([254, 3, 77, 2, 4, 0x12, 0x34, 3, 3, 7]);
            let bytes = packet(ip, &options, b"payload");
            let parsed = parse(ip, &bytes).unwrap();
            assert_eq!(
                parsed.options,
                Options {
                    mss: Some(0x1234),
                    window_scale: Some(7)
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
            assert_eq!(parsed.options.window_scale, Some(scale.min(14)));
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
}
