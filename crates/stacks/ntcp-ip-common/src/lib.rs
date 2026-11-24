#![no_std]
use core::net::IpAddr;

pub mod ipv6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Length,
    Version,
    Checksum,
    FragmentationUnsupported,
    ExtensionsUnsupported,
    JumbogramsUnsupported,
    Options,
    Invalid,
    VlanUnsupported,
    EtherTypeUnsupported,
    ProtocolUnsupported,
    Quote,
}

// Accumulate native words, folding at the end of each block. A carry
// out of a word's position is the end-around carry
// (2^16 is congruent to 1 modulo 2^16 - 1), and a nonzero sum never folds
// to zero. An odd final octet is padded with zero.
//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# The checksum field is the 16 bit one's complement of the one's complement
//# sum of all 16 bit words in the header. For purposes of computing the
//# checksum, the value of the checksum field is zero.
#[inline]
pub fn checksum(bytes: &[u8]) -> u16 {
    checksum_with_sum(bytes, 0)
}

/// The Internet checksum with the sum of an even-length prefix. The prefix
/// may still contain carries (e.g. addresses and TCP header fields).
#[inline]
pub fn checksum_with_sum(bytes: &[u8], prefix: u64) -> u16 {
    // Even a slice larger than the IPv6 jumbogram limit has a bounded sum.
    const BLOCK: usize = 1 << 30;
    checksum_with_sum_blocks(bytes, prefix, BLOCK)
}

#[inline]
fn checksum_with_sum_blocks(bytes: &[u8], prefix: u64, block_size: usize) -> u16 {
    if bytes.len() <= block_size {
        return checksum_block(bytes, prefix);
    }
    let sum = !checksum_chunked(bytes, block_size);
    checksum_block(&sum.to_be_bytes(), prefix)
}

#[cold]
fn checksum_chunked(bytes: &[u8], block_size: usize) -> u16 {
    debug_assert!(block_size > 0 && block_size.is_multiple_of(2));
    let mut sum = 0u32;
    for block in bytes.chunks(block_size) {
        sum += u32::from(!checksum_block(block, 0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline]
fn checksum_block(bytes: &[u8], prefix: u64) -> u16 {
    // Sum native words with end-around carry. Two independent chains
    // overlap on long buffers. Each 64-byte run folds its last carry
    // once, with no per-word widening.
    #[inline]
    fn add(sum: u64, word: u64) -> u64 {
        let (sum, carry) = sum.overflowing_add(word);
        sum + u64::from(carry)
    }
    // Multiplication by 256 swaps the octets modulo 65535. First bring
    // the network-order prefix below 2^33 so the shift fits.
    let prefix = (prefix & 0xffff_ffff) + (prefix >> 32);
    let mut first = prefix << if cfg!(target_endian = "little") { 8 } else { 0 };
    let mut second = 0u64;
    let (pairs, rest) = bytes.as_chunks::<128>();
    for pair in pairs {
        let words = pair.as_chunks::<8>().0;
        let (mut a, mut b) = (false, false);
        for i in 0..8 {
            (first, a) = first.carrying_add(u64::from_ne_bytes(words[i]), a);
            (second, b) = second.carrying_add(u64::from_ne_bytes(words[i + 8]), b);
        }
        first += u64::from(a);
        second += u64::from(b);
    }
    let mut total = add(first, second);
    let (lines, rest) = rest.as_chunks::<64>();
    if let Some(line) = lines.first() {
        let mut carry = false;
        for &word in line.as_chunks::<8>().0 {
            (total, carry) = total.carrying_add(u64::from_ne_bytes(word), carry);
        }
        total += u64::from(carry);
    }
    let (words, rest) = rest.as_chunks::<8>();
    for &word in words {
        total = add(total, u64::from_ne_bytes(word));
    }
    let (word, rest) = rest.as_chunks::<4>();
    if let Some(&word) = word.first() {
        total = add(total, u64::from(u32::from_ne_bytes(word)));
    }
    let tail = match rest {
        [a, b, c] => [*a, *b, *c, 0],
        [a, b] => [*a, *b, 0, 0],
        [a] => [*a, 0, 0, 0],
        _ => [0; 4],
    };
    let wide = add(total, u64::from(u32::from_ne_bytes(tail)));
    let (half, carry) = (wide as u32).overflowing_add((wide >> 32) as u32);
    let half = half + u32::from(carry);
    let sum = (half & 0xffff) + (half >> 16);
    !u16::from_be(((sum & 0xffff) + (sum >> 16)) as u16)
}

pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
pub const UDP_HEADER: usize = 8;

// Transport checksum over the family pseudo-header (RFC 768 for IPv4, RFC 8200
// section 8.1 for IPv6) and `upper`, which holds the complete upper-layer
// header and data. The destination is the final destination even when an IPv4
// source route or an IPv6 Routing header places an intermediate hop in the
// header (`ipv6::Chain::final_destination`). A correctly sealed
// `upper` yields zero.
pub fn pseudo_header_checksum(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    upper: &[u8],
) -> Result<u16, Error> {
    let mut pseudo = [0; 40];
    let pseudo = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let len = u16::try_from(upper.len()).map_err(|_| Error::Length)?;
            pseudo[..4].copy_from_slice(&source.octets());
            pseudo[4..8].copy_from_slice(&destination.octets());
            pseudo[9] = protocol;
            pseudo[10..12].copy_from_slice(&len.to_be_bytes());
            &pseudo[..12]
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let len = u32::try_from(upper.len()).map_err(|_| Error::Length)?;
            pseudo[..16].copy_from_slice(&source.octets());
            pseudo[16..32].copy_from_slice(&destination.octets());
            pseudo[32..36].copy_from_slice(&len.to_be_bytes());
            pseudo[39] = protocol;
            &pseudo[..]
        }
        _ => return Err(Error::Version),
    };
    // Both pseudo-headers have even length, so the sums concatenate exactly.
    let mut sum = u32::from(!checksum(pseudo)) + u32::from(!checksum(upper));
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Ok(!(sum as u16))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Udp<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    // None only for an IPv4 sender that transmitted no checksum.
    pub checksum: Option<u16>,
    pub payload: &'a [u8],
}

// Write the RFC 768 header in front of `payload_len` bytes already resident at
// `datagram[UDP_HEADER..]`; returns the UDP length. The checksum is always
// generated (RFC 1122 section 4.1.3.4 requires checksumming by default and
// IPv6 makes it mandatory). A computed zero is sent as all ones because a
// transmitted zero means "no checksum" to IPv4 receivers. Source port zero is
// RFC 768's "not used" value; destination port zero names no receiver. The
// payload is never modified; on error only the header bytes may be.
pub fn encode_udp(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    datagram: &mut [u8],
    payload_len: usize,
) -> Result<usize, Error> {
    let len = payload_len.checked_add(UDP_HEADER).ok_or(Error::Length)?;
    let wire_len = u16::try_from(len).map_err(|_| Error::Length)?;
    if len > datagram.len() {
        return Err(Error::Length);
    }
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(Error::Version);
    }
    if destination_port == 0 {
        return Err(Error::Invalid);
    }
    let datagram = &mut datagram[..len];
    datagram[..2].copy_from_slice(&source_port.to_be_bytes());
    datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
    datagram[4..6].copy_from_slice(&wire_len.to_be_bytes());
    datagram[6..8].fill(0);
    let sum = match pseudo_header_checksum(source, destination, PROTOCOL_UDP, datagram)? {
        0 => 0xffff,
        sum => sum,
    };
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    Ok(len)
}

// Parse one received UDP datagram carried by an IP payload. The UDP length
// defines the datagram: it must cover the header and fit the IP payload, and
// octets beyond it are not datagram data. A received zero checksum means the
// IPv4 sender computed none; IPv6 forbids it (RFC 8200 section 8.1), so it is
// rejected there like any other checksum failure.
pub fn parse_udp(source: IpAddr, destination: IpAddr, payload: &[u8]) -> Result<Udp<'_>, Error> {
    let header = payload.get(..UDP_HEADER).ok_or(Error::Truncated)?;
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if len < UDP_HEADER || len > payload.len() {
        return Err(Error::Length);
    }
    let datagram = &payload[..len];
    let checksum = match u16::from_be_bytes([header[6], header[7]]) {
        0 if source.is_ipv4() && destination.is_ipv4() => None,
        0 => return Err(Error::Checksum),
        sum => {
            if pseudo_header_checksum(source, destination, PROTOCOL_UDP, datagram)? != 0 {
                return Err(Error::Checksum);
            }
            Some(sum)
        }
    };
    Ok(Udp {
        source_port: u16::from_be_bytes([header[0], header[1]]),
        destination_port: u16::from_be_bytes([header[2], header[3]]),
        checksum,
        payload: &datagram[UDP_HEADER..],
    })
}

#[cfg(test)]
mod tests {
    use super::{checksum, checksum_chunked, checksum_with_sum, checksum_with_sum_blocks};

    // RFC 1071's sum of 16-bit words, folded after every word.
    fn reference(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn wide_sum_matches_the_word_reference() {
        let mut state = 0x2545_f491_u32;
        let mut bytes = [0; 1600];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        for start in 0..4 {
            for len in (0..300).chain([1459, 1460, 1461, 1595]) {
                let slice = &bytes[start..start + len];
                assert_eq!(checksum(slice), reference(slice));
            }
        }
        // All-ones words carry on every addition; zeros never fold to zero.
        for len in [0, 1, 2, 3, 20, 65535, 65536] {
            let ones = [0xff; 65536];
            assert_eq!(checksum(&ones[..len]), reference(&ones[..len]));
            assert_eq!(checksum(&[0; 64][..len.min(64)]), 0xffff);
        }
    }

    #[test]
    fn prefix_sum_matches_network_order_words() {
        // Extend well past 128 and 256 bytes so the 128-byte dual-accumulator
        // loop, 64-byte tail, 8-byte/4-byte tails, and 0..3 byte tails all run
        // with nonzero prefixes.
        let mut bytes = [0u8; 320];
        for (i, b) in bytes[8..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(41).wrapping_add(7);
        }
        let prefixes = [0u64, 1, 0xffff, 0x10000, 0xff00_1234_abcd_ffff, u64::MAX];
        for prefix in prefixes {
            bytes[..8].copy_from_slice(&prefix.to_be_bytes());
            for end in 8..=bytes.len() {
                assert_eq!(
                    checksum_with_sum(&bytes[8..end], prefix),
                    reference(&bytes[..end])
                );
            }
        }
        // All-ones payload past 256 bytes with maximum prefix forces carries on
        // every step of the 128-byte pair loop.
        let mut ones = [0xffu8; 275];
        for prefix in prefixes {
            ones[..8].copy_from_slice(&prefix.to_be_bytes());
            for len in [0, 1, 63, 64, 127, 128, 129, 255, 256, 257, 267] {
                assert_eq!(
                    checksum_with_sum(&ones[8..8 + len], prefix),
                    reference(&ones[..8 + len])
                );
            }
        }
    }

    #[test]
    fn chunked_prefix_checksum_matches_reference() {
        let mut state = 0x9e37_79b9_u32;
        let mut bytes = [0u8; 265];
        for byte in &mut bytes[8..] {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let prefixes = [0u64, 1, 0xffff, 0x10000, 0xff00_1234_abcd_ffff, u64::MAX];
        for block_size in [2, 4, 8, 16, 64, 128] {
            for prefix in prefixes {
                bytes[..8].copy_from_slice(&prefix.to_be_bytes());
                for len in [
                    0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257,
                ] {
                    assert_eq!(
                        checksum_with_sum_blocks(&bytes[8..8 + len], prefix, block_size),
                        reference(&bytes[..8 + len])
                    );
                }

                let mut ones = [0xffu8; 139];
                ones[..8].copy_from_slice(&prefix.to_be_bytes());
                for len in [0, 1, 2, 3, 7, 16, 65, 129, 131] {
                    assert_eq!(
                        checksum_with_sum_blocks(&ones[8..8 + len], prefix, block_size),
                        reference(&ones[..8 + len])
                    );
                }

                let mut zeros = [0u8; 73];
                zeros[..8].copy_from_slice(&prefix.to_be_bytes());
                for len in [0, 1, 4, 17, 65] {
                    assert_eq!(
                        checksum_with_sum_blocks(&zeros[8..8 + len], prefix, block_size),
                        reference(&zeros[..8 + len])
                    );
                }
            }
        }
    }

    #[test]
    fn chunked_checksum_matches_reference() {
        let mut state = 0x9e37_79b9_u32;
        let mut bytes = [0u8; 257];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        for block_size in [2, 4, 6, 8, 12, 16, 64] {
            for len in [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
                129, 255, 256, 257,
            ] {
                let slice = &bytes[..len];
                assert_eq!(checksum_chunked(slice, block_size), reference(slice));
            }
            // All-ones chunks force 0xFFFF + 0xFFFF carry wraparound on every step,
            // including odd-length trailing chunks.
            let ones = [0xffu8; 131];
            for len in [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 130, 131] {
                assert_eq!(
                    checksum_chunked(&ones[..len], block_size),
                    reference(&ones[..len])
                );
            }
            let zeros = [0u8; 65];
            for len in [0, 1, 4, 17, 65] {
                assert_eq!(checksum_chunked(&zeros[..len], block_size), 0xffff);
            }
        }
    }
}
