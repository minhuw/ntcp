#![no_std]

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

// Folding each word avoids overflow even for caller-provided large slices.
//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# The checksum field is the 16 bit one's complement of the one's complement
//# sum of all 16 bit words in the header. For purposes of computing the
//# checksum, the value of the checksum field is zero.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
