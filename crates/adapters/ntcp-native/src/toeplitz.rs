// The Toeplitz hash of receive-side scaling (RSS): the 32-bit result is the
// XOR, over every set bit i of the input (most significant bit of the
// first octet first), of the 32-bit window of the key starting at bit i.
// For IPv4 TCP the input is source address, destination address, source
// port, destination port (12 octets, network order); for IPv4 without
// ports it is the two addresses (8 octets).
use std::net::Ipv4Addr;

/// The RSS key mlx5 and many other NICs use by default (40 octets).
pub const DEFAULT_KEY: [u8; 40] = [
    0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a, 0x3e, 0x94,
    0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7, 0xd9, 0x56, 0x3d, 0x59,
    0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
];

/// The longest input this module hashes: an IPv4 address pair and ports.
pub(crate) const MAX_INPUT: usize = 12;

pub(crate) struct Toeplitz {
    key: Vec<u8>,
}

impl Toeplitz {
    /// None unless the key covers a `MAX_INPUT`-octet input: at least
    /// `MAX_INPUT + 4` octets.
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        (key.len() >= MAX_INPUT + 4).then(|| Self { key: key.to_vec() })
    }

    /// The hash of `input`, at most `MAX_INPUT` octets.
    pub(crate) fn hash(&self, input: &[u8]) -> u32 {
        assert!(input.len() <= MAX_INPUT);
        let bit = |i: usize| u32::from(self.key[i / 8] >> (7 - i % 8) & 1);
        let mut window = u32::from_be_bytes(self.key[..4].try_into().unwrap());
        let mut result = 0;
        for (n, &octet) in input.iter().enumerate() {
            for b in 0..8 {
                if octet & (0x80 >> b) != 0 {
                    result ^= window;
                }
                window = window << 1 | bit(32 + n * 8 + b);
            }
        }
        result
    }

    /// The hash of an IPv4 packet's addresses.
    pub(crate) fn ipv4(&self, source: Ipv4Addr, destination: Ipv4Addr) -> u32 {
        let mut input = [0; 8];
        input[..4].copy_from_slice(&source.octets());
        input[4..].copy_from_slice(&destination.octets());
        self.hash(&input)
    }

    /// The hash of an IPv4 TCP (or UDP) packet's addresses and ports.
    pub(crate) fn ipv4_ports(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> u32 {
        let mut input = [0; 12];
        input[..4].copy_from_slice(&source.octets());
        input[4..8].copy_from_slice(&destination.octets());
        input[8..10].copy_from_slice(&source_port.to_be_bytes());
        input[10..].copy_from_slice(&destination_port.to_be_bytes());
        self.hash(&input)
    }
}
