// The Toeplitz hash of receive-side scaling (RSS): the 32-bit result is the
// XOR, over every set bit i of the input (most significant bit of the
// first octet first), of the 32-bit window of the key starting at bit i.
// For IPv4 TCP the input is source address, destination address, source
// port, destination port (12 octets, network order); for IPv4 without
// ports it is the two addresses (8 octets).
use std::net::Ipv4Addr;

/// The RSS key mlx5 and many other NICs use by default (40 octets): DPDK's
/// `rss_hash_default_key` in `drivers/net/mlx5/mlx5_rxq.c`.
pub const DEFAULT_KEY: [u8; 40] = [
    0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a, 0x3e, 0x94,
    0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7, 0xd9, 0x56, 0x3d, 0x59,
    0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
];

/// The longest input this module hashes: an IPv4 address pair and ports.
pub(crate) const MAX_INPUT: usize = 12;

// The hash is linear in the input, so `new` folds the key into one table
// per input octet position: entry v of table n is the hash of octet value
// v at position n. A hash is then one lookup and XOR per octet. Byte tables
// (12 KiB) measured about 30% faster than nibble tables (1.5 KiB), and a
// hash reads only 12 of their cache lines.
pub(crate) struct Toeplitz {
    tables: Box<[[u32; 256]; MAX_INPUT]>,
}

impl Toeplitz {
    /// None unless the key covers a `MAX_INPUT`-octet input: at least
    /// `MAX_INPUT + 4` octets.
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        if key.len() < MAX_INPUT + 4 {
            return None;
        }
        // The last octet's windows end within `MAX_INPUT + 4` key octets;
        // the padding only lets every position load eight.
        let mut padded = [0; MAX_INPUT + 7];
        padded[..MAX_INPUT + 4].copy_from_slice(&key[..MAX_INPUT + 4]);
        let mut tables = Box::new([[0; 256]; MAX_INPUT]);
        for (n, table) in tables.iter_mut().enumerate() {
            // The key windows of the octet's bits, most significant first.
            let octets = u64::from_be_bytes(padded[n..n + 8].try_into().unwrap());
            let windows: [u32; 8] = std::array::from_fn(|b| (octets << b >> 32) as u32);
            for (value, entry) in table.iter_mut().enumerate() {
                *entry = (0..8)
                    .filter(|b| value & (0x80 >> b) != 0)
                    .fold(0, |hash, b| hash ^ windows[b]);
            }
        }
        Some(Self { tables })
    }

    /// The hash of `input`, at most `MAX_INPUT` octets.
    pub(crate) fn hash(&self, input: &[u8]) -> u32 {
        assert!(input.len() <= MAX_INPUT);
        input
            .iter()
            .zip(self.tables.iter())
            .fold(0, |hash, (&octet, table)| hash ^ table[usize::from(octet)])
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

#[cfg(test)]
mod tests {
    use super::*;

    // The bit-at-a-time definition, for any key long enough for the input.
    fn reference(key: &[u8], input: &[u8]) -> u32 {
        let bit = |i: usize| u32::from(key[i / 8] >> (7 - i % 8) & 1);
        let mut window = u32::from_be_bytes(key[..4].try_into().unwrap());
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

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn fill(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.next() as u8;
            }
        }
    }

    // The Microsoft RSS verification suite for IPv4, as DPDK's
    // app/test/test_thash.c quotes it ("From 82599 Datasheet 7.1.2.8.3 RSS
    // Verification Suite"): key `default_rss_key`, then per row the
    // destination and source addresses, the destination and source ports,
    // and the hashes without and with ports.
    const VERIFICATION_KEY: [u8; 40] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];
    const ADDRESSES: [[u8; 8]; 5] = [
        [161, 142, 100, 80, 66, 9, 149, 187],
        [65, 69, 140, 83, 199, 92, 111, 2],
        [12, 22, 207, 184, 24, 19, 198, 95],
        [209, 142, 163, 6, 38, 27, 205, 30],
        [202, 188, 127, 2, 153, 39, 163, 191],
    ];
    const PORTS: [[u16; 2]; 5] = [
        [1766, 2794],
        [4739, 14230],
        [38024, 12898],
        [2217, 48228],
        [1303, 44251],
    ];
    const HASHES: [[u32; 2]; 5] = [
        [0x323e8fc2, 0x51ccc178],
        [0xd718262a, 0xc626b0ea],
        [0xd2d0a5de, 0x5c2b394a],
        [0x82989176, 0xafc7327f],
        [0x5d1809c5, 0x10e828a2],
    ];

    #[test]
    fn matches_the_rss_verification_suite() {
        let toeplitz = Toeplitz::new(&VERIFICATION_KEY).unwrap();
        for ((addresses, [destination_port, source_port]), [l3, l4]) in
            ADDRESSES.into_iter().zip(PORTS).zip(HASHES)
        {
            let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&addresses[..4]).unwrap());
            let source = Ipv4Addr::from(<[u8; 4]>::try_from(&addresses[4..]).unwrap());
            assert_eq!(toeplitz.ipv4(source, destination), l3);
            assert_eq!(
                toeplitz.ipv4_ports(source, destination, source_port, destination_port),
                l4
            );
        }
    }

    #[test]
    fn tables_match_the_bitwise_definition() {
        let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
        for keys in 0..64 {
            let mut key = vec![0; MAX_INPUT + 4 + keys % 25];
            random.fill(&mut key);
            let toeplitz = Toeplitz::new(&key).unwrap();
            for len in 0..=MAX_INPUT {
                for _ in 0..64 {
                    let mut input = [0; MAX_INPUT];
                    random.fill(&mut input[..len]);
                    assert_eq!(toeplitz.hash(&input[..len]), reference(&key, &input[..len]));
                }
            }
        }
    }

    #[test]
    fn default_key_is_mlx5s() {
        assert_eq!(
            DEFAULT_KEY,
            [
                0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a,
                0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7,
                0xd9, 0x56, 0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
            ]
        );
    }

    #[test]
    fn refuses_short_keys() {
        for len in 0..MAX_INPUT + 4 {
            assert!(Toeplitz::new(&DEFAULT_KEY[..len]).is_none());
        }
        assert!(Toeplitz::new(&DEFAULT_KEY[..MAX_INPUT + 4]).is_some());
    }
}
