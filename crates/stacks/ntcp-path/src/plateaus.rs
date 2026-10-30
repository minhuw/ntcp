use crate::Error;

/// A bounded, source-free replaceable IPv4 fallback policy. Values are IP octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Plateaus {
    values: [u32; Self::CAPACITY],
    len: u8,
}

impl Ipv4Plateaus {
    pub const CAPACITY: usize = 16;
    /// Exact historical RFC1191 Table 7-1 (576 is not a historical plateau).
    pub const RFC1191: Self = Self {
        values: [
            65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68, 0, 0, 0, 0, 0,
        ],
        len: 11,
    };
    pub const HISTORICAL: Self = Self::RFC1191;

    // A compact deployment policy, not an exhaustive catalogue or path guarantee:
    // AWS 9001/8500/1500: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html
    // Google 8896/1500/1460: https://docs.cloud.google.com/vpc/docs/mtu
    // PPPoE 1492: RFC2516 section 7; RFC4638 permits negotiated larger MTUs.
    // RFC791 supplies ceiling65535, receive/reassembly fallback576, floor68.
    pub const CONTEMPORARY: Self = Self {
        values: [
            65535, 9001, 8896, 8500, 1500, 1492, 1460, 576, 68, 0, 0, 0, 0, 0, 0, 0,
        ],
        len: 9,
    };

    pub fn new(values: &[u32]) -> Result<Self, Error> {
        if values.len() > Self::CAPACITY
            || values.last() != Some(&68)
            || values.iter().any(|v| !(68..=65535).contains(v))
            || values.windows(2).any(|v| v[0] <= v[1])
        {
            return Err(Error::InvalidArgument);
        }
        let mut table = Self {
            values: [0; Self::CAPACITY],
            len: values.len() as u8,
        };
        table.values[..values.len()].copy_from_slice(values);
        Ok(table)
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.values[..usize::from(self.len)]
    }

    /// Strict descent, saturating at the legal IPv4 floor.
    pub fn next_lower(&self, bound: u32) -> u32 {
        self.as_slice()
            .iter()
            .copied()
            .find(|&p| p < bound)
            .unwrap_or(68)
    }

    /// Legacy zero-next-hop fallback. The caller must correlate the quote with
    /// an actually submitted IPv4 packet, validate its header, and supply the
    /// exact sent IP size. This pure arithmetic does not authenticate feedback.
    /// `header_bytes` is bytes, not the wire IHL word count.
    pub fn legacy_fallback(
        &self,
        current_estimate: u32,
        quoted_total: u32,
        header_bytes: u32,
        exact_sent_size: u32,
    ) -> Result<u32, Error> {
        if !(68..=65535).contains(&current_estimate)
            || !(20..=60).contains(&header_bytes)
            || !header_bytes.is_multiple_of(4)
            || !(header_bytes..=65535).contains(&quoted_total)
            || !(68..=65535).contains(&exact_sent_size)
        {
            return Err(Error::InvalidArgument);
        }
        let corrected = if quoted_total >= current_estimate {
            quoted_total - header_bytes
        } else {
            quoted_total
        };
        Ok(self.next_lower(corrected.min(exact_sent_size)))
    }
}

// Keep low-level default policy historically compatible. PathService explicitly
// selects CONTEMPORARY instead.
impl Default for Ipv4Plateaus {
    fn default() -> Self {
        Self::RFC1191
    }
}
