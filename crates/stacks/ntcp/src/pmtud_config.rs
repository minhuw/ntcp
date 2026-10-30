use crate::Error;

// Minimum legal path MTU of each family: 68 octets for IPv4 (RFC 1191) and
// the IPv6 minimum link MTU (RFC 8200, RFC 8201).
const IPV4_MIN_MTU: u32 = 68;
const IPV6_MIN_MTU: u32 = 1280;

pub(crate) fn min_mtu(ipv4: bool) -> u32 {
    if ipv4 { IPV4_MIN_MTU } else { IPV6_MIN_MTU }
}

// Default initial search_low: RFC 4821's widely safe 1024 bytes for IPv4,
// the IPv6 minimum link MTU for IPv6.
pub(crate) fn default_search_low(ipv4: bool) -> u32 {
    if ipv4 { 1024 } else { IPV6_MIN_MTU }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchAging {
    Seconds(u64),
    Infinity,
}

impl SearchAging {
    pub(crate) fn ticks(self, units_per_second: u64) -> Result<Option<u64>, Error> {
        match self {
            Self::Seconds(seconds) if seconds >= 300 => seconds
                .checked_mul(units_per_second)
                .map(Some)
                .ok_or(Error::InvalidArgument),
            Self::Infinity => Ok(None),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Public compatibility adapter for the canonical IP-layer plateau policy.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Plateaus(ntcp_path::Ipv4Plateaus);

impl Ipv4Plateaus {
    pub const CAPACITY: usize = ntcp_path::Ipv4Plateaus::CAPACITY;
    pub const RFC1191: Self = Self(ntcp_path::Ipv4Plateaus::RFC1191);
    pub const HISTORICAL: Self = Self::RFC1191;
    pub const CONTEMPORARY: Self = Self(ntcp_path::Ipv4Plateaus::CONTEMPORARY);

    pub fn new(values: &[u32]) -> Result<Self, Error> {
        ntcp_path::Ipv4Plateaus::new(values)
            .map(Self)
            .map_err(|_| Error::InvalidArgument)
    }

    pub fn as_slice(&self) -> &[u32] {
        self.0.as_slice()
    }
}

impl Default for Ipv4Plateaus {
    fn default() -> Self {
        Self::RFC1191
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtudPolicy {
    pub search_aging: SearchAging,
    pub ipv4_plateaus: Ipv4Plateaus,
}

impl PmtudPolicy {
    pub const DEFAULT: Self = Self {
        search_aging: SearchAging::Seconds(600),
        ipv4_plateaus: Ipv4Plateaus::RFC1191,
    };
}

impl Default for PmtudPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtudConfig {
    pub first_hop_mtu: u32,
    // Same-path administrative packetization ceiling, independent of physical
    // interface MTU and network-discovered limits. Explicit IPv6 ceilings may
    // be smaller than 1280; they do not authorize accepting subminimum PTB.
    // None imposes no additional route ceiling.
    pub route_mtu: Option<u32>,
    pub initial_mtu: Option<u32>,
    pub initial_search_low: Option<u32>,
    pub initial_search_high: Option<u32>,
    pub policy: PmtudPolicy,
}

impl PmtudConfig {
    pub const fn new(first_hop_mtu: u32) -> Self {
        Self {
            first_hop_mtu,
            route_mtu: None,
            initial_mtu: None,
            initial_search_low: None,
            initial_search_high: None,
            policy: PmtudPolicy::DEFAULT,
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc4821#section-7.2
    //= reason=Reviewed 0030a96: independent creation-only initial_search_low is validated with initial_mtu/initial_search_high, family and allocation bounds. Defaults remain conservative IPv4 min(mtu,1024) and IPv6 min(mtu,1280); explicit transport bounds use packet/header limits independently of physical IPv6 link and PTB minimums. Tests assert defaults, independent overrides, rejection rather than silent clamping, and subsequent peer caps. Destination policy configuration is independently covered at071/119.
    //# It is RECOMMENDED that search_low be initially set to an MTU size that is likely
    //# to work over a very wide range of environments. Given today's technologies, a
    //# value of 1024 bytes is probably safe enough. The initial value for search_low
    //# SHOULD be configurable.

    pub(crate) fn initial_values(self, bound: u32, ipv4: bool) -> Result<(u32, u32, u32), Error> {
        let floor = min_mtu(ipv4);
        // Preserve the physical link minimum. Explicit transport bounds only
        // need space for base headers and the existing eight-byte data minimum;
        // ConnectionConfig additionally reserves its enabled TCP options.
        // IPv6 base headers plus eight data bytes also equal IPv4's legal
        // 68-byte minimum. Option-aware checks belong to ConnectionConfig.
        let packet_floor = 40 + 20 + 8;
        let max = if ipv4 { 65535 } else { 65575 };
        let bound = bound.min(self.route_mtu.unwrap_or(bound));
        if !(floor..=max).contains(&self.first_hop_mtu)
            || self
                .route_mtu
                .is_some_and(|mtu| !(packet_floor..=max).contains(&mtu))
            || [
                self.initial_mtu,
                self.initial_search_low,
                self.initial_search_high,
            ]
            .into_iter()
            .flatten()
            .any(|v| !(packet_floor..=bound.min(self.first_hop_mtu)).contains(&v))
        {
            return Err(Error::InvalidArgument);
        }
        let high = self.initial_search_high.unwrap_or(bound);
        let mtu = self.initial_mtu.unwrap_or(high);
        let low = self
            .initial_search_low
            .unwrap_or(mtu.min(default_search_low(ipv4)));
        if low > mtu || mtu > high {
            return Err(Error::InvalidArgument);
        }
        Ok((mtu, low, high))
    }
}
