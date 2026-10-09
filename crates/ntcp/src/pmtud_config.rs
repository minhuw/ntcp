use crate::Error;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Plateaus {
    values: [u32; Self::CAPACITY],
    len: u8,
}

impl Ipv4Plateaus {
    pub const CAPACITY: usize = 16;
    pub const RFC1191: Self = Self {
        values: [
            65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68, 0, 0, 0, 0, 0,
        ],
        len: 11,
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
    pub initial_mtu: Option<u32>,
    pub initial_search_low: Option<u32>,
    pub initial_search_high: Option<u32>,
    pub policy: PmtudPolicy,
}

impl PmtudConfig {
    pub const fn new(first_hop_mtu: u32) -> Self {
        Self {
            first_hop_mtu,
            initial_mtu: None,
            initial_search_low: None,
            initial_search_high: None,
            policy: PmtudPolicy::DEFAULT,
        }
    }

    pub(crate) fn initial_values(self, bound: u32, ipv4: bool) -> Result<(u32, u32, u32), Error> {
        let floor = if ipv4 { 68 } else { 1280 };
        let max = if ipv4 { 65535 } else { 65575 };
        if !(floor..=max).contains(&self.first_hop_mtu)
            || [
                self.initial_mtu,
                self.initial_search_low,
                self.initial_search_high,
            ]
            .into_iter()
            .flatten()
            .any(|v| !(floor..=bound.min(self.first_hop_mtu)).contains(&v))
        {
            return Err(Error::InvalidArgument);
        }
        let high = self.initial_search_high.unwrap_or(bound);
        let mtu = self.initial_mtu.unwrap_or(high);
        let low = self
            .initial_search_low
            .unwrap_or(mtu.min(if ipv4 { 1024 } else { 1280 }));
        if low > mtu || mtu > high {
            return Err(Error::InvalidArgument);
        }
        Ok((mtu, low, high))
    }
}
