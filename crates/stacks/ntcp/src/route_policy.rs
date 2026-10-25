use crate::{ConnectionConfig, Error};

/// Caller-supplied transport parameters for one destination on the same path.
/// These do not select a next hop or identify a different path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutePolicy {
    pub mtu: Option<u32>,
    pub advertised_mss: Option<u16>,
    pub initial_mtu: Option<u32>,
    pub initial_search_low: Option<u32>,
    pub initial_search_high: Option<u32>,
}

fn cap<T: Ord + Copy>(base: Option<T>, route: Option<T>) -> Option<T> {
    match (base, route) {
        (Some(a), Some(b)) => Some(a.min(b)),
        _ => base.or(route),
    }
}
impl RoutePolicy {
    pub fn validate(self, defaults: &ConnectionConfig, ipv4: bool) -> Result<(), Error> {
        let mut config = defaults.clone();
        self.apply(&mut config)?;
        config.validate(ipv4)
    }
    pub(crate) fn route_mtu(self, defaults: &ConnectionConfig) -> Option<u32> {
        cap(defaults.pmtud.and_then(|p| p.route_mtu), self.mtu)
    }
    pub(crate) fn apply(self, config: &mut ConnectionConfig) -> Result<(), Error> {
        if self.advertised_mss == Some(0) {
            return Err(Error::InvalidArgument);
        }
        config.advertised_mss = cap(config.advertised_mss, self.advertised_mss);
        if let Some(p) = config.pmtud.as_mut() {
            p.route_mtu = cap(p.route_mtu, self.mtu);
            p.initial_mtu = self.initial_mtu.or(p.initial_mtu);
            p.initial_search_low = self.initial_search_low.or(p.initial_search_low);
            p.initial_search_high = cap(p.initial_search_high, self.initial_search_high);
        } else if self.mtu.is_some()
            || self.initial_mtu.is_some()
            || self.initial_search_low.is_some()
            || self.initial_search_high.is_some()
        {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}
