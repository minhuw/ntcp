// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
fn v6_unsupported(addr: std::net::SocketAddrV6) -> bool {
    addr.scope_id() != 0 || addr.flowinfo() != 0 || addr.ip().is_unicast_link_local()
}
pub(super) fn binding_overlap(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port()
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip().is_unspecified() || b.ip().is_unspecified() || a.ip() == b.ip())
}
fn binding_scopes(api: SocketAddr, wire: SocketAddr, only: bool) -> [Option<SocketAddr>; 2] {
    if api.is_ipv6() && api.ip().is_unspecified() && !only {
        [
            Some(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), api.port())),
            Some(SocketAddr::new(
                std::net::Ipv6Addr::UNSPECIFIED.into(),
                api.port(),
            )),
        ]
    } else {
        [Some(wire), None]
    }
}
impl Socket {
    pub(super) fn conflicts_binding(&self, api: SocketAddr, wire: SocketAddr, only: bool) -> bool {
        let Some(local) = self.local else {
            return false;
        };
        let old_api = if matches!(self.handle, Handle::Connection(_)) {
            self.api_address(local)
        } else {
            self.bound_addr.unwrap_or_else(|| self.api_address(local))
        };
        binding_scopes(old_api, local, self.v6only)
            .into_iter()
            .flatten()
            .any(|a| {
                binding_scopes(api, wire, only)
                    .into_iter()
                    .flatten()
                    .any(|b| binding_overlap(a, b))
            })
    }
    pub(super) fn api_unspecified(&self) -> IpAddr {
        if self.domain == AF_INET6 {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            Ipv4Addr::UNSPECIFIED.into()
        }
    }
    pub(super) fn api_address(&self, addr: SocketAddr) -> SocketAddr {
        if self.domain == AF_INET6
            && let SocketAddr::V4(v) = addr
        {
            return SocketAddr::new(v.ip().to_ipv6_mapped().into(), v.port());
        }
        addr
    }
    pub(super) fn normalize_address(
        &self,
        addr: SocketAddr,
        wire: IpAddr,
        bind: bool,
    ) -> Result<SocketAddr> {
        if crate::ip::family(addr.ip()) != self.domain {
            return Err(EAFNOSUPPORT);
        }
        let normalized = match addr {
            SocketAddr::V6(v) => {
                if v6_unsupported(v) {
                    return Err(EOPNOTSUPP);
                }
                if let Some(ip) = v.ip().to_ipv4_mapped() {
                    if self.v6only {
                        return Err(if bind { EINVAL } else { ENETUNREACH });
                    }
                    SocketAddr::new(ip.into(), v.port())
                } else if v.ip().is_unspecified() && !self.v6only && wire.is_ipv4() && bind {
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), v.port())
                } else {
                    addr
                }
            }
            _ => addr,
        };
        if !bind && normalized.is_ipv4() != wire.is_ipv4() {
            return Err(ENETUNREACH);
        }
        Ok(normalized)
    }
    pub(super) fn wire_tos(&self, wire: IpAddr) -> u8 {
        if wire.is_ipv4() {
            self.tos
        } else {
            self.ipv6_tclass
        }
    }
    pub(super) fn wire_discover(&self, wire: IpAddr) -> i32 {
        if wire.is_ipv4() {
            self.discover
        } else {
            self.ipv6_discover
        }
    }
    pub(super) fn set_wire_ip_policy(&mut self, wire: IpAddr, tos: u8, discover: i32) {
        if wire.is_ipv4() {
            self.tos = tos;
            self.discover = discover;
        } else {
            self.ipv6_tclass = tos;
            self.ipv6_discover = discover;
        }
    }
    pub(super) fn other_ip_policy(&self, wire: IpAddr) -> (u8, i32) {
        if wire.is_ipv4() {
            (self.ipv6_tclass, self.ipv6_discover)
        } else {
            (self.tos, self.discover)
        }
    }
    pub(super) fn set_other_ip_policy(&mut self, wire: IpAddr, tos: u8, discover: i32) {
        if wire.is_ipv4() {
            self.ipv6_tclass = tos;
            self.ipv6_discover = discover;
        } else {
            self.tos = tos;
            self.discover = discover;
        }
    }
}
