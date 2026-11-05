// Redirect reception for both families (never originated): validation of
// the message against this Host's own forwarding authority and submission
// evidence, then a bounded override beneath the administrative route
// (`PathService::redirect`), whose installation invalidates the paths it
// moves; `Host::service_changes` then brings every TCP binding and UDP flow
// on them to the new first hop (RFC 1191 section 6.3: the packetization
// layer learns of the possible PMTU change). Held output meets the
// submission barrier, which refuses what the current path no longer
// carries.
use core::net::{IpAddr, Ipv6Addr};
use ntcp::Instant;
use ntcp_icmp::{Ipv6Redirect, Quote};
use ntcp_path::{PathKey, PathStatus, ResolvedNextHop, ScopedAddress};

use crate::{Error, Host, IngressContext, IngressPacket, path, quote_key};

/// The disposition of a wire-valid Redirect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectOutcome {
    /// The destination's first hop changed: its paths are invalidated and
    /// their clients are notified by the next `Host::service_changes`.
    Installed,
    Rejected(RedirectRejection),
}

/// Why a wire-valid Redirect changed nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectRejection {
    /// No usable quote: an ICMPv6 Redirect without a Redirected Header
    /// whose quote names a packet this Host sent. RFC 4861 section 8.1
    /// does not require the option; this Host's policy accepts a Redirect
    /// only with evidence of an exact committed submission.
    NoEvidence,
    /// The quote matches no exact committed submission, or its matches do
    /// not agree on one path incarnation.
    Uncorrelated,
    /// The quoted submission's path is no longer the authoritative
    /// selection (a replaced route generation, a changed first hop or
    /// link).
    Stale,
    /// It arrived on another link than the one the path leaves through.
    WrongLink,
    /// The sender is not the destination's current first-hop router, or
    /// the destination is reached directly.
    NotFirstHop,
    /// The ICMPv6 Destination is not the quoted submission's forwarding
    /// destination.
    Destination,
    /// The new IPv4 gateway is not reached directly over the arrival link,
    /// or the target is unusable as a first hop.
    Target,
}

impl Host {
    // The current authoritative path of the exact committed submission
    // `quoted` (as `quoted_message`, whose quoted packet starts at offset
    // 8), on which a Redirect from `sender` arrived over `context`'s link.
    fn redirected_path(
        &self,
        context: IngressContext,
        now: Instant,
        sender: ScopedAddress,
        quoted: &Quote,
        quoted_message: &[u8],
    ) -> Result<PathKey, RedirectRejection> {
        use RedirectRejection::*;
        let key = quote_key(quoted);
        // A link-local quoted source belongs to the arrival link.
        let zone = matches!(key.source, IpAddr::V6(v) if v.is_unicast_link_local())
            .then_some(context.link);
        let path = self
            .ledger
            .correlate_in(now, &key, zone)
            .path
            .filter(|path| self.quote_authorized(*path, quoted_message))
            .ok_or(Uncorrelated)?;
        let snapshot = self.paths.path_snapshot(path).map_err(|_| Stale)?;
        if snapshot.status() != PathStatus::Valid {
            return Err(Stale);
        }
        let key = snapshot.key();
        self.paths.validate_selection(key).map_err(|_| Stale)?;
        if key.link() != context.link {
            return Err(WrongLink);
        }
        if key.next_hop() != ResolvedNextHop::Address(sender)
            || key.next_hop() == ResolvedNextHop::Address(key.forwarding_destination())
        {
            return Err(NotFirstHop);
        }
        Ok(key)
    }

    // RFC 792 and RFC 1122 section 3.2.2.2, with the run's strict
    // rejection of every case RFC 1122 says SHOULD be discarded: the
    // Redirect must come from the current first-hop gateway of the quoted
    // datagram's destination over the link that datagram left through, and
    // the new gateway must be reached directly over that link. Host and
    // Network Redirects update that one destination, whatever its type of
    // service, without inventing a network mask; the type-of-service forms
    // apply to the DSCP the datagram was submitted with, never the quoted
    // (possibly remarked) bits.
    pub(crate) fn redirect_ipv4(
        &mut self,
        context: IngressContext,
        now: Instant,
        packet: &IngressPacket,
    ) -> Result<RedirectOutcome, Error> {
        use RedirectRejection::*;
        let redirect = ntcp_icmp::decode_ipv4_redirect(packet.ip, packet.payload)?;
        self.owned_on_link(context, packet.ip.destination)?;
        self.now = self.now.max(now);
        let sender = ScopedAddress::new(packet.ip.source, None)?;
        let key = match self.redirected_path(context, now, sender, &redirect.quoted, packet.payload)
        {
            Ok(key) => key,
            Err(rejection) => return Ok(RedirectOutcome::Rejected(rejection)),
        };
        let Ok(gateway) = ScopedAddress::new(IpAddr::V4(redirect.gateway), None) else {
            return Ok(RedirectOutcome::Rejected(Target));
        };
        let direct = self
            .paths
            .resolve(path::PathRequest {
                source: key.source(),
                destination: gateway,
                dscp: key.dscp(),
            })
            .ok()
            .filter(|gateway| {
                gateway.key().link() == key.link()
                    && self
                        .paths
                        .route(gateway.key().route())
                        .is_ok_and(|route| route.next_hop == path::NextHop::OnLink)
            });
        if direct.is_none() {
            return Ok(RedirectOutcome::Rejected(Target));
        }
        self.install_redirect(key, sender, gateway, redirect.code.type_of_service())
    }

    // RFC 4861 sections 8.1 and 8.3, from a link-local `source` on an
    // ND-capable port (the decoder checked the message itself). The sender
    // must be the current first-hop router of the quoted submission's
    // forwarding destination over the arrival link, and the ICMPv6
    // Destination must be that destination, so a quote for one destination
    // never authorizes another. The target need not match any on-link
    // prefix. A target equal to the destination makes it on-link; any other
    // target is a router. A Target Link-Layer Address updates the neighbor
    // cache as section 8.3 describes. All flows to the destination move,
    // whatever their flow label.
    pub(crate) fn redirect_ipv6(
        &mut self,
        context: IngressContext,
        now: Instant,
        source: Ipv6Addr,
        redirect: Ipv6Redirect,
    ) -> Result<RedirectOutcome, Error> {
        use RedirectRejection::*;
        self.now = self.now.max(now);
        let Some((quoted, option)) = redirect.redirected else {
            return Ok(RedirectOutcome::Rejected(NoEvidence));
        };
        let sender = ScopedAddress::new(IpAddr::V6(source), Some(context.link))?;
        let key = match self.redirected_path(context, now, sender, &quoted, option) {
            Ok(key) => key,
            Err(rejection) => return Ok(RedirectOutcome::Rejected(rejection)),
        };
        let destination = key.forwarding_destination();
        if destination.address() != IpAddr::V6(redirect.destination) {
            return Ok(RedirectOutcome::Rejected(Destination));
        }
        let on_link = redirect.target == redirect.destination;
        let target = if on_link {
            destination
        } else {
            match ScopedAddress::new(IpAddr::V6(redirect.target), Some(context.link)) {
                Ok(target) => target,
                Err(_) => return Ok(RedirectOutcome::Rejected(Target)),
            }
        };
        let outcome = self.install_redirect(key, sender, target, false)?;
        if outcome == RedirectOutcome::Installed && self.neighbors.port(context.link).is_some() {
            self.neighbors.redirect(
                context.link,
                redirect.target,
                redirect.target_link_layer,
                !on_link,
                now,
            );
        }
        Ok(outcome)
    }

    fn install_redirect(
        &mut self,
        key: PathKey,
        sender: ScopedAddress,
        target: ScopedAddress,
        type_of_service: bool,
    ) -> Result<RedirectOutcome, Error> {
        match self.paths.redirect(key, sender, target, type_of_service) {
            Ok(()) => Ok(RedirectOutcome::Installed),
            Err(path::Error::InvalidArgument) => {
                Ok(RedirectOutcome::Rejected(RedirectRejection::Target))
            }
            Err(error) => Err(error.into()),
        }
    }
}
