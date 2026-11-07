//! The ntcp-pathctl command line (shared by the binary and by embedding
//! tests that run it as a separate process).
//!
//! Usage: ntcp-pathctl SOCKET COMMAND
//!   routes | paths | clients PATH
//!   select PREFIX                          route token of an unambiguous prefix
//!   set route|path TOKEN GENERATION [disable] [estimate=OCTETS]
//!                                          replace the complete policy (CAS)
//!   disable|enable route|path TOKEN        discovery policy (read, then CAS)
//!   estimate route|path TOKEN OCTETS|clear administrative estimate (read, then CAS)
//!   plateaus [VALUE...]                    get or replace the IPv4 plateau table
//!   aging [SECONDS|infinity]               get or set the search aging
//!
//! Output is one `key=value` line per object. Exit status: 0 success, 1 the
//! server refused the request (`status=NAME` on stderr; nothing changed),
//! 2 usage error, 3 I/O or protocol failure.

use crate::client::{Client, ClientError};
use crate::protocol::{
    Aging, ClientEntry, NextHop, PathEntry, Payload, Plateaus, Policy, Prefix, Request, RouteEntry,
    Search, Source,
};
use std::net::IpAddr;
use std::path::Path;

fn usage() -> u8 {
    eprintln!(
        "usage: ntcp-pathctl SOCKET (routes | paths | clients PATH | select PREFIX | \
         set route|path TOKEN GENERATION [disable] [estimate=OCTETS] | \
         disable|enable route|path TOKEN | estimate route|path TOKEN OCTETS|clear | \
         plateaus [VALUE...] | aging [SECONDS|infinity])"
    );
    2
}

fn token(text: &str) -> Option<u64> {
    u64::from_str_radix(text, 16).ok()
}

fn optional(v: Option<u32>) -> String {
    v.map_or("-".into(), |v| v.to_string())
}

fn source(s: Source) -> &'static str {
    match s {
        Source::Route => "route",
        Source::Path => "path",
        Source::RouteAndPath => "route+path",
    }
}

fn policy(p: Policy) -> String {
    format!(
        "disabled={} estimate={}",
        u8::from(p.discovery_disabled),
        optional(p.estimate)
    )
}

fn prefix(p: Prefix) -> String {
    format!("{}/{}", p.network, p.length)
}

fn print_route(e: &RouteEntry) {
    println!(
        "route token={:016x} generation={} destination={} source={} dscp={} link={:016x} next_hop={} metric={} {}",
        e.token,
        e.generation,
        prefix(e.destination),
        e.source.map_or("-".into(), prefix),
        e.dscp.map_or("-".into(), |d| d.to_string()),
        e.link,
        match e.next_hop {
            NextHop::OnLink => "on-link".to_string(),
            NextHop::Gateway(a) => format!("gateway:{a}"),
            NextHop::Forwarder(id) => format!("forwarder:{id}"),
        },
        e.metric,
        policy(e.policy),
    );
}

fn print_path(e: &PathEntry) {
    println!(
        "path token={:016x} generation={} version={} valid={} route={:016x} source={} destination={} \
         forwarding={} next_hop={} dscp={} pins={} {} route_policy={} effective_disabled={} \
         administrative_estimate={} accepted={} first_hop={} learned={} restriction={} budget={} \
         retry_not_before={} negative_revision={} discovery_revision={} clients={}",
        e.token,
        e.generation,
        e.version,
        u8::from(e.valid),
        e.route,
        e.source,
        e.destination,
        e.forwarding,
        match e.next_hop {
            NextHop::OnLink => "on-link".to_string(),
            NextHop::Gateway(a) => a.to_string(),
            NextHop::Forwarder(id) => format!("forwarder:{id}"),
        },
        e.dscp,
        e.pins,
        policy(e.policy),
        e.route_policy.map_or("-".into(), |p| format!(
            "{}/{}",
            u8::from(p.discovery_disabled),
            optional(p.estimate)
        )),
        e.discovery_disabled.map_or("-", source),
        e.estimate
            .map_or("-".into(), |(v, s)| format!("{v}:{}", source(s))),
        e.accepted
            .map_or("-".into(), |(v, p)| format!("{v}:{p:?}").to_lowercase()),
        e.first_hop,
        optional(e.learned),
        optional(e.restriction),
        optional(e.budget),
        e.retry_not_before,
        e.negative_revision,
        e.discovery_revision,
        e.clients,
    );
}

fn print_client(e: &ClientEntry) {
    let transport = e.transport.map_or("-".into(), |t| {
        format!(
            "peer_mss:{},user_mss:{},local_mss:{},allocation:{},payload_limit:{},destination_mtu:{},effective_mss:{}",
            t.peer_mss,
            t.user_mss.map_or("-".into(), |v| v.to_string()),
            t.local_mss,
            t.allocation,
            t.send_ip_payload_limit,
            optional(t.destination_mtu),
            t.effective_mss
        )
    });
    const DEFERRAL: [&str; 6] = [
        "-",
        "hold",
        "cooldown",
        "loss-recovery",
        "data-or-window",
        "discovery-disabled",
    ];
    const CLIP: [&str; 4] = ["-", "search-high", "transport", "search-low"];
    let reason = |table: &[&'static str], code: Option<u8>| {
        table
            .get(usize::from(code.unwrap_or(0)))
            .copied()
            .unwrap_or("unknown")
    };
    let search = match e.search {
        None => "-".to_string(),
        Some(Search::Pending { target, deferred }) => {
            format!("pending:{target}:{}", reason(&DEFERRAL, deferred))
        }
        Some(Search::Attempted {
            target,
            size,
            clipped,
        }) => {
            format!("attempted:{target}:{size}:{}", reason(&CLIP, clipped))
        }
    };
    println!(
        "client kind={} id={:016x} usable={} transport={} search={}",
        format!("{:?}", e.kind).to_lowercase(),
        e.id,
        optional(e.usable_ip_packet),
        transport,
        search
    );
}

fn fail(error: ClientError) -> u8 {
    match error {
        ClientError::Status(status) => {
            eprintln!("status={}", status.name());
            1
        }
        ClientError::Io(e) => {
            eprintln!("error={e}");
            3
        }
        ClientError::Protocol => {
            eprintln!("error=protocol");
            3
        }
    }
}

// Current policy and generation of one target, read from the listing.
fn current(client: &mut Client, route: bool, target: u64) -> Result<(u64, Policy), ClientError> {
    if route {
        client
            .routes()?
            .into_iter()
            .find(|e| e.token == target)
            .map(|e| (e.generation, e.policy))
    } else {
        client
            .paths()?
            .into_iter()
            .find(|e| e.token == target)
            .map(|e| (e.generation, e.policy))
    }
    .ok_or(ClientError::Status(crate::protocol::Status::Stale))
}

fn set(
    client: &mut Client,
    route: bool,
    target: u64,
    expected: u64,
    policy: Policy,
) -> Result<(), ClientError> {
    let request = if route {
        Request::SetRoutePolicy {
            route: target,
            expected,
            policy,
        }
    } else {
        Request::SetPathPolicy {
            path: target,
            expected,
            policy,
        }
    };
    if let Payload::Applied {
        generation,
        affected,
    } = client.ok(&request)?
    {
        println!("applied generation={generation} affected_paths={affected}");
        Ok(())
    } else {
        Err(ClientError::Protocol)
    }
}

fn kind(text: &str) -> Option<bool> {
    match text {
        "route" => Some(true),
        "path" => Some(false),
        _ => None,
    }
}

//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= reason=The ntcp-pathctl utility's estimate command (or set with estimate=OCTETS) sets or clears the owner's administrative PMTU estimate on a forwarding route, applied to every path resolved through it now and after idle eviction and reacquisition, or on an exact resolved path, under compare-and-set generations, bounded by the first hop and the family minimum; simultaneous route and path values intersect. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. The value is compared with the path's accepted network estimate, never with an earlier administrative request or a transport-clipped size: a lower value lowers the accepted estimate at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same transaction and caps search and confirmed growth while set; an identical value is a no-op; a higher value is cached as the administrative estimate and changes no accepted estimate, hold, search bound or current size: it caps TCP PLPMTUD and the Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it, so the route's PMTU grows to it only through an acknowledged or echoed unfragmented probe (PathService::confirm_delivery), and a failed targeted probe is not reopened; reacquisition through the route never promotes a deferred upward value. Clearing removes the cap and keeps every hold. Queries report the cached administrative estimate, the accepted estimate with its provenance and each client's usable size and transport ceilings separately. On a discovery-disabled IPv4 route the value is the RFC 1122 section 3.3.3 sending limit (actual knowledge, never above the accepted estimate). Endpoint::set_destination_route, set_route_mtu and lower_mss remain separate transport ceilings. Tests: ntcp-host src/tests/admin.rs (both families, deterministic caller time: downward fanout and hold arithmetic, equal no-op, an upward value deferred through the hold and then grown by a targeted probe exactly to the value, a failed targeted probe not reopened) and ipv4_policy.rs (a disabled route with a value sends at most it), ntcp-path tests/administration.rs (route and path precedence, eviction and reacquisition without promotion, single and bulk replacement) and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin case shows a downward set shrinking tun_echo's packets at once, an upward value recorded while the accepted estimate and packet sizes stay unchanged, and a disabled IPv4 path with a value of 1000 sending at most 1000 octets.
//# - Change the PMTU value associated with a given route.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= reason=The ntcp-pathctl system utility provides both per-path controls of 8201-080/081 for IPv6 paths and for the forwarding routes they resolve through: discovery disable and enable and administrative PMTU estimate set and clear on a route or an exact resolved path under compare-and-set generations, with paginated route and path queries (the cached administrative estimate, the accepted network estimate with provenance, the shared packet budget, holds, revisions and each client's usable size, transport ceilings and deferred growth with its reason), the IPv4 plateau table and search aging. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. Tests: real utility process round trips in both families with every negative case (ntcp-path-control tests/control.rs, the native runtime and tun_echo control tests); the integration/rfc_host admin and native-admin cases run ntcp-pathctl as a separate process against live tun_echo and the native runtime harness during IPv6 traffic, refusing a stale compare-and-set with nothing changed.
//# It is suggested that an implementation provides a way for a system utility program to:
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= reason=The ntcp-pathctl utility's disable command (or set with disable) sets the owner's discovery-disable flag on an exact resolved path or on a forwarding route, which applies to every path resolved through it now and later (a route disable dominates a path enable; clearing a path policy reveals the route policy); enable clears it. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. Host::admin_apply enforces the flag on the existing and future users of the path without rewriting any connection's creation configuration: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) is sent there; TCP stops every size-search change (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; outstanding TCP and adjunct size results selected under the previous policy publish nothing, including a probe acknowledged after the disable; and the path's IPv6 packet budget becomes the minimum link MTU (8201-082). Clearing restores each client's own configuration without fabricated size proof. Tests: ntcp-host src/tests/admin.rs (existing and future TCP capped at 1280, control and GSO segments, a probe submitted before the disable publishing nothing, policy-revision invalidation), adjunct.rs discovery_disable_stops_the_adjunct, emitter.rs discovery_disable_caps_ipv6_flows_at_1280_and_refuses_probes and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin and native-admin cases capture IPv6 output at most 1280 octets after ntcp-pathctl disables discovery during live traffic, with stream and datagram hashes intact and a neighbor destination keeping 1500-octet packets, and full size after enable. Re-enabling restores probing without stale size proof (integration/rfc_host admin reenable case, both families, tun_echo's Host Echo adjunct, no fragmented traffic before the disable): while the path is disabled its fragmented UDP replies create adjunct demand, yet no Echo Request leaves toward it; right after ntcp-pathctl re-enables discovery, and before any adjunct reply, the utility reports the accepted estimate with its provenance and the adjunct's usable size at their pre-disable values, so the deliveries made while disabled proved nothing; then an unfragmented Echo Request above the connectionless effective size leaves, and after its real Echo Reply only the adjunct's usable size grows (PathService answers NotLarger on the unlearned path).
//# - Specify that Path MTU Discovery not be done on a given path.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= reason=The ntcp-pathctl utility's estimate command (or set with estimate=OCTETS) sets or clears the owner's administrative PMTU estimate on an exact resolved path or a forwarding route under compare-and-set generations, bounded by the first hop and the family minimum. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. The value is compared with the path's accepted network estimate, never with an earlier administrative request or a transport-clipped size: a lower value lowers the accepted estimate at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same transaction and caps search and confirmed growth while set; an identical value is a no-op; a higher value is cached as the administrative estimate and changes no accepted estimate, hold, search bound or current size: it caps TCP PLPMTUD and the Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it, so the path's PMTU grows to it only through an acknowledged or echoed unfragmented probe (PathService::confirm_delivery), and a failed targeted probe is not reopened. Clearing removes the cap and keeps every hold. Queries report the cached administrative estimate, the accepted estimate with its provenance and each client's usable size and transport ceilings separately. On a discovery-disabled IPv6 path the 1280-octet budget applies whatever the value (8201-082); a larger value stays cached. Tests: ntcp-host src/tests/admin.rs (both families, deterministic caller time: downward fanout and hold arithmetic, equal no-op, an upward value deferred through the hold and then grown by a targeted probe exactly to the value, a failed targeted probe not reopened), ntcp-path tests/administration.rs (route and path precedence, idle eviction without promotion, replacement) and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin case shows a downward set shrinking IPv6 packets at once and an upward set growing nothing.
//# - Change the PMTU value associated with a given path.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= reason=Introduces the per-route administrative controls in 1191-091/092, which the ntcp-pathctl system utility now provides. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling holds output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases, both families): separate ntcp-pathctl processes query, refuse a stale compare-and-set with nothing changed, and set route and path policy against live tun_echo and the native runtime harness while they carry TCP and UDP traffic, with the effect captured on the wire. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
//# We suggest that an implementation provide a way for a system utility program to:
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= reason=PMTUD is configured per connection at creation; the owner's per-route and per-path discovery-disable flag is enforced through Host::administration (on IPv4 by leaving DF clear under the RFC 1122 sending limit) and set by the ntcp-pathctl utility. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling holds output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases, both families): after a discovery disable set with ntcp-pathctl, captured IPv6 packets of existing and new TCP connections and UDP replies are at most 1280 octets and IPv4 packets carry DF clear with a distinct leased Identification within the 576-octet Forwarder limit, with stream and datagram hashes intact and a neighbor destination unaffected; re-enabling restores DF and the full size. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both. Re-enabling restores probing without stale size proof (integration/rfc_host admin reenable case, both families, tun_echo's Host Echo adjunct, no fragmented traffic before the disable): while the path is disabled its fragmented UDP replies create adjunct demand, yet no Echo Request leaves toward it; right after ntcp-pathctl re-enables discovery, and before any adjunct reply, the utility reports the accepted estimate with its provenance and the adjunct's usable size at their pre-disable values, so the DF-clear TCP and fragment deliveries made while disabled proved nothing; then an unfragmented Echo Request with DF set, above the connectionless effective size, leaves, and after its real Echo Reply only the adjunct's usable size grows (PathService answers NotLarger on the unlearned path).
//# - Specify that PMTU Discovery not be done on a given route.
fn run(socket: &Path, args: &[String]) -> Result<u8, ClientError> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut client = Client::connect(socket)?;
    match args.as_slice() {
        ["routes"] => client.routes()?.iter().for_each(print_route),
        ["paths"] => client.paths()?.iter().for_each(print_path),
        ["clients", path] => {
            let Some(path) = token(path) else {
                return Ok(usage());
            };
            client.clients(path)?.iter().for_each(print_client);
        }
        ["select", text] => {
            let Some((network, length)) = text.split_once('/') else {
                return Ok(usage());
            };
            let (Ok(network), Ok(length)) = (network.parse::<IpAddr>(), length.parse::<u8>())
            else {
                return Ok(usage());
            };
            if let Payload::Selected { route } = client.ok(&Request::SelectRoute {
                destination: Prefix { network, length },
            })? {
                println!("route token={route:016x}");
            }
        }
        ["set", object, target, generation, rest @ ..] => {
            let (Some(route), Some(target), Ok(expected)) =
                (kind(object), token(target), generation.parse::<u64>())
            else {
                return Ok(usage());
            };
            let mut policy = Policy::default();
            for option in rest {
                match option.strip_prefix("estimate=") {
                    _ if *option == "disable" => policy.discovery_disabled = true,
                    Some(value) => match value.parse() {
                        Ok(v) => policy.estimate = Some(v),
                        Err(_) => return Ok(usage()),
                    },
                    None => return Ok(usage()),
                }
            }
            set(&mut client, route, target, expected, policy)?;
        }
        [action @ ("disable" | "enable"), object, target] => {
            let (Some(route), Some(target)) = (kind(object), token(target)) else {
                return Ok(usage());
            };
            let (expected, mut policy) = current(&mut client, route, target)?;
            policy.discovery_disabled = *action == "disable";
            set(&mut client, route, target, expected, policy)?;
        }
        ["estimate", object, target, value] => {
            let (Some(route), Some(target)) = (kind(object), token(target)) else {
                return Ok(usage());
            };
            let estimate = match *value {
                "clear" => None,
                v => match v.parse() {
                    Ok(v) => Some(v),
                    Err(_) => return Ok(usage()),
                },
            };
            let (expected, mut policy) = current(&mut client, route, target)?;
            policy.estimate = estimate;
            set(&mut client, route, target, expected, policy)?;
        }
        ["plateaus"] => {
            if let Payload::Plateaus(table) = client.ok(&Request::GetPlateaus)? {
                let values: Vec<String> = table.as_slice().iter().map(u32::to_string).collect();
                println!("plateaus={}", values.join(","));
            }
        }
        ["plateaus", values @ ..] => {
            let Ok(values) = values
                .iter()
                .map(|v| v.parse())
                .collect::<Result<Vec<u32>, _>>()
            else {
                return Ok(usage());
            };
            let Some(table) = Plateaus::new(&values) else {
                return Ok(usage());
            };
            client.ok(&Request::SetPlateaus(table))?;
            println!("applied plateaus");
        }
        ["aging"] => {
            if let Payload::Aging(aging) = client.ok(&Request::GetAging)? {
                match aging {
                    Aging::Unset => println!("aging=creation-policy"),
                    Aging::Infinity => println!("aging=infinity"),
                    Aging::Seconds(s) => println!("aging={s}"),
                }
            }
        }
        ["aging", value] => {
            let aging = match *value {
                "infinity" => Aging::Infinity,
                v => match v.parse() {
                    Ok(s) => Aging::Seconds(s),
                    Err(_) => return Ok(usage()),
                },
            };
            client.ok(&Request::SetAging(aging))?;
            println!("applied aging");
        }
        _ => return Ok(usage()),
    }
    Ok(0)
}

/// Run the utility with `args` (`SOCKET COMMAND...`, without the program
/// name), printing to stdout and stderr; returns the exit status.
pub fn main(args: &[String]) -> u8 {
    let Some((socket, rest)) = args.split_first() else {
        return usage();
    };
    match run(Path::new(socket), rest) {
        Ok(code) => code,
        Err(error) => fail(error),
    }
}
