// Control server and ntcp-pathctl: real utility process round trips against
// a live Host, every negative control of the protocol and the socket, and
// the bounded slot and deadline behavior.
//
// Second-uid evidence: these tests run as one uid (a one-uid user namespace
// or an unprivileged account cannot run a client under a second uid), so a
// denied peer is exercised with an allow-list that excludes the connecting
// uid, and filesystem denial is shown through the server's own private
// directory validation. A namespace root with CAP_DAC_OVERRIDE could still
// open a 0600 socket in a 0700 directory; SO_PEERCRED is what refuses it.

use ntcp::{
    ActiveOpenOptions, ConnectionConfig, Endpoint, EndpointConfig, ManagedOpenOptions,
    OutgoingIpv4Options, PmtudConfig,
};
use ntcp_host::path::{self, ContextId, ForwarderId, InterfaceKey, ScopedAddress};
use ntcp_host::{Forwarding, Host, Ipv4Receive, Ipv6Receive, ReceiveCapabilities};
use ntcp_path_control::protocol::{
    self, LENGTH_PREFIX, Payload, Policy, Request, Status, VERSION, opcode,
};
use ntcp_path_control::server::{FRAME_SECONDS, IDLE_SECONDS, SLOTS};
use ntcp_path_control::{ControlConfig, Server};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const SECOND: u64 = 1_000_000;

struct Side {
    host: Host,
    endpoint: Endpoint,
}

fn config() -> EndpointConfig {
    EndpointConfig {
        max_connections: 2,
        max_listeners: 2,
        connection: ConnectionConfig {
            mss: 1460,
            send_capacity: 65536,
            receive_capacity: 65536,
            timestamps: true,
            pmtud: Some(PmtudConfig::new(1500)),
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    }
}

fn addresses(v6: bool) -> (SocketAddr, SocketAddr) {
    if v6 {
        (
            "[2001:db8::1]:1000".parse().unwrap(),
            "[2001:db8::2]:8080".parse().unwrap(),
        )
    } else {
        (
            "192.0.2.1:1000".parse().unwrap(),
            "192.0.2.2:8080".parse().unwrap(),
        )
    }
}

// A Host on one 1500-octet link with a default route through a forwarder
// and one active TCP connection on the resulting path.
fn side(v6: bool) -> Side {
    side_with(v6, |paths, limits| (paths, limits))
}

// `side` with the Host limits adjusted by `limits`.
fn side_with(
    v6: bool,
    adjust: impl FnOnce(path::Limits, ntcp_host::Limits) -> (path::Limits, ntcp_host::Limits),
) -> Side {
    let (local, remote) = addresses(v6);
    let cfg = config();
    let (paths, limits) = ntcp_host::managed_limits(&cfg, 1, 1, 1, 4, 1).unwrap();
    let (paths, limits) = adjust(paths, limits);
    let mut host = Host::new(ContextId::new(77), paths, limits, cfg.connection.timebase).unwrap();
    let context = host
        .register_link(
            InterfaceKey(1),
            1500,
            ReceiveCapabilities {
                max_ip_packet: 65575,
                ipv4: Ipv4Receive::Unrecognized,
                ipv6: Ipv6Receive::BaseHeader,
                gro: false,
            },
            Forwarding::Forwarder(ForwarderId(9)),
        )
        .unwrap();
    host.register_source(
        ScopedAddress::new(local.ip(), None).unwrap(),
        context.link(),
    )
    .unwrap();
    host.add_route(path::Route {
        destination: path::IpPrefix::new(if v6 { "::" } else { "0.0.0.0" }.parse().unwrap(), 0)
            .unwrap(),
        source: None,
        dscp: None,
        link: context.link(),
        next_hop: path::NextHop::Forwarder(ForwarderId(9)),
        metric: 0,
    })
    .unwrap();
    let mut endpoint = Endpoint::new(cfg.clone(), [7; 32], 0, move |request| match request {
        ntcp::AddressValidation::Bind { local: address }
        | ntcp::AddressValidation::Open { local: address, .. } => address == local.ip(),
        ntcp::AddressValidation::Incoming { destination, .. } => destination == local.ip(),
        ntcp::AddressValidation::Route { source, .. } => source == local.ip(),
    })
    .unwrap();
    host.attach(&mut endpoint).unwrap();
    endpoint
        .enable_output_reservations_with_capacity(1)
        .unwrap();
    endpoint
        .connect_with_path_provider(
            0,
            local,
            remote,
            ManagedOpenOptions {
                transport: ActiveOpenOptions::from(&cfg.connection),
                dscp: 0,
                ipv4_options: OutgoingIpv4Options::default(),
                receive_authority: None,
            },
            &mut host,
        )
        .unwrap();
    Side { host, endpoint }
}

// A fresh private (0700) directory for one test's socket.
fn private_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ntcp-pathctl-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

fn serve(side: &mut Side, allow_uids: Vec<u32>, name: &str) -> (Server, PathBuf) {
    let socket = private_dir(name).join("control");
    let capability = side.host.administration();
    let server = Server::bind(
        &ControlConfig {
            socket: socket.clone(),
            allow_uids,
        },
        capability,
        side.endpoint.caller_timebase(),
    )
    .unwrap();
    (server, socket)
}

// Run the real utility as a separate process while the owner loop serves.
fn pathctl(server: &mut Server, side: &mut Side, socket: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ntcp-pathctl"))
        .arg(socket)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(20), "pathctl hung");
        server.service(&mut side.host, &mut side.endpoint, 0);
        std::thread::sleep(Duration::from_millis(1));
    }
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "pathctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.trim()
        .split(' ')
        .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
        .unwrap_or_else(|| panic!("{key} missing in {line}"))
}

#[test]
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=The ntcp-pathctl utility's estimate command (or set with estimate=OCTETS) sets or clears the owner's administrative PMTU estimate on a forwarding route, applied to every path resolved through it now and after idle eviction and reacquisition, or on an exact resolved path, under compare-and-set generations, bounded by the first hop and the family minimum; simultaneous route and path values intersect. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. The value is compared with the path's accepted network estimate, never with an earlier administrative request or a transport-clipped size: a lower value lowers the accepted estimate at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same transaction and caps search and confirmed growth while set; an identical value is a no-op; a higher value is cached as the administrative estimate and changes no accepted estimate, hold, search bound or current size: it caps TCP PLPMTUD and the Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it, so the route's PMTU grows to it only through an acknowledged or echoed unfragmented probe (PathService::confirm_delivery), and a failed targeted probe is not reopened; reacquisition through the route never promotes a deferred upward value. Clearing removes the cap and keeps every hold. Queries report the cached administrative estimate, the accepted estimate with its provenance and each client's usable size and transport ceilings separately. On a discovery-disabled IPv4 route the value is the RFC 1122 section 3.3.3 sending limit (actual knowledge, never above the accepted estimate). Endpoint::set_destination_route, set_route_mtu and lower_mss remain separate transport ceilings. Tests: ntcp-host src/tests/admin.rs (both families, deterministic caller time: downward fanout and hold arithmetic, equal no-op, an upward value deferred through the hold and then grown by a targeted probe exactly to the value, a failed targeted probe not reopened) and ipv4_policy.rs (a disabled route with a value sends at most it), ntcp-path tests/administration.rs (route and path precedence, eviction and reacquisition without promotion, single and bulk replacement) and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin case shows a downward set shrinking tun_echo's packets at once, an upward value recorded while the accepted estimate and packet sizes stay unchanged, and a disabled IPv4 path with a value of 1000 sending at most 1000 octets.
//# - Change the PMTU value associated with a given route.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=The ntcp-pathctl system utility provides both per-path controls of 8201-080/081 for IPv6 paths and for the forwarding routes they resolve through: discovery disable and enable and administrative PMTU estimate set and clear on a route or an exact resolved path under compare-and-set generations, with paginated route and path queries (the cached administrative estimate, the accepted network estimate with provenance, the shared packet budget, holds, revisions and each client's usable size, transport ceilings and deferred growth with its reason), the IPv4 plateau table and search aging. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. Tests: real utility process round trips in both families with every negative case (ntcp-path-control tests/control.rs, the native runtime and tun_echo control tests); the integration/rfc_host admin and native-admin cases run ntcp-pathctl as a separate process against live tun_echo and the native runtime harness during IPv6 traffic, refusing a stale compare-and-set with nothing changed.
//# It is suggested that an implementation provides a way for a system utility program to:
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=The ntcp-pathctl utility's disable command (or set with disable) sets the owner's discovery-disable flag on an exact resolved path or on a forwarding route, which applies to every path resolved through it now and later (a route disable dominates a path enable; clearing a path policy reveals the route policy); enable clears it. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. Host::admin_apply enforces the flag on the existing and future users of the path without rewriting any connection's creation configuration: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) is sent there; TCP stops every size-search change (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; outstanding TCP and adjunct size results selected under the previous policy publish nothing, including a probe acknowledged after the disable; and the path's IPv6 packet budget becomes the minimum link MTU (8201-082). Clearing restores each client's own configuration without fabricated size proof. Tests: ntcp-host src/tests/admin.rs (existing and future TCP capped at 1280, control and GSO segments, a probe submitted before the disable publishing nothing, policy-revision invalidation), adjunct.rs discovery_disable_stops_the_adjunct, emitter.rs discovery_disable_caps_ipv6_flows_at_1280_and_refuses_probes and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin and native-admin cases capture IPv6 output at most 1280 octets after ntcp-pathctl disables discovery during live traffic, with stream and datagram hashes intact and a neighbor destination keeping 1500-octet packets, and full size after enable. Re-enabling restores probing without stale size proof (integration/rfc_host admin reenable case, both families, tun_echo's Host Echo adjunct, no fragmented traffic before the disable): while the path is disabled its fragmented UDP replies create adjunct demand, yet no Echo Request leaves toward it; right after ntcp-pathctl re-enables discovery, and before any adjunct reply, the utility reports the accepted estimate with its provenance and the adjunct's usable size at their pre-disable values, so the deliveries made while disabled proved nothing; then an unfragmented Echo Request above the connectionless effective size leaves, and after its real Echo Reply only the adjunct's usable size grows (PathService answers NotLarger on the unlearned path).
//# - Specify that Path MTU Discovery not be done on a given path.
//= https://www.rfc-editor.org/rfc/rfc8201#section-5.6
//= type=test
//= reason=The ntcp-pathctl utility's estimate command (or set with estimate=OCTETS) sets or clears the owner's administrative PMTU estimate on an exact resolved path or a forwarding route under compare-and-set generations, bounded by the first hop and the family minimum. The ntcp-pathctl utility (crates/adapters/ntcp-path-control, src/bin/ntcp-pathctl.rs) talks to an opt-in local control server that the native runtime (control.socket, control.allow_uids, separate from route.*) and tun_echo (NTCP_CONTROL_SOCKET) serve on their owner loops: an absolute-pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized by the kernel's SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with bounded frames, pages, peer slots and deadlines and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing. The server acts through the Host-instance-bound Administration capability (Host::administration), and every route or path policy change is one serialized Host::admin_apply transaction that validates every affected TCP binding read-only, failing with nothing changed, and then applies the policy to the existing users of each affected path at once; future users are created under it. The value is compared with the path's accepted network estimate, never with an earlier administrative request or a transport-clipped size: a lower value lowers the accepted estimate at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same transaction and caps search and confirmed growth while set; an identical value is a no-op; a higher value is cached as the administrative estimate and changes no accepted estimate, hold, search bound or current size: it caps TCP PLPMTUD and the Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it, so the path's PMTU grows to it only through an acknowledged or echoed unfragmented probe (PathService::confirm_delivery), and a failed targeted probe is not reopened. Clearing removes the cap and keeps every hold. Queries report the cached administrative estimate, the accepted estimate with its provenance and each client's usable size and transport ceilings separately. On a discovery-disabled IPv6 path the 1280-octet budget applies whatever the value (8201-082); a larger value stays cached. Tests: ntcp-host src/tests/admin.rs (both families, deterministic caller time: downward fanout and hold arithmetic, equal no-op, an upward value deferred through the hold and then grown by a targeted probe exactly to the value, a failed targeted probe not reopened), ntcp-path tests/administration.rs (route and path precedence, idle eviction without promotion, replacement) and the utility round trips in ntcp-path-control tests/control.rs; the integration/rfc_host admin case shows a downward set shrinking IPv6 packets at once and an upward set growing nothing.
//# - Change the PMTU value associated with a given path.
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=Introduces the per-route administrative controls in 1191-091/092, which the ntcp-pathctl system utility now provides. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling and the start quiet period hold output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases, both families): separate ntcp-pathctl processes query, refuse a stale compare-and-set with nothing changed, and set route and path policy against live tun_echo and the native runtime harness while they carry TCP and UDP traffic, with the effect captured on the wire. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both.
//# We suggest that an implementation provide a way for a system utility program to:
//= https://www.rfc-editor.org/rfc/rfc1191#section-6.6
//= type=test
//= reason=PMTUD is configured per connection at creation; the owner's per-route and per-path discovery-disable flag is enforced through Host::administration (on IPv4 by leaving DF clear under the RFC 1122 sending limit) and set by the ntcp-pathctl utility. T13 supplies the mechanisms those controls build on: the Host IdentifierAllocator (every non-atomic IPv4 datagram the Host originates, fragmented or DF-clear, carries a leased Identification), the fragmenting datagram emitter and Host UDP Probe mode; it adds no administrative control. The administrative model exists: PathService stores owner policy (discovery disable and an administrative PMTU estimate) per forwarding route and per exact resolved path under compare-and-set generations and keeps a route's administrative restriction (the lowest value its estimate imposed on a path) across idle path eviction and upward sets until the route's estimate is cleared, and its outstanding administrative hold across clears as well, and installs later paths of the route under them, so reacquisition never promotes a deferred upward value; Host::administration issues a Host-instance-bound capability for query (the administrative estimate, the accepted network estimate with its provenance, each client's usable size, TCP transport ceilings, and the TCP and Echo adjunct search diagnostic), read-only candidate validation and apply. Each estimate operation compares with the path's accepted network estimate: a downward value lowers it at once with a fresh negative revision and a hold of max(old, now + 600 seconds), notifies every client of the path in the same administration transaction and caps the search and confirmed growth while set; an equal value is a no-op; an upward value changes no accepted estimate, hold, search lower bound, current size or confirmed bound and defines a search transition: it caps TCP PLPMTUD and the Host Echo adjunct search, and once per value the first probe the existing hold, cooldown, loss-recovery, data/window and adjunct-demand rules allow targets it (clipped by the first-hop, transport and negative-evidence bounds; the deferral or clip is reported), so the accepted estimate grows only through an acknowledged or echoed unfragmented probe and PathService::confirm_delivery, and a failed targeted probe is not reopened by later revisions; clearing removes the cap for live and later paths and keeps every hold, while a live path incarnation keeps the accepted estimate a restriction lowered (no older larger value is restored), which relaxes only through confirmed delivery there. Size proof follows the final submitted bytes: a TCP record raises max_acked or search_low or reaches confirm_delivery only when its submitted packet was unfragmentable (IPv4 DF set, certified from Host::submit's physical receipt for managed output), so DF-clear IP_PMTUDISC_DONT output proves no size. Every change is one serialized Host::admin_apply transaction: it validates read-only every TCP binding on each affected path (complete option-bearing headers plus one payload octet), failing with nothing changed, then stores the policy and applies each binding's new snapshot, each UDP flow's change notification and the Echo adjunct state at once; best-effort output never blocks a change: a held stateless output lease is revalidated by the submission barrier and a queued ICMP message is sized at emission, exactly as after a trusted PTB decrease (one that no longer fits is refused or counted unsent), so a remote peer cannot hold the owner's restriction off; the IPv4 plateau table and RFC 4821 search aging (existing TCP connections at once, future ones before their first output) are administered through the same capability. The discovery-disable flag is enforced on existing and future users: no TCP PLPMTUD probe, Echo adjunct probe or UDP Probe-mode datagram (refused with DiscoveryDisabled) leaves a flagged path and the submission barrier refuses any packet above its ordinary budget; TCP stops size-search changes (probe success, implicit growth, isolated-loss narrowing, verification and black-hole fallback) while loss recovery continues; each change invalidates outstanding TCP and adjunct size results selected under the previous policy; and on IPv6 the path's packet budget is at most 1280 octets, which every physical packet of existing and newly created users obeys (Host tests: TCP output and retransmissions, SYN, SYN-ACK, FIN and RST control segments and stateless resets, each physical software-GSO segment of an aggregate held across the disable and of new aggregates, UDP Refuse and Fragment, and Echo replies). On IPv4 the flag leaves DF clear on the packets of the route or path whatever the upper layer requests (RFC 1191 section 6.6, the user's recorded decision B): TCP segments including control segments and connections created with PLPMTUD, whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments of UDP Fragment mode and Echo replies (MF, offsets and the datagram's one Identification kept, every rewritten header checksum recomputed), each DF-clear datagram carrying an Identification leased from the Host allocator (the RFC 6864 ceiling and the start quiet period hold output instead of reusing a value); its sending limit is the RFC 1122 section 3.3.3 EMTU_S: the owner's administrative value when set (never above the accepted estimate), otherwise at most 576 octets through a gateway or forwarder and the accepted estimate within the link MTU on-link, the packet budget existing and future TCP, UDP Refuse and Fragment, Echo replies and udp_datagram_limits use. The TCP submission barrier (Host::submit) refuses a DF-set IPv4 packet on such a path; Host::clears_dont_fragment and Host::lease_df_clear apply the rewrite at each physical submission in the native runtime (a route disable dominates the socket's IP_MTU_DISCOVER) and tun_echo, and DF-clear deliveries prove no size (Host tests in ntcp-host src/tests/ipv4_policy.rs, PathService tests of the on-link, gateway and forwarder limits). T12 stage 6 adds the system utility: the ntcp-path-control crate's opt-in local control socket (an absolute pathname Unix stream socket of mode 0600 in a private 0700 directory owned by the owner; every request, queries included, authorized on the accepted descriptor by its kernel SO_PEERCRED uid against an allow-list defaulting to the owner's effective uid, without a root bypass and failing closed; a versioned length-prefixed binary protocol with fixed-width fields, frame and page bounds derived from the largest encoded messages, bounded peer slots, per-pass work, frame-completion, reply-drain and idle deadlines, and explicit statuses for malformed, oversized, unknown-version, unknown-opcode, unauthorized and stale requests, which change nothing), served from the owner loop of the native runtime (control.socket, control.allow_uids, separate from route.*; native descriptors and direct system calls on the owner thread, before the held-output early continue) and of tun_echo (NTCP_CONTROL_SOCKET), through the Host-bound administration capability, and the ntcp-pathctl utility: paginated route and path queries carrying a listing revision (generations, policy, the cached administrative estimate, the accepted estimate with provenance, the shared packet budget, holds and revisions, and per client the usable size, transport ceilings and deferred growth with its reason), discovery disable and enable and administrative estimate set and clear on a route or an exact path under compare-and-set generations, the IPv4 plateau table and search aging (real utility process round trips in ntcp-path-control tests/control.rs, the native runtime and tun_echo tests). Namespace evidence (integration/rfc_host admin and native-admin cases, both families): after a discovery disable set with ntcp-pathctl, captured IPv6 packets of existing and new TCP connections and UDP replies are at most 1280 octets and IPv4 packets carry DF clear with a distinct leased Identification within the 576-octet Forwarder limit, with stream and datagram hashes intact and a neighbor destination unaffected; re-enabling restores DF and the full size. Host::udp_send, the T9 whole-datagram API that tun_echo's Refuse-mode UDP echo replies use, leaves its IPv4 datagrams on such a route DF clear with a leased Identification as well, holding a datagram on identifier backpressure (UdpSendError::Backpressure) and refusing one above the sending limit with its payload limit (ntcp-host test disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams); the integration/rfc_host admin refuse case captures tun_echo's Refuse-mode replies after ntcp-pathctl disables discovery on its IPv4 path: DF clear, distinct nonzero Identifications and at most 576 octets, a larger reply refused locally with the 548-octet payload limit, while the neighbor destination keeps DF and re-enabling restores it. Route isolation of the IPv4 policy is shown in-process: ntcp-host test disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments disables one of two routes sharing a link and next hop, whose fragments leave DF clear while the other route keeps DF on its fragments; on the wire, the integration/rfc_host icmp route-isolation case gives the datagram_drive Host a second route (the same link and Forwarder next hop, selected by DSCP): after the owner disables discovery on its default route, that route's source fragments leave DF clear with one nonzero leased Identification per datagram and at most 576 octets, while the neighboring enabled route keeps DF on its fragments and the peer reassembles both. Re-enabling restores probing without stale size proof (integration/rfc_host admin reenable case, both families, tun_echo's Host Echo adjunct, no fragmented traffic before the disable): while the path is disabled its fragmented UDP replies create adjunct demand, yet no Echo Request leaves toward it; right after ntcp-pathctl re-enables discovery, and before any adjunct reply, the utility reports the accepted estimate with its provenance and the adjunct's usable size at their pre-disable values, so the DF-clear TCP and fragment deliveries made while disabled proved nothing; then an unfragmented Echo Request with DF set, above the connectionless effective size, leaves, and after its real Echo Reply only the adjunct's usable size grows (PathService answers NotLarger on the unlearned path).
//# - Specify that PMTU Discovery not be done on a given route.
fn utility_process_round_trips_both_families() {
    for v6 in [false, true] {
        let mut side = side(v6);
        let (mut server, socket) = serve(&mut side, Vec::new(), if v6 { "rt6" } else { "rt4" });
        // The socket is 0600 inside the private directory.
        let mode = std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let routes = stdout(&pathctl(&mut server, &mut side, &socket, &["routes"]));
        let route = routes.lines().next().unwrap().to_string();
        let token = field(&route, "token").to_string();
        assert_eq!(field(&route, "generation"), "0");
        assert_eq!(field(&route, "disabled"), "0");
        let selected = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["select", if v6 { "::/0" } else { "0.0.0.0/0" }],
        ));
        assert_eq!(selected.trim(), format!("route token={token}"));

        let paths = stdout(&pathctl(&mut server, &mut side, &socket, &["paths"]));
        let path = paths.lines().next().unwrap().to_string();
        assert_eq!(field(&path, "route"), token);
        assert_eq!(field(&path, "budget"), "1500");
        assert_eq!(field(&path, "accepted"), "1500:unlearned");
        assert_eq!(field(&path, "administrative_estimate"), "-");
        let path_token = field(&path, "token").to_string();
        let clients = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["clients", &path_token],
        ));
        assert!(
            clients.lines().any(|l| field(l, "kind") == "tcp"),
            "{clients}"
        );

        // Disable discovery on the route: the path's budget becomes the
        // IPv6 minimum link MTU, or for IPv4 behind a forwarder the RFC
        // 1122 3.3.3 limit of 576 octets.
        let applied = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["disable", "route", &token],
        ));
        assert_eq!(applied.trim(), "applied generation=1 affected_paths=1");
        let path = stdout(&pathctl(&mut server, &mut side, &socket, &["paths"]));
        assert_eq!(field(&path, "effective_disabled"), "route");
        assert_eq!(field(&path, "budget"), if v6 { "1280" } else { "576" });
        let cap = side.host.administration();
        let snapshot = side.host.admin_paths(&cap).unwrap().next().unwrap();
        assert!(snapshot.snapshot.discovery_disabled());

        // An administrative estimate below the accepted (unlearned
        // first-hop) estimate is a downward restriction: it lowers the
        // accepted estimate at once with the Host's 600-second hold.
        let applied = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["estimate", "route", &token, "1400"],
        ));
        assert!(applied.starts_with("applied generation=2"), "{applied}");
        let path = stdout(&pathctl(&mut server, &mut side, &socket, &["paths"]));
        assert_eq!(field(&path, "administrative_estimate"), "1400:route");
        assert_eq!(field(&path, "accepted"), "1400:learned");
        assert_eq!(field(&path, "learned"), "1400");
        assert_eq!(field(&path, "retry_not_before"), "600000000");
        // Disabled: IPv6 stays at 1280 whatever the value; IPv4 sends with
        // the owner's value as its actual knowledge of the path.
        assert_eq!(field(&path, "budget"), if v6 { "1280" } else { "1400" });

        // A stale compare-and-set changes nothing and exits 1.
        let denied = pathctl(
            &mut server,
            &mut side,
            &socket,
            &["set", "route", &token, "1"],
        );
        assert_eq!(denied.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&denied.stderr).trim(),
            "status=stale"
        );
        let route = stdout(&pathctl(&mut server, &mut side, &socket, &["routes"]));
        assert_eq!(field(&route, "generation"), "2");
        assert_eq!(field(&route, "disabled"), "1");
        assert_eq!(field(&route, "estimate"), "1400");

        // Enable and clear through explicit compare-and-set.
        let applied = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["set", "route", &token, "2"],
        ));
        assert!(applied.starts_with("applied generation=3"), "{applied}");
        let path = stdout(&pathctl(&mut server, &mut side, &socket, &["paths"]));
        assert_eq!(field(&path, "effective_disabled"), "-");
        // Clearing never restores the older, larger accepted estimate.
        assert_eq!(field(&path, "budget"), "1400");
        assert_eq!(field(&path, "administrative_estimate"), "-");

        // Exact-path policy.
        let applied = stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["disable", "path", &path_token],
        ));
        assert!(applied.starts_with("applied"), "{applied}");
        let path = stdout(&pathctl(&mut server, &mut side, &socket, &["paths"]));
        assert_eq!(field(&path, "effective_disabled"), "path");

        // Plateau table and search aging.
        let plateaus = stdout(&pathctl(&mut server, &mut side, &socket, &["plateaus"]));
        assert_eq!(
            plateaus.trim(),
            "plateaus=65535,9001,8896,8500,1500,1492,1460,576,68"
        );
        stdout(&pathctl(
            &mut server,
            &mut side,
            &socket,
            &["plateaus", "1500", "1006", "576", "68"],
        ));
        let plateaus = stdout(&pathctl(&mut server, &mut side, &socket, &["plateaus"]));
        assert_eq!(plateaus.trim(), "plateaus=1500,1006,576,68");
        let invalid = pathctl(
            &mut server,
            &mut side,
            &socket,
            &["plateaus", "576", "1500", "68"],
        );
        assert_eq!(
            String::from_utf8_lossy(&invalid.stderr).trim(),
            "status=invalid"
        );
        let aging = stdout(&pathctl(&mut server, &mut side, &socket, &["aging"]));
        assert_eq!(aging.trim(), "aging=creation-policy");
        stdout(&pathctl(&mut server, &mut side, &socket, &["aging", "900"]));
        let aging = stdout(&pathctl(&mut server, &mut side, &socket, &["aging"]));
        assert_eq!(aging.trim(), "aging=900");
        let short = pathctl(&mut server, &mut side, &socket, &["aging", "299"]);
        assert_eq!(
            String::from_utf8_lossy(&short.stderr).trim(),
            "status=invalid"
        );
        let aging = stdout(&pathctl(&mut server, &mut side, &socket, &["aging"]));
        assert_eq!(aging.trim(), "aging=900");
        drop(server);
        // The server removes its own socket.
        assert!(std::fs::symlink_metadata(&socket).is_err());
    }
}

fn raw(
    stream: &mut UnixStream,
    server: &mut Server,
    side: &mut Side,
    frame: &[u8],
    now: u64,
) -> Option<(Status, Payload)> {
    stream.write_all(frame).unwrap();
    for _ in 0..4 {
        server.service(&mut side.host, &mut side.endpoint, now);
    }
    read_reply(stream)
}

fn read_reply(stream: &mut UnixStream) -> Option<(Status, Payload)> {
    let mut prefix = [0u8; LENGTH_PREFIX];
    stream.read_exact(&mut prefix).ok()?;
    let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut body).ok()?;
    let response = protocol::decode_response(&body).unwrap();
    Some((response.status, response.payload))
}

fn connect(socket: &Path) -> UnixStream {
    let stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

// The server closed the connection: end of stream (or a reset when it
// closed with unread pipelined requests), after any data it wrote.
fn closed(stream: &mut UnixStream) -> bool {
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) => return e.kind() == std::io::ErrorKind::ConnectionReset,
        }
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}

#[test]
fn malformed_unknown_oversized_stale_and_inconsistent_requests_change_nothing() {
    let mut side = side(false);
    let (mut server, socket) = serve(&mut side, Vec::new(), "negative");
    let cap = side.host.administration();
    let before = side.host.paths().admin_revision();
    let mut s = connect(&socket);
    let route = match raw(
        &mut s,
        &mut server,
        &mut side,
        &protocol::encode_request(&Request::QueryRoutes {
            cursor: 0,
            revision: 0,
        }),
        0,
    ) {
        Some((Status::Ok, Payload::Routes(header, entries))) => {
            assert_eq!(header.total, 1);
            (entries[0].token, header.revision)
        }
        other => panic!("{other:?}"),
    };
    let disable = Policy {
        discovery_disabled: true,
        estimate: None,
    };
    // Unknown version, unknown opcode and malformed bodies keep the
    // connection open.
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &framed(&[
                VERSION + 1,
                opcode::QUERY_ROUTES,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]),
            0
        )
        .map(|r| r.0),
        Some(Status::UnknownVersion)
    );
    assert_eq!(
        raw(&mut s, &mut server, &mut side, &framed(&[VERSION, 99]), 0).map(|r| r.0),
        Some(Status::UnknownOpcode)
    );
    let mut set = protocol::encode_request(&Request::SetRoutePolicy {
        route: route.0,
        expected: 0,
        policy: disable,
    });
    set.truncate(set.len() - 1);
    let len = (set.len() - LENGTH_PREFIX) as u32;
    set[..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(
        raw(&mut s, &mut server, &mut side, &set, 0).map(|r| r.0),
        Some(Status::Malformed)
    );
    // Stale compare-and-set and a token no live route carries.
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::SetRoutePolicy {
                route: route.0,
                expected: 5,
                policy: disable
            }),
            0
        )
        .map(|r| r.0),
        Some(Status::Stale)
    );
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::SetRoutePolicy {
                route: route.0 ^ 1,
                expected: 0,
                policy: disable
            }),
            0
        )
        .map(|r| r.0),
        Some(Status::Stale)
    );
    // An inconsistent continuation is rejected.
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::QueryRoutes {
                cursor: 1,
                revision: route.1 ^ 1
            }),
            0
        )
        .map(|r| r.0),
        Some(Status::Inconsistent)
    );
    assert_eq!(side.host.paths().admin_revision(), before);
    assert_eq!(
        side.host.admin_routes(&cap).unwrap().next().unwrap().policy,
        Default::default()
    );
    // A continuation after a change sees a different revision.
    assert!(matches!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::SetRoutePolicy {
                route: route.0,
                expected: 0,
                policy: disable
            }),
            0
        ),
        Some((
            Status::Ok,
            Payload::Applied {
                generation: 1,
                affected: 1
            }
        ))
    ));
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::QueryRoutes {
                cursor: 1,
                revision: route.1
            }),
            0
        )
        .map(|r| r.0),
        Some(Status::Inconsistent)
    );
    // An oversized announced length is refused and the connection closes.
    let oversized = framed(&[0; protocol::MAX_REQUEST_BODY + 1]);
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &oversized[..LENGTH_PREFIX],
            0
        )
        .map(|r| r.0),
        Some(Status::Oversized)
    );
    for _ in 0..4 {
        server.service(&mut side.host, &mut side.endpoint, 0);
    }
    assert!(closed(&mut s));
    assert_eq!(side.host.paths().admin_revision(), before + 1);
}

#[test]
fn peer_credentials_outside_the_allow_list_are_refused_before_dispatch() {
    let mut side = side(true);
    let me = unsafe { libc::geteuid() };
    // An allow-list that excludes the connecting uid: no root bypass and no
    // implicit owner when a list is given.
    let (mut server, socket) = serve(&mut side, vec![me.wrapping_add(1)], "denied");
    let cap = side.host.administration();
    let before = side.host.paths().admin_revision();
    let mut s = connect(&socket);
    let route = side.host.admin_routes(&cap).unwrap().next().unwrap();
    // Queries are authorized too.
    assert_eq!(
        raw(
            &mut s,
            &mut server,
            &mut side,
            &protocol::encode_request(&Request::QueryRoutes {
                cursor: 0,
                revision: 0
            }),
            0
        )
        .map(|r| r.0),
        Some(Status::Unauthorized)
    );
    assert!(closed(&mut s));
    let denied = pathctl(
        &mut server,
        &mut side,
        &socket,
        &["disable", "route", "0000000000000001"],
    );
    assert_eq!(
        String::from_utf8_lossy(&denied.stderr).trim(),
        "status=unauthorized"
    );
    assert_eq!(side.host.paths().admin_revision(), before);
    assert_eq!(side.host.admin_routes(&cap).unwrap().next().unwrap(), route);
}

#[test]
fn full_slots_answer_busy_and_deadlines_bound_trickling_blocked_and_idle_peers() {
    let mut side = side(false);
    let (mut server, socket) = serve(&mut side, Vec::new(), "slots");
    let mut held: Vec<UnixStream> = (0..SLOTS).map(|_| connect(&socket)).collect();
    server.service(&mut side.host, &mut side.endpoint, 0);
    let mut extra = connect(&socket);
    server.service(&mut side.host, &mut side.endpoint, 0);
    assert_eq!(read_reply(&mut extra).map(|r| r.0), Some(Status::Busy));
    assert!(closed(&mut extra));

    // Slot 0 trickles a partial frame; slot 1 pipelines requests without
    // reading replies until its reply cannot be written; slots 2 and 3
    // stay idle (slot 3 sends one request first, which renews its idle
    // deadline).
    held[0].write_all(&[0, 0]).unwrap();
    let query = protocol::encode_request(&Request::QueryRoutes {
        cursor: 0,
        revision: 0,
    });
    held[1].set_nonblocking(true).unwrap();
    held[3].write_all(&query).unwrap();
    // Keep pipelining while the server serves; it stops reading once a
    // reply cannot be written.
    for _ in 0..20_000 {
        let _ = held[1].write(&query);
        server.service(&mut side.host, &mut side.endpoint, SECOND);
    }
    assert_eq!(read_reply(&mut held[3]).map(|r| r.0), Some(Status::Ok));
    // A frame not completed within FRAME_SECONDS, and a reply not drained
    // within FRAME_SECONDS, close their slots; idle slots stay.
    let frame_deadline = SECOND + FRAME_SECONDS * SECOND + 1;
    server.service(&mut side.host, &mut side.endpoint, frame_deadline);
    assert!(closed(&mut held[0]));
    held[1].set_nonblocking(false).unwrap();
    held[1]
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(closed(&mut held[1]));
    // Freed slots serve new peers.
    let mut fresh = connect(&socket);
    assert_eq!(
        raw(&mut fresh, &mut server, &mut side, &query, frame_deadline).map(|r| r.0),
        Some(Status::Ok)
    );
    // Idle deadline: slot 2 (idle since 0) closes after IDLE_SECONDS; slot
    // 3 (renewed at 1 s) and the fresh peer stay until theirs.
    server.service(
        &mut side.host,
        &mut side.endpoint,
        IDLE_SECONDS * SECOND + 1,
    );
    assert!(closed(&mut held[2]));
    held[3].set_nonblocking(true).unwrap();
    let mut byte = [0u8; 1];
    assert!(
        matches!(held[3].read(&mut byte), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
    server.service(
        &mut side.host,
        &mut side.endpoint,
        frame_deadline + IDLE_SECONDS * SECOND + 1,
    );
    held[3].set_nonblocking(false).unwrap();
    assert!(closed(&mut held[3]));
    assert!(closed(&mut fresh));
}

#[test]
fn socket_pathname_safety() {
    let mut side = side(false);
    let (cap, timebase) = (side.host.administration(), side.endpoint.caller_timebase());
    let bind = |socket: PathBuf| {
        Server::bind(
            &ControlConfig {
                socket,
                allow_uids: Vec::new(),
            },
            cap.clone(),
            timebase,
        )
    };
    // Relative pathnames and directories with group/other access are refused.
    assert!(bind(PathBuf::from("relative/control")).is_err());
    let open = private_dir("open");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        bind(open.join("control")).err().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    // A symbolic link to a private directory is not a private directory.
    let private = private_dir("target");
    let link = private_dir("link-parent").join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    assert_eq!(
        bind(link.join("control")).err().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    // An unrelated existing file is never unlinked.
    let file = private.join("control");
    std::fs::write(&file, b"keep").unwrap();
    assert_eq!(
        bind(file.clone()).err().unwrap().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    // A live server's socket is not taken over.
    let socket = private.join("live");
    let live = bind(socket.clone()).unwrap();
    assert_eq!(
        bind(socket.clone()).err().unwrap().kind(),
        std::io::ErrorKind::AddrInUse
    );
    drop(live);
    // A stale socket of ours (listener gone, pathname left) is replaced.
    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(stale);
    assert!(std::fs::symlink_metadata(&socket).is_ok());
    let replaced = bind(socket.clone()).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // Drop removes only the socket it bound: a pathname replaced behind it
    // survives.
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"other").unwrap();
    drop(replaced);
    assert_eq!(std::fs::read(&socket).unwrap(), b"other");
}

// Parent decision D23: a listing's revision covers each entry's identity
// and administrative state, never values that change with traffic or time.
// With more than one page of paths (one UDP flow pinned to many
// destinations leaves their paths cached), a trusted decrease and a new
// pin between two page requests leave the continuation consistent and the
// second page reports the new live values; a path policy change (a new
// policy and generation) between pages makes it Inconsistent.
#[test]
fn listing_revisions_ignore_live_values_but_not_administrative_changes() {
    let wanted = protocol::PATHS_PER_PAGE + 2;
    let udp = ntcp_host::UdpLimits {
        flows: 1,
        receive_datagrams: 1,
        max_payload: 1500,
        events: 1,
        evicted_signatures: 1,
        probe_receipts: 1,
    };
    let mut side = side_with(false, |paths, limits| {
        let (paths, limits) = ntcp_host::managed_udp_limits(paths, limits, udp).unwrap();
        (
            path::Limits {
                paths: paths.paths + wanted,
                ..paths
            },
            limits,
        )
    });
    let (local, _) = addresses(false);
    let flow = side
        .host
        .udp_open(
            &side.endpoint,
            SocketAddr::new(local.ip(), 5000),
            None,
            ntcp_host::UdpOptions {
                dscp: 0,
                hop_limit: 64,
            },
        )
        .unwrap();
    let remote = |i: usize| std::net::IpAddr::from([198, 51, 100, i as u8 + 1]);
    for i in 0..wanted {
        side.host
            .udp_path_limits(&side.endpoint, flow, Some(remote(i)))
            .unwrap();
    }
    let cap = side.host.administration();
    let total = side.host.admin_paths(&cap).unwrap().count();
    assert!(total > protocol::PATHS_PER_PAGE, "more than one page");
    let (mut server, socket) = serve(&mut side, Vec::new(), "pages");
    let mut s = connect(&socket);
    let query = |cursor: u32, revision: u64| {
        protocol::encode_request(&Request::QueryPaths { cursor, revision })
    };
    let first = |s: &mut UnixStream, server: &mut Server, side: &mut Side| match raw(
        s,
        server,
        side,
        &query(0, 0),
        0,
    ) {
        Some((Status::Ok, Payload::Paths(header, entries))) => {
            assert_eq!(header.total as usize, total);
            assert_eq!(entries.len(), protocol::PATHS_PER_PAGE);
            header.revision
        }
        other => panic!("{other:?}"),
    };
    // A path on the second page and its live values before the change.
    let target = side
        .host
        .admin_paths(&cap)
        .unwrap()
        .nth(protocol::PATHS_PER_PAGE)
        .unwrap();
    let target_path = target.snapshot.path();
    let revision = first(&mut s, &mut server, &mut side);
    // Live changes between the pages: the shared estimate of the target
    // path drops (version, accepted and learned estimates, budget, hold
    // and negative revision change) and the flow pins another destination.
    side.host.trusted_decrease(0, target_path, 1200).unwrap();
    side.host
        .udp_path_limits(&side.endpoint, flow, Some(remote(0)))
        .unwrap();
    let cursor = protocol::PATHS_PER_PAGE as u32;
    match raw(&mut s, &mut server, &mut side, &query(cursor, revision), 0) {
        Some((Status::Ok, Payload::Paths(header, entries))) => {
            assert_eq!(header.revision, revision);
            assert_eq!(header.cursor, cursor);
            assert_eq!(entries.len(), total - protocol::PATHS_PER_PAGE);
            // The page reports the live values current when it was built.
            assert_eq!(entries[0].learned, Some(1200));
            assert_eq!(entries[0].budget, Some(1200));
        }
        other => panic!("{other:?}"),
    }
    // An administrative change between the pages: a path policy (a new
    // policy and generation) makes the continuation inconsistent.
    let revision = first(&mut s, &mut server, &mut side);
    let target = side.host.admin_path(&cap, target_path).unwrap();
    let candidate = side
        .host
        .admin_validate(
            &cap,
            0,
            path::AdminChange {
                target: path::AdminTarget::Path(target_path),
                expected: target.generation,
                policy: path::AdminPolicy {
                    discovery_disabled: true,
                    estimate: None,
                },
            },
        )
        .unwrap();
    side.host
        .admin_apply(&cap, &mut side.endpoint, candidate)
        .unwrap();
    assert_eq!(
        raw(&mut s, &mut server, &mut side, &query(cursor, revision), 0).map(|r| r.0),
        Some(Status::Inconsistent)
    );
}

// Parent decision D24: the client reports the reply a server delivered
// before closing, even when the server closed before the request was
// written (the write then fails with a broken pipe). A denied peer gets
// Unauthorized, a peer of a full server Busy, from Client::call.
#[test]
fn refusals_at_accept_reach_client_call_after_the_server_closed() {
    use ntcp_path_control::client::Client;
    let mut side = side(false);
    let me = unsafe { libc::geteuid() };
    let (mut server, socket) = serve(&mut side, vec![me.wrapping_add(1)], "refused");
    let mut client = Client::connect(&socket).unwrap();
    server.service(&mut side.host, &mut side.endpoint, 0);
    let request = Request::QueryRoutes {
        cursor: 0,
        revision: 0,
    };
    assert_eq!(
        client.call(&request).map(|r| r.status).ok(),
        Some(Status::Unauthorized)
    );
    drop(server);

    let (mut server, socket) = serve(&mut side, Vec::new(), "full");
    let held: Vec<UnixStream> = (0..SLOTS).map(|_| connect(&socket)).collect();
    server.service(&mut side.host, &mut side.endpoint, 0);
    let mut client = Client::connect(&socket).unwrap();
    server.service(&mut side.host, &mut side.endpoint, 0);
    assert_eq!(
        client.call(&request).map(|r| r.status).ok(),
        Some(Status::Busy)
    );
    drop(held);
}
