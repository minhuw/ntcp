# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Owner path administration on the wire: ntcp-pathctl against live tun_echo.

The topology is the ICMP scenario's (ntcp <-> TUN <-> Linux router <-> veth
<-> Linux peer namespace) with a 1500-octet egress, so no router PTB is
involved: every size change on the wire comes from the administration. Two
kernel peers share the peer namespace: P (the administered path) and N, a
neighbor destination resolved through the same tun_echo route whose path is
never administered. ntcp-pathctl runs as a separate process and reaches
tun_echo's opt-in control socket (NTCP_CONTROL_SOCKET in a private 0700
directory the harness created); every request crosses the real Unix socket,
SO_PEERCRED check and owner-thread service. N shares P's route because
tun_echo has a single (Forwarder) route: this case shows exact-path
isolation on the wire; isolation between routes is shown on the wire by
the icmp route-isolation case (a second, DSCP-selected route of the
datagram_drive Host keeps DF on its fragments while the disabled default
route clears it) and in-process by the ntcp-host test
disabling_one_ipv4_route_leaves_a_neighbor_route_keeping_df_on_fragments.
tun_echo runs in Fragment mode
with the Linux peers' stated reassembly capacity, so both whole datagrams
and source fragments are observed.

Expectations, per the administration's documented policy:
- disabled IPv6 path: no physical packet above 1280 octets (RFC 8201 5.6);
- disabled IPv4 path: DF clear and a leased (nonzero, unrepeated)
  Identification on every packet, source fragments included, and at most 576
  octets through tun_echo's Forwarder route without an administrative value
  (RFC 1191 6.6, RFC 1122 3.3.3 EMTU_S) or at most the administrative value
  with one;
- the neighbor path keeps DF and its full size throughout;
- a downward estimate shrinks packets at once; an upward one is recorded but
  grows nothing (post-hold validated growth is covered by the deterministic
  caller-time Host tests, not by a 600-second wait here).
"""
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import icmp
from linux_peer import fnv, pattern

HERE = Path(__file__).resolve().parent
TCP_BYTES = 24576
FRAGMENTED_REQUEST = 3000
# RFC 1122 3.3.3: EMTU_S <= 576 off the connected network (Forwarder route).
IPV4_OFFLINK = 576
IPV6_MINIMUM = 1280
# Per family: downward and upward administrative values (below, then above
# the 1500-octet accepted estimate of this topology; IPv6 values are never
# below its 1280-octet minimum link MTU, which the Host refuses), and the
# value set together with a disable (IPv6: above 1280, so it stays cached).
VALUES = {4: dict(downward=1100, upward=1400, disabled=1000),
          6: dict(downward=1400, upward=1450, disabled=1400)}


def cases():
    """tun_echo (the TUN Host embedding) and the native runtime harness
    (run.native_admin_child), both families; tun_echo's Refuse-mode UDP
    echo (whole datagrams through Host::udp_send) on a disabled IPv4 path,
    whose DF policy is IPv4-only; and re-enable evidence with tun_echo's Echo
    adjunct, both families."""
    return ([dict(kind=kind, family=family, scenario="utility") for kind in ("admin", "native-admin")
             for family in (4, 6)] + [dict(kind="admin", family=4, scenario="refuse")]
            + [dict(kind="admin", family=family, scenario="reenable") for family in (4, 6)])


def parse_records(text, kind):
    """`kind key=value ...` lines of ntcp-pathctl output."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == kind:
            found.append(dict(f.split("=", 1) for f in fields[1:] if "=" in f))
    return found


class Pathctl:
    """ntcp-pathctl as a separate process for every request."""

    def __init__(self, binary, socket_path):
        self.binary, self.socket = binary, socket_path
        self.log = []

    def run(self, *args, expect=0):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NTCP_") and k != "LD_PRELOAD"}
        p = subprocess.run([str(self.binary), str(self.socket), *map(str, args)], env=env,
                           capture_output=True, text=True, timeout=10)
        self.log.append(dict(args=list(map(str, args)), exit=p.returncode, stdout=p.stdout[-2000:],
                             stderr=p.stderr[-500:]))
        assert p.returncode == expect, self.log[-1]
        return p

    def routes(self):
        return parse_records(self.run("routes").stdout, "route")

    def paths(self):
        return parse_records(self.run("paths").stdout, "path")

    def path(self, destination):
        found = [p for p in self.paths() if p["destination"] == destination and p["valid"] == "1"]
        assert len(found) == 1, (destination, found)
        return found[0]


def check_ids(packets):
    """Every DF-clear IPv4 datagram carries its own nonzero Identification:
    one per whole packet, shared only by the fragments of one datagram."""
    datagrams = {}
    for e in packets:
        key = ("fragment", e["protocol"], e["ip_id"]) if e["fragmented"] else ("whole", e["time_ns"], e["ip_id"])
        datagrams.setdefault(key, e["ip_id"])
    ids = list(datagrams.values())
    assert all(ids), "zero Identification on a DF-clear datagram"
    assert len(set(ids)) == len(ids), ("repeated Identification", sorted(ids)[:16])
    return len(ids)


def child(case, proof, binary, pathctl_binary, Peer, command, emit):
    family = case["family"]
    a = icmp.ADDRESSES[family]
    DOWNWARD, UPWARD = VALUES[family]["downward"], VALUES[family]["upward"]
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    neighbor = ntcp = capture = None
    directory = tempfile.mkdtemp(prefix="t12-control-")
    socket_path = Path(directory) / "control.sock"
    evidence = dict(case=case)
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = icmp.setup(family, 1500, command, peer.p.pid)
        # N: a second kernel peer in the peer namespace, at the egress
        # peer address (another destination behind the same route).
        neighbor = Peer(["nsenter", "-t", str(peer.p.pid), "-n", sys.executable, "-B", HERE / "icmp_peer.py",
                         a["egress_peer"], a["ntcp"], icmp.PORT])
        assert neighbor.ready["namespace"] == peer.ready["namespace"], neighbor.ready
        capture = icmp.Capture(icmp.TUN)
        ntcp = icmp.Ntcp(binary, a["ntcp"], "fragment", {
            f"NTCP_PEER_REASSEMBLY_IPV{family}": str(icmp.PEER_REASSEMBLY),
            "NTCP_CONTROL_SOCKET": str(socket_path)})
        mode = os.stat(socket_path).st_mode
        directory_mode = os.stat(directory).st_mode
        assert stat.S_ISSOCK(mode) and stat.S_IMODE(mode) == 0o600, oct(mode)
        assert stat.S_IMODE(directory_mode) == 0o700, oct(directory_mode)
        ctl = Pathctl(pathctl_binary, socket_path)
        evidence.update(tun_echo_settings=ntcp.settings, control_socket_mode=oct(stat.S_IMODE(mode)),
                        control_directory_mode=oct(stat.S_IMODE(directory_mode)), euid=os.geteuid(),
                        allow_list="default (the owner's effective uid); a second-uid SO_PEERCRED denial needs a "
                                   "second mapped uid, which this one-uid user namespace cannot provide (covered "
                                   "by the ntcp-path-control and runtime control tests)")

        def request(who, *fields):
            who.send(" ".join(map(str, fields)))
            result = who.read()
            assert result["event"] == fields[0], result
            return result

        def tcp(who, salt):
            result = request(who, "tcp", TCP_BYTES, salt)
            assert (result["tx"], result["rx"]) == (TCP_BYTES, TCP_BYTES), result
            assert result["hash"] == fnv(pattern(TCP_BYTES, salt)), result
            return result

        def fudp(who, salt):
            result = request(who, "fudp", FRAGMENTED_REQUEST, salt, 5)
            assert result["reply"] == FRAGMENTED_REQUEST and result["match"], result
            assert result["sha256"] == result["request_sha256"], result
            return result

        def own(events, destination):
            items = [e for e in events if e["direction"] == "from-ntcp" and e["source"] == a["ntcp"]
                     and e["destination"] == destination]
            for e in items:
                assert e["ip_checksum_valid"], ("IP header checksum", icmp.public(e))
                assert e["fragmented"] or e["checksum_valid"], ("transport checksum", icmp.public(e))
            return items

        def datagrams(events, destination):
            found = [(d, f) for d, f in icmp.reassemble(events) if d["direction"] == "from-ntcp"
                     and (d["source"], d["destination"]) == (a["ntcp"], destination)]
            for d, fragments in found:
                assert d["checksum_valid"], ("reassembled transport checksum", icmp.public(d))
                assert all(f["offset"] or f["more"] for f in fragments), "atomic fragment"
            return found

        def summary(items):
            return dict(packets=len(items), max_length=max((e["length"] for e in items), default=0),
                        tcp=sum(e["protocol"] == 6 for e in items), fragments=sum(e["fragmented"] for e in items),
                        df=sorted({e["df"] for e in items}, key=str))

        def enabled_window(items, ceiling):
            """DF (IPv4) on every packet and fragment; sizes up to CEILING."""
            assert items and max(e["length"] for e in items) <= ceiling, summary(items)
            assert family == 6 or all(e["df"] for e in items), ("enabled path keeps DF", summary(items))

        def ptbs(events):
            return [e for e in events if e["direction"] == "to-ntcp" and e.get("ptb")]

        # Warm-up: both destinations reach the echo; both paths exist.
        for who, salt in ((peer, 1), (neighbor, 2)):
            warm = request(who, "udp", 64, salt, 2.0)
            assert warm["reply"] == 64 and warm["match"], warm
        routes = ctl.routes()
        assert len(routes) == 1 and routes[0]["next_hop"].startswith("forwarder:"), routes
        route = routes[0]
        target = ctl.path(a["peer"])
        other = ctl.path(a["egress_peer"])
        assert target["token"] != other["token"] and target["route"] == other["route"] == route["token"]
        assert target["effective_disabled"] == "-" and target["administrative_estimate"] == "-", target

        # Baseline: full-size TCP and DF fragments to P.
        mark = capture.mark()
        baseline_tcp = tcp(peer, 3)
        baseline_udp = fudp(peer, 4)
        events = capture.since(mark)
        baseline = own(events, a["peer"])
        enabled_window(baseline, 1500)
        assert max(e["length"] for e in baseline if e["protocol"] == 6) == 1500, summary(baseline)
        assert datagrams(events, a["peer"]), "baseline fragmented reply"

        # A query while traffic runs (P's TCP echo in flight).
        peer.send(f"tcp {TCP_BYTES} 5")
        during = ctl.paths()
        result = peer.read()
        assert result["event"] == "tcp" and result["hash"] == fnv(pattern(TCP_BYTES, 5)), result

        # Refused requests change nothing: stale generation, unknown target.
        before = ctl.path(a["peer"])
        stale = ctl.run("set", "path", target["token"], int(target["generation"]) + 7, "disable", expect=1)
        assert "status=stale" in stale.stderr, stale.stderr
        missing = ctl.run("disable", "path", "%016x" % (int(target["token"], 16) ^ 0x5a5a), expect=1)
        assert "status=" in missing.stderr, missing.stderr
        after = ctl.path(a["peer"])
        unchanged = ("generation", "disabled", "estimate", "effective_disabled", "administrative_estimate",
                     "accepted", "negative_revision", "discovery_revision", "retry_not_before")
        assert {k: before[k] for k in unchanged} == {k: after[k] for k in unchanged}, (before, after)

        # An existing connection (established before the change) on P.
        opened = request(peer, "open", "a", 64, 6)
        disabled = ctl.run("disable", "path", target["token"])
        state = ctl.path(a["peer"])
        assert state["effective_disabled"] == "path" and state["disabled"] == "1", state
        assert int(state["generation"]) > int(target["generation"]), (target, state)
        assert ctl.path(a["egress_peer"])["effective_disabled"] == "-", "neighbor path untouched"

        limit = IPV4_OFFLINK if family == 4 else IPV6_MINIMUM
        mark = capture.mark()
        finished = request(peer, "finish", "a", TCP_BYTES, 7)
        assert finished["hash"] == fnv(pattern(TCP_BYTES, 7)) and finished["local_port"] == opened["local_port"]
        disabled_tcp = tcp(peer, 8)
        whole = request(peer, "udp", 64, 9, 2.0)
        assert whole["reply"] == 64 and whole["match"], whole
        disabled_udp = fudp(peer, 10)
        # The neighbor at the same time: enabled, full size, DF.
        neighbor_tcp = tcp(neighbor, 11)
        neighbor_udp = fudp(neighbor, 12)
        events = capture.since(mark)
        target_packets = own(events, a["peer"])
        assert target_packets and max(e["length"] for e in target_packets) <= limit, summary(target_packets)
        existing = [e for e in target_packets if e["protocol"] == 6 and e.get("dport") == opened["local_port"]]
        assert existing and any(e["payload"] for e in existing), "existing connection's output after disable"
        if family == 4:
            assert not any(e["df"] for e in target_packets), ("DF clear on the disabled path",
                                                              [icmp.public(e) for e in target_packets if e["df"]][:4])
            ids = check_ids(target_packets)
        else:
            ids = None
        replies = datagrams(events, a["peer"])
        assert replies and all(len(f) > 1 for _, f in replies), "fragmented replies on the disabled path"
        assert all(d["payload"] == FRAGMENTED_REQUEST for d, _ in replies), [icmp.public(d) for d, _ in replies]
        neighbor_packets = own(events, a["egress_peer"])
        enabled_window(neighbor_packets, 1500)
        assert max(e["length"] for e in neighbor_packets if e["protocol"] == 6) == 1500, summary(neighbor_packets)
        assert any(f for d, f in datagrams(events, a["egress_peer"])), "neighbor fragmented reply"
        disabled_evidence = dict(
            utility=disabled.stdout.strip(), state=state, existing=dict(open=opened, finish=finished,
                                                                        packets=summary(existing)),
            target=summary(target_packets), datagrams_with_leased_ids=ids,
            fragment_sizes=[[f["length"] for f in sorted(fr, key=lambda f: f["offset"])] for _, fr in replies],
            fragment_df=sorted({f["df"] for _, fr in replies for f in fr}, key=str),
            neighbor=summary(neighbor_packets), tcp=[disabled_tcp, neighbor_tcp], udp=[whole, disabled_udp, neighbor_udp])

        # Re-enable: the policy is gone; output is DF again and its size
        # comes from the accepted estimate, never from DF-clear deliveries.
        ctl.run("enable", "path", target["token"])
        state = ctl.path(a["peer"])
        assert state["effective_disabled"] == "-" and state["accepted"].startswith("1500:"), state
        mark = capture.mark()
        enabled_tcp = tcp(peer, 13)
        reenabled = own(capture.since(mark), a["peer"])
        enabled_window(reenabled, 1500)

        # Downward estimate: packets shrink at once.
        ctl.run("estimate", "path", target["token"], DOWNWARD)
        state = ctl.path(a["peer"])
        assert state["accepted"].startswith(f"{DOWNWARD}:") and state["administrative_estimate"].startswith(
            f"{DOWNWARD}:"), state
        mark = capture.mark()
        down_tcp = tcp(peer, 14)
        down = own(capture.since(mark), a["peer"])
        enabled_window(down, DOWNWARD)
        assert max(e["length"] for e in down if e["protocol"] == 6) > DOWNWARD - 48, summary(down)

        # Upward estimate: recorded as the administrative value only.
        ctl.run("estimate", "path", target["token"], UPWARD)
        up_state = ctl.path(a["peer"])
        assert up_state["administrative_estimate"].startswith(f"{UPWARD}:"), up_state
        assert up_state["accepted"].startswith(f"{DOWNWARD}:"), ("upward set grows nothing", up_state)
        mark = capture.mark()
        up_tcp = tcp(peer, 15)
        up = own(capture.since(mark), a["peer"])
        enabled_window(up, DOWNWARD)
        clients = ctl.run("clients", up_state["token"]).stdout

        # Disabled with an administrative value: IPv4 is limited to that
        # value (actual knowledge); IPv6 to its 1280-octet minimum (the
        # value above it stays cached, RFC 8201 5.6).
        value = VALUES[family]["disabled"]
        current = ctl.path(a["peer"])
        ctl.run("set", "path", current["token"], current["generation"], "disable", f"estimate={value}")
        valued_state = ctl.path(a["peer"])
        assert valued_state["effective_disabled"] == "path", valued_state
        mark = capture.mark()
        valued_tcp = tcp(peer, 16)
        valued_udp = fudp(peer, 17)
        events = capture.since(mark)
        valued = own(events, a["peer"])
        ceiling = value if family == 4 else min(value, IPV6_MINIMUM)
        assert valued and max(e["length"] for e in valued) <= ceiling, summary(valued)
        assert max(e["length"] for e in valued if e["protocol"] == 6) > IPV4_OFFLINK, summary(valued)
        if family == 4:
            assert not any(e["df"] for e in valued), "DF clear with an administrative value"
            check_ids(valued)
        assert datagrams(events, a["peer"]), "fragmented reply with an administrative value"
        assert not ptbs(capture.since(0)), "no router PTB in the administration case"

        evidence.update(
            settings=settings, routes=routes, initial_paths=dict(target=target, neighbor=other),
            query_during_traffic=len(during), baseline=dict(tcp=baseline_tcp, udp=baseline_udp, packets=summary(baseline)),
            refused=dict(stale=stale.stderr.strip(), unknown=missing.stderr.strip(), before=before, after=after),
            disabled=disabled_evidence, reenabled=dict(state=state, tcp=enabled_tcp, packets=summary(reenabled)),
            downward=dict(tcp=down_tcp, packets=summary(down)),
            upward=dict(state=up_state, tcp=up_tcp, packets=summary(up), clients=clients.strip().splitlines()),
            administrative_disabled=dict(value=value, ceiling=ceiling, state=valued_state, tcp=valued_tcp, udp=valued_udp,
                                         packets=summary(valued)),
            utility_requests=len(ctl.log), ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (ntcp and ntcp.close, neighbor and neighbor.close, peer.close, capture and capture.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        # The server removes its own socket; the harness removes its directory.
        for leftover in (socket_path,):
            try:
                leftover.unlink()
            except FileNotFoundError:
                pass
        os.rmdir(directory)
        if errors:
            emit("T12_ADMIN_CLEANUP", dict(case=case, errors=errors))
            if not primary:
                raise RuntimeError(errors)
    return evidence


def refuse_child(case, proof, binary, pathctl_binary, Peer, command, emit):
    """tun_echo in Refuse mode answers each UDP request with one whole
    datagram through Host::udp_send. On the disabled IPv4 path P every reply
    leaves DF clear with its own leased nonzero Identification and a valid
    header checksum, within the 576-octet Forwarder sending limit (a larger
    reply is refused locally with that payload limit); the neighbor N keeps
    DF throughout, and re-enabling restores DF and the full size on P."""
    assert case["family"] == 4, "the DF policy of a disabled route is IPv4-only"
    a = icmp.ADDRESSES[4]
    allowed = IPV4_OFFLINK - 28
    big, fitting = 1000, allowed
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    neighbor = ntcp = capture = None
    directory = tempfile.mkdtemp(prefix="t12-control-")
    socket_path = Path(directory) / "control.sock"
    evidence = dict(case=case)
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = icmp.setup(4, 1500, command, peer.p.pid)
        neighbor = Peer(["nsenter", "-t", str(peer.p.pid), "-n", sys.executable, "-B", HERE / "icmp_peer.py",
                         a["egress_peer"], a["ntcp"], icmp.PORT])
        capture = icmp.Capture(icmp.TUN)
        ntcp = icmp.Ntcp(binary, a["ntcp"], "refuse", {"NTCP_CONTROL_SOCKET": str(socket_path)})
        ctl = Pathctl(pathctl_binary, socket_path)

        def udp(who, size, salt, wait=2.0):
            who.send(f"udp {size} {salt} {wait}")
            result = who.read()
            assert result["event"] == "udp", result
            assert result["reply"] is None or (result["reply"] == size and result["match"]), result
            return result

        def replies(events, destination):
            found = [e for e in events if e["direction"] == "from-ntcp" and e["protocol"] == 17
                     and (e["source"], e["destination"]) == (a["ntcp"], destination)]
            for e in found:
                assert e["ip_checksum_valid"] and e["checksum_valid"] and not e["fragmented"], icmp.public(e)
            return found

        def summary(items):
            return dict(packets=len(items), lengths=[e["length"] for e in items], df=[e["df"] for e in items],
                        ip_ids=[e["ip_id"] for e in items])

        for who, salt in ((peer, 1), (neighbor, 2)):
            assert udp(who, 64, salt)["reply"] == 64
        target = ctl.path(a["peer"])
        mark = capture.mark()
        assert udp(peer, big, 3)["reply"] == big
        baseline = replies(capture.since(mark), a["peer"])
        assert [e["length"] for e in baseline] == [big + 28] and all(e["df"] for e in baseline), summary(baseline)

        ctl.run("disable", "path", target["token"])
        state = ctl.path(a["peer"])
        assert state["effective_disabled"] == "path", state
        mark, line = capture.mark(), ntcp.mark()
        whole = [udp(peer, size, salt) for size, salt in ((fitting, 4), (64, 5), (300, 6))]
        assert all(r["reply"] for r in whole), whole
        refused = udp(peer, big, 7, 1.0)
        assert refused["reply"] is None, refused
        refusal = ntcp.wait(icmp.REFUSED, line, 5)
        assert (int(refusal.group(1)), int(refusal.group(3))) == (big, allowed), refusal.group(0)
        neighbor_reply = udp(neighbor, big, 8)
        assert neighbor_reply["reply"] == big, neighbor_reply
        events = capture.since(mark)
        disabled = replies(events, a["peer"])
        assert [e["length"] for e in disabled] == [fitting + 28, 64 + 28, 300 + 28], summary(disabled)
        assert not any(e["df"] for e in disabled), ("DF clear on the disabled path", summary(disabled))
        ids = check_ids(disabled)
        neighbor_packets = replies(events, a["egress_peer"])
        assert [e["length"] for e in neighbor_packets] == [big + 28], summary(neighbor_packets)
        assert all(e["df"] for e in neighbor_packets), ("neighbor keeps DF", summary(neighbor_packets))

        ctl.run("enable", "path", target["token"])
        mark = capture.mark()
        assert udp(peer, big, 9)["reply"] == big
        reenabled = replies(capture.since(mark), a["peer"])
        assert [e["length"] for e in reenabled] == [big + 28] and all(e["df"] for e in reenabled), summary(reenabled)
        evidence.update(settings=settings, tun_echo_settings=ntcp.settings, initial_path=target, disabled_state=state,
                        baseline=summary(baseline), disabled=summary(disabled), leased_ids=ids,
                        refusal=refusal.group(0), neighbor=summary(neighbor_packets), reenabled=summary(reenabled),
                        utility_requests=len(ctl.log), ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (ntcp and ntcp.close, neighbor and neighbor.close, peer.close, capture and capture.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        os.rmdir(directory)
        if errors:
            emit("T12_ADMIN_CLEANUP", dict(case=case, errors=errors))
            if not primary:
                raise RuntimeError(errors)
    return evidence


# The reenable case's waits: the adjunct probes as soon as the loop runs
# after demand or re-enable (no hold on an unlearned path); a probe waits up
# to its 3-second reply timeout before the next one may leave.
DISABLED_WAIT = 4
PROBE_WAIT = 10
REPLY_WAIT = 30


def reenable_child(case, proof, binary, pathctl_binary, Peer, command, emit):
    """Re-enabling discovery restores probing without reviving size proof,
    shown with tun_echo's Host Echo adjunct (RFC 4821 PLPMTUD for its
    source fragmentation), which needs no hold on a path without a learned
    decrease. No fragmented traffic reaches P before the disable, so the
    adjunct has no converged search there (whose restart would wait RFC 4821
    7.3's interval). While P is disabled, fragmented UDP replies create
    adjunct demand (the utility lists the adjunct client) and DF-clear TCP
    (IPv4) and fragments are delivered, yet no adjunct Echo Request leaves
    toward P. Right after ntcp-pathctl re-enables discovery the utility
    reports the accepted estimate with its provenance and the adjunct's usable
    size at their pre-disable values (the connectionless effective size the
    utility reports for the warm-up UDP flow before the disable, the
    configured initial value): the DF-clear deliveries proved nothing. The harness-owned drop rule in the router namespace
    (adjunct-silence's) discards ntcp's Echo Requests until that query has
    returned, so it precedes every adjunct reply; the capture still shows
    the probe leaving (unfragmented, DF on IPv4, above the connectionless
    effective size). Once the rule is removed a later probe draws a real
    Echo Reply and values grow only through the existing confirmation rules:
    the adjunct's usable size rises to the echoed size, while the shared
    accepted estimate stays the unlearned first hop (PathService answers
    NotLarger on an unlearned path)."""
    family = case["family"]
    a = icmp.ADDRESSES[family]
    initial = icmp.CONNECTIONLESS_INITIAL[family]
    limit = IPV4_OFFLINK if family == 4 else IPV6_MINIMUM
    echo_protocol = 1 if family == 4 else 58
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    ntcp = capture = None
    silenced = False
    directory = tempfile.mkdtemp(prefix="t12-control-")
    socket_path = Path(directory) / "control.sock"
    evidence = dict(case=case)
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = icmp.setup(family, 1500, command, peer.p.pid)
        capture = icmp.Capture(icmp.TUN)
        ntcp = icmp.Ntcp(binary, a["ntcp"], "fragment", {
            f"NTCP_PEER_REASSEMBLY_IPV{family}": str(icmp.PEER_REASSEMBLY),
            "NTCP_CONTROL_SOCKET": str(socket_path)})
        ctl = Pathctl(pathctl_binary, socket_path)

        def request(*fields):
            peer.send(" ".join(map(str, fields)))
            result = peer.read()
            assert result["event"] == fields[0], result
            return result

        def clients(token):
            return parse_records(ctl.run("clients", token).stdout, "client")

        def adjunct(entries):
            found = [c for c in entries if c["kind"] == "adjunct"]
            assert len(found) <= 1, entries
            return found[0] if found else None

        def probes(events):
            return [e for e in events if e["direction"] == "from-ntcp" and not e["fragmented"]
                    and e["protocol"] == echo_protocol and e.get("echo") is True
                    and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]

        def answers(events, probe):
            return [e for e in events if e["direction"] == "to-ntcp" and e.get("echo") is False
                    and e["source"] == a["peer"] and (e["identifier"], e["sequence"]) == (probe["identifier"], probe["sequence"])
                    and e["data"] == probe["data"] and e["checksum_valid"] and e["time_ns"] > probe["time_ns"]]

        def replies_to_ntcp(events):
            return [e for e in events if e["direction"] == "to-ntcp" and e.get("echo") is False
                    and e["source"] == a["peer"]]

        def fragments(events):
            found = [(d, f) for d, f in icmp.reassemble(events) if d["direction"] == "from-ntcp"
                     and (d["source"], d["destination"]) == (a["ntcp"], a["peer"]) and d["protocol"] == 17]
            for d, pieces in found:
                assert d["checksum_valid"], ("reassembled transport checksum", icmp.public(d))
                assert all(f["ip_checksum_valid"] and (f["offset"] or f["more"]) for f in pieces), "fragment"
            return found

        def public_probe(p):
            return dict(length=p["length"], df=p["df"], checksum_valid=p["checksum_valid"])

        # Warm-up with an unfragmented datagram: P's path exists, no demand.
        warm = request("udp", 64, 1, 2.0)
        assert warm["reply"] == 64 and warm["match"], warm
        target = ctl.path(a["peer"])
        assert target["effective_disabled"] == "-" and target["learned"] == "-", target
        assert target["accepted"] == "1500:unlearned" and target["budget"] == "1500", target
        before_clients = clients(target["token"])
        assert adjunct(before_clients) is None, ("no adjunct state before any fragmented traffic", before_clients)
        # The pre-disable connectionless effective size (the same rule sizes
        # the warm-up flow and the adjunct): the configured initial value.
        flows = [c for c in before_clients if c["kind"] == "udp"]
        assert flows and all(c["usable"] == str(initial) for c in flows), (initial, before_clients)
        pre_usable = flows[0]["usable"]
        assert not probes(capture.since(0)), "no adjunct probe before any demand"

        # Disable P before any fragmented traffic reaches it.
        ctl.run("disable", "path", target["token"])
        disabled_state = ctl.path(a["peer"])
        assert disabled_state["effective_disabled"] == "path", disabled_state
        assert disabled_state["budget"] == str(limit), disabled_state
        mark = capture.mark()
        disabled_tcp = request("tcp", TCP_BYTES, 2)
        assert (disabled_tcp["tx"], disabled_tcp["rx"]) == (TCP_BYTES, TCP_BYTES), disabled_tcp
        assert disabled_tcp["hash"] == fnv(pattern(TCP_BYTES, 2)), disabled_tcp
        disabled_udp = request("fudp", FRAGMENTED_REQUEST, 3, 5)
        assert disabled_udp["reply"] == FRAGMENTED_REQUEST and disabled_udp["match"], disabled_udp
        # Time in which an enabled path's adjunct would already have probed.
        time.sleep(DISABLED_WAIT)
        demand_clients = clients(target["token"])
        events = capture.since(mark)
        replies = fragments(events)
        assert replies and all(len(f) > 1 for _, f in replies), "fragmented replies while disabled"
        own = [e for e in events if e["direction"] == "from-ntcp"
               and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]
        assert own and max(e["length"] for e in own) <= limit, max(e["length"] for e in own)
        if family == 4:
            assert not any(e["df"] for e in own), "DF clear on the disabled path"
            check_ids(own)
        demand = adjunct(demand_clients)
        assert demand is not None, ("fragmented replies created adjunct demand", demand_clients)
        assert not probes(events), ("no adjunct Echo Request while disabled", [public_probe(p) for p in probes(events)])

        # Hold ntcp's Echo Requests at the router so the re-enable query
        # precedes every adjunct reply.
        silence = icmp.silence_rule(command)
        silenced = True
        mark = capture.mark()
        ctl.run("enable", "path", target["token"])
        reenabled = ctl.path(a["peer"])
        reenabled_clients = clients(target["token"])
        queried_ns = time.monotonic_ns()
        assert reenabled["effective_disabled"] == "-", reenabled
        unchanged = ("accepted", "learned", "budget", "restriction", "retry_not_before", "negative_revision")
        assert {k: reenabled[k] for k in unchanged} == {k: target[k] for k in unchanged}, (target, reenabled)
        restored = adjunct(reenabled_clients)
        assert restored is not None and restored["usable"] == pre_usable, (pre_usable, reenabled_clients)
        assert not [e for e in replies_to_ntcp(capture.since(mark)) if e["time_ns"] <= queried_ns], "reply before query"

        # Probing is restored: an Echo Request leaves toward P.
        deadline = time.monotonic() + PROBE_WAIT
        while not probes(capture.since(mark)):
            assert time.monotonic() < deadline, "no adjunct Echo Request after re-enable"
            time.sleep(0.1)
        first = probes(capture.since(mark))[0]
        assert first["checksum_valid"] and first["length"] > initial and first["length"] <= 1500, public_probe(first)
        assert family == 6 or first["df"], ("IPv4 probe with DF", public_probe(first))
        dropped = icmp.silence_counters(command)
        command(["nft", "delete", "table", "inet", icmp.SILENCE_TABLE])
        silenced = False

        # A later probe draws a real Echo Reply; values grow only through
        # the confirmation rules.
        deadline = time.monotonic() + REPLY_WAIT
        while True:
            events = capture.since(mark)
            answered = [(p, answers(events, p)) for p in probes(events)]
            answered = [(p, r[0]) for p, r in answered if r]
            if answered:
                break
            assert time.monotonic() < deadline, ("no answered probe", [public_probe(p) for p in probes(events)])
            time.sleep(0.2)
        time.sleep(0.5)
        grown = ctl.path(a["peer"])
        grown_clients = clients(target["token"])
        events = capture.since(mark)
        sent = probes(events)
        for p in sent:
            assert p["checksum_valid"] and (family == 6 or p["df"]) and initial < p["length"] <= 1500, public_probe(p)
        confirmed = [p["length"] for p in sent if answers(events, p)]
        usable = int(adjunct(grown_clients)["usable"])
        assert initial < usable <= max(confirmed), (usable, confirmed)
        assert grown["accepted"] == "1500:unlearned" and grown["learned"] == "-", ("NotLarger", grown)
        evidence.update(
            settings=settings, tun_echo_settings=ntcp.settings, connectionless_initial=initial, sending_limit=limit,
            before=dict(path=target, clients=before_clients),
            disabled=dict(path=disabled_state, clients=demand_clients, tcp=disabled_tcp, udp=disabled_udp,
                          packets=len(own), max_length=max(e["length"] for e in own),
                          df=sorted({e["df"] for e in own}, key=str),
                          fragment_sizes=[[f["length"] for f in sorted(fr, key=lambda f: f["offset"])]
                                          for _, fr in replies],
                          adjunct_probes=0, waited_seconds=DISABLED_WAIT),
            reenabled=dict(path=reenabled, clients=reenabled_clients, first_probe=public_probe(first),
                           silence=dict(rule=silence, counters=dropped)),
            grown=dict(path=grown, clients=grown_clients, probes=[public_probe(p) for p in sent],
                       confirmed=confirmed, adjunct_usable=usable),
            utility_requests=len(ctl.log), ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        if silenced:
            try:
                command(["nft", "delete", "table", "inet", icmp.SILENCE_TABLE])
            except Exception as e:
                errors.append(f"{type(e).__name__}: {e}")
        for close in (ntcp and ntcp.close, peer.close, capture and capture.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        os.rmdir(directory)
        if errors:
            emit("T12_ADMIN_CLEANUP", dict(case=case, errors=errors))
            if not primary:
                raise RuntimeError(errors)
    return evidence
