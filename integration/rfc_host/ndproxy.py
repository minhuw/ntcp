# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Native IPv6 path changes behind a Linux router (T19): one reusable N-R-P
fixture.

N is the native runtime (this harness's binary in its `phased` mode: one
Host configured by the production configuration parser on a resolving
`io.*` port, no next-hop MAC and no static neighbor) on t19n in the harness
namespace. R and P are network namespaces of the harness's user namespace,
each held by a sleeping process and entered by PID. R joins N's link
(t19ru, 1500 octets, addresses fd19::1/64 and fe80::1) and P's link (t19rd,
1500 until the case lowers it to 1280) and forwards IPv6. P owns the
destination D on its loopback and routes N's /64 back through R.

proxy-ptb: D (fd19::d) lies inside N's /64, so N selects it through its
on-link route; R answers N's Neighbor Solicitation for D as an NDP proxy
(proxy_ndp on t19ru, `ip -6 neigh add proxy D`). black-hole: the same
transition with an owned nft rule on R dropping its outgoing ICMPv6 type 2.
gateway-ptb: D (fd19:d::d) lies outside N's /64 and N routes its prefix
through `io.gateway.fd19:d::/64 = fe80::1`, R's link-local address; R
proxies nothing.

Every case establishes its stream at downstream MTU 1500 (so neither peer's
MSS hides oversized native output), exchanges a first phase, lowers both
ends of R's downstream link to 1280 and exchanges a second phase. N's port
and both R interfaces are captured.
"""
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import icmp
import scoped
from linux_peer import fnv, pattern

HERE = Path(__file__).resolve().parent
NATIVE_PORT, ROUTER_UP, ROUTER_DOWN, PEER_PORT = "t19n", "t19ru", "t19rd", "t19pr"
MACS = {NATIVE_PORT: "02:00:00:19:00:02", ROUTER_UP: "02:00:00:19:00:01",
        ROUTER_DOWN: "02:00:00:19:01:01", PEER_PORT: "02:00:00:19:01:02"}
NATIVE, ROUTER, ROUTER_LL = "fd19::2", "fd19::1", "fe80::1"
DOWN_ROUTER, DOWN_PEER = "fd19:1::1", "fd19:1::2"
DESTINATIONS = {"proxy-ptb": "fd19::d", "black-hole": "fd19::d", "gateway-ptb": "fd19:d::d"}
GATEWAY_PREFIX = "fd19:d::/64"
FIRST_HOP, DOWNSTREAM = 1500, 1280
PEER_LISTEN, NATIVE_LISTEN = 18190, 18191
BLACK_HOLE_TABLE = "t19blackhole"
# (bytes, salt) of the native-to-peer and peer-to-native halves of each phase.
FIRST = ((32768, 7), (6144, 11))
SECOND = ((65536, 19), (4096, 23))
LATER = (8192, 29)
SCENARIOS = (("proxy-ptb", "native-client"), ("proxy-ptb", "native-server"),
             ("black-hole", "native-client"), ("gateway-ptb", "native-client"))


def cases():
    return [dict(kind="nd-proxy", family=6, scenario=s, direction=d) for s, d in SCENARIOS]


def config(scenario):
    """The native runtime's configuration: a resolving `io.*` port on N's
    /64 (its on-link route), plus the gateway variant's route."""
    text = f"io.backend=af-packet\nio.interface={NATIVE_PORT}\nio.address={NATIVE}\nio.prefix=64\n"
    if scenario == "gateway-ptb":
        text += f"io.gateway.{GATEWAY_PREFIX}={ROUTER_LL}\n"
    return text


def held_namespace(proof):
    """A further network namespace of the harness user namespace, held by a
    sleeping process (entered by its PID, never named)."""
    holder = subprocess.Popen(["unshare", "--net", "sleep", "300"], stdin=subprocess.DEVNULL)
    deadline = time.monotonic() + 5
    while os.stat(f"/proc/{holder.pid}/ns/net").st_ino in (proof["net"]["current"], proof["net"]["parent"]):
        assert time.monotonic() < deadline and holder.poll() is None, "held namespace"
        time.sleep(0.02)
    return holder


def namespace_socket(pid, interface):
    """An AF_PACKET socket created in PID's network namespace, bound to its
    INTERFACE (a socket keeps the namespace it was created in)."""
    own = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.bind((interface, 0))
        finally:
            os.setns(own, os.CLONE_NEWNET)
    finally:
        os.close(own)
        os.close(target)
    return s


class Capture(scoped.Capture):
    """scoped.Capture of an interface in another namespace: "out" frames
    left that namespace through it."""

    def __init__(self, pid, interface):
        import threading
        self.socket = namespace_socket(pid, interface)
        self.events, self.error, self.bytes = [], None, 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()


def sysctl(run, path, value=None):
    if value is not None:
        run("sh", "-c", f"echo {value} > /proc/sys/{path}")
    return run("cat", "/proc/sys/" + path).strip()


def setup(command, scenario, r_pid, p_pid):
    here = lambda *args: command(list(args))
    in_r = lambda *args: command(["nsenter", "-t", str(r_pid), "-n", *args])
    in_p = lambda *args: command(["nsenter", "-t", str(p_pid), "-n", *args])
    destination = DESTINATIONS[scenario]
    for run in (here, in_r, in_p):
        # Only explicitly configured addresses; no DAD delay on them.
        for name in ("all", "default"):
            sysctl(run, f"net/ipv6/conf/{name}/addr_gen_mode", 1)
            sysctl(run, f"net/ipv6/conf/{name}/accept_dad", 0)
        run("ip", "link", "set", "lo", "up")
    offload = ["tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"]
    for near, ours, theirs, there, far in ((here, NATIVE_PORT, ROUTER_UP, r_pid, in_r),
                                           (in_r, ROUTER_DOWN, PEER_PORT, p_pid, in_p)):
        near("ip", "link", "add", ours, "type", "veth", "peer", "name", theirs, "netns", str(there))
        for run, name in ((near, ours), (far, theirs)):
            run("ip", "link", "set", name, "address", MACS[name], "mtu", str(FIRST_HOP))
            run("ethtool", "-K", name, *offload)
    sysctl(in_r, "net/ipv6/conf/all/forwarding", 1)
    if scenario != "gateway-ptb":
        sysctl(in_r, f"net/ipv6/conf/{ROUTER_UP}/proxy_ndp", 1)
    in_r("ip", "addr", "add", ROUTER + "/64", "dev", ROUTER_UP, "nodad")
    in_r("ip", "addr", "add", ROUTER_LL + "/64", "dev", ROUTER_UP, "nodad")
    in_r("ip", "addr", "add", DOWN_ROUTER + "/64", "dev", ROUTER_DOWN, "nodad")
    in_p("ip", "addr", "add", DOWN_PEER + "/64", "dev", PEER_PORT, "nodad")
    in_p("ip", "addr", "add", destination + "/128", "dev", "lo")
    for run, name in ((here, NATIVE_PORT), (in_r, ROUTER_UP), (in_r, ROUTER_DOWN), (in_p, PEER_PORT)):
        run("ip", "link", "set", name, "up")
    # R and P know each other statically; N resolves everything itself.
    in_r("ip", "-6", "neigh", "replace", DOWN_PEER, "lladdr", MACS[PEER_PORT], "nud", "permanent", "dev", ROUTER_DOWN)
    in_p("ip", "-6", "neigh", "replace", DOWN_ROUTER, "lladdr", MACS[ROUTER_DOWN], "nud", "permanent",
         "dev", PEER_PORT)
    in_r("ip", "-6", "route", "replace", destination + "/128", "via", DOWN_PEER, "dev", ROUTER_DOWN)
    in_p("ip", "-6", "route", "replace", str(ipaddress.ip_network(NATIVE + "/64", strict=False)), "via", DOWN_ROUTER,
         "dev", PEER_PORT)
    if scenario != "gateway-ptb":
        in_r("ip", "-6", "neigh", "add", "proxy", destination, "dev", ROUTER_UP)
    native_link = json.loads(here("ip", "-j", "addr", "show", "dev", NATIVE_PORT))[0]
    assert not native_link.get("addr_info"), ("kernel address on the native-owned port", native_link)
    assert not json.loads(here("ip", "-j", "-6", "neigh", "show") or "[]"), "no neighbor entry on N's side"
    to_destination = json.loads(in_r("ip", "-j", "-6", "route", "get", destination))[0]
    to_native = json.loads(in_r("ip", "-j", "-6", "route", "get", NATIVE))[0]
    back = json.loads(in_p("ip", "-j", "-6", "route", "get", NATIVE))[0]
    assert to_destination["dev"] == ROUTER_DOWN and to_native["dev"] == ROUTER_UP and back["dev"] == PEER_PORT, \
        (to_destination, to_native, back)
    router_sysctls = {path: sysctl(in_r, path) for path in (
        "net/ipv6/conf/all/forwarding", f"net/ipv6/conf/{ROUTER_UP}/forwarding",
        f"net/ipv6/conf/{ROUTER_UP}/proxy_ndp", f"net/ipv6/neigh/{ROUTER_UP}/proxy_delay",
        "net/ipv6/icmp/ratelimit", "net/ipv6/icmp/ratemask")}
    return dict(scenario=scenario, destination=destination, native=NATIVE, macs=MACS,
                router_addresses=json.loads(in_r("ip", "-j", "-6", "addr", "show")),
                router_proxies=in_r("ip", "-6", "neigh", "show", "proxy").strip(),
                router_routes=json.loads(in_r("ip", "-j", "-6", "route", "show")),
                peer_routes=json.loads(in_p("ip", "-j", "-6", "route", "show")),
                router_to_destination=to_destination, router_to_native=to_native, peer_to_native=back,
                router_sysctls=router_sysctls, proxy_delay_changed=False,
                mtus=dict(native=native_link["mtu"], downstream_initial=FIRST_HOP, downstream_lowered=DOWNSTREAM),
                namespaces=dict(router=os.stat(f"/proc/{r_pid}/ns/net").st_ino,
                                peer=os.stat(f"/proc/{p_pid}/ns/net").st_ino),
                offload="disabled on all four veth ends")


def router_counter(command, r_pid):
    """R's kernel-generated Packet Too Big count (Icmp6OutPktTooBigs)."""
    text = command(["nsenter", "-t", str(r_pid), "-n", "cat", "/proc/net/snmp6"])
    return int(dict(line.split() for line in text.splitlines())["Icmp6OutPktTooBigs"])


def black_hole(command, r_pid):
    """R's owned rule: drop (and count) its own outgoing ICMPv6 type 2."""
    nft = lambda *args: command(["nsenter", "-t", str(r_pid), "-n", "nft", *args])
    nft("add", "table", "inet", BLACK_HOLE_TABLE)
    nft("add", "chain", "inet", BLACK_HOLE_TABLE, "out", "{ type filter hook output priority 0; }")
    nft("add", "rule", "inet", BLACK_HOLE_TABLE, "out", "icmpv6", "type", "packet-too-big", "counter", "drop")


def black_hole_drops(command, r_pid):
    ruleset = json.loads(command(["nsenter", "-t", str(r_pid), "-n", "nft", "-j", "list", "table", "inet",
                                  BLACK_HOLE_TABLE]))["nftables"]
    return sum(e["counter"]["packets"] for item in ruleset if "rule" in item for e in item["rule"]["expr"]
               if "counter" in e)


def covered(dropped, segments):
    """Whether SEGMENTS resend every octet of the DROPPED segment."""
    octets = set()
    for e in segments:
        start = (e["seq"] - dropped["seq"]) & 0xffffffff
        if start < 1 << 31:
            octets.update(range(start, min(start + e["payload"], dropped["payload"])))
        else:
            end = start + e["payload"] - (1 << 32)
            octets.update(range(0, max(0, min(end, dropped["payload"]))))
    return octets == set(range(dropped["payload"]))


def summary(e):
    return {k: e[k] for k in ("direction", "eth_src", "eth_dst", "source", "destination", "ip_length", "time_ns")
            if k in e} | {k: e[k] for k in ("seq", "ack", "payload", "flags", "icmp_type", "mtu", "target") if k in e}


def child(case, proof, binary, Peer, command):
    scenario, direction = case["scenario"], case["direction"]
    destination = DESTINATIONS[scenario]
    router = held_namespace(proof)
    peer_holder = held_namespace(proof)
    peer = driver = None
    captures = {}
    evidence = dict(case=case)

    def call(process, line, event):
        process.send(line)
        result = process.read()
        assert result["event"] == event, result
        return result

    try:
        settings = setup(command, scenario, router.pid, peer_holder.pid)
        evidence.update(settings=settings, configuration=config(scenario).splitlines())
        captures = dict(native=scoped.Capture(NATIVE_PORT), upstream=Capture(router.pid, ROUTER_UP),
                        downstream=Capture(router.pid, ROUTER_DOWN))
        peer = Peer(["nsenter", "-t", str(peer_holder.pid), "-n", sys.executable, "-B", HERE / "ndproxy.py", "peer"])
        assert peer.ready["namespace"] == settings["namespaces"]["peer"], peer.ready
        call(peer, f"listen {PEER_LISTEN}", "listening")
        counter_before = router_counter(command, router.pid)
        driver = Peer([binary, "phased", config(scenario)])

        # Establish at downstream MTU 1500.
        if direction == "native-client":
            peer.send("accept s")
            established = call(driver, f"connect s {destination} {PEER_LISTEN}", "connected")
            peer_side = peer.read()
        else:
            call(driver, f"listen {NATIVE_LISTEN}", "listening")
            driver.send("accept s")
            # From D: N's routes cover its /64 and the gateway prefix only.
            peer_side = call(peer, f"connect s {NATIVE} {NATIVE_LISTEN} {destination}", "connected")
            established = driver.read()
        assert established["event"] in ("connected", "accepted") and peer_side["event"] in ("accepted", "connected")
        assert established["path_mtu"] == FIRST_HOP, established

        def phase(sizes):
            (out_n, out_salt), (back_n, back_salt) = sizes
            driver.send(f"send s {out_n} {out_salt}")
            peer.send(f"recv s {out_n} {out_salt}")
            sent, received = driver.read(), peer.read()
            assert received["hash"] == fnv(pattern(out_n, out_salt)), received
            peer.send(f"send s {back_n} {back_salt}")
            driver.send(f"recv s {back_n} {back_salt}")
            back_sent, back_received = peer.read(), driver.read()
            assert back_received["hash"] == fnv(pattern(back_n, back_salt)), back_received
            return dict(native_sent=sent, peer_received=received, peer_sent=back_sent, native_received=back_received)

        first = phase(FIRST)
        before = call(driver, "query s", "query")
        native = captures["native"]
        initial = native.since(0)

        # Discovery: R's NA (proxy or gateway) precedes every native TCP segment.
        target = ROUTER_LL if scenario == "gateway-ptb" else destination
        solicitations = scoped.nd(initial, 135, direction="out", target=target)
        advertisements = scoped.nd(initial, 136, direction="in", target=target)
        assert solicitations and advertisements, [summary(e) for e in initial[:20]]
        ns, na = scoped.checked_nd(solicitations[0]), scoped.checked_nd(advertisements[0])
        assert ns["eth_src"] == MACS[NATIVE_PORT] and scoped.lladdr(ns, 1) == MACS[NATIVE_PORT], ns
        assert na["eth_src"] == MACS[ROUTER_UP] and scoped.lladdr(na, 2) == MACS[ROUTER_UP] and na["solicited"], na
        tcp = [e for e in initial if e.get("protocol") == 6]
        out = [e for e in tcp if e["direction"] == "out"]
        assert out and min(e["time_ns"] for e in out) > na["time_ns"], "a native segment before resolution"
        syn = next(e for e in out if e["flags"] & 0x12 in (0x02, 0x12))
        assert all(e["eth_dst"] == MACS[ROUTER_UP] and e["destination"] == destination for e in out), \
            [summary(e) for e in out[:4]]
        first_lengths = [e["ip_length"] for e in out if e["payload"]]
        assert max(first_lengths) == FIRST_HOP, sorted(set(first_lengths))
        evidence.update(established=established, peer_established=peer_side, first_phase=first, first_query=before,
                        solicitation=ns, advertisement=na, solicitations=len(solicitations),
                        first_segment=summary(syn), first_phase_lengths=sorted(set(first_lengths)))

        # The path change: R's downstream link (both ends) drops to 1280.
        if scenario == "black-hole":
            black_hole(command, router.pid)
        marks = {name: c.mark() for name, c in captures.items()}
        counter_mid = router_counter(command, router.pid)
        for pid, name in ((router.pid, ROUTER_DOWN), (peer_holder.pid, PEER_PORT)):
            command(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", name, "mtu", str(DOWNSTREAM)])
        changed = time.monotonic_ns()
        second = phase(SECOND)
        existing = call(driver, "query s", "query")
        driver.send("shutdown s")
        driver.read()
        call(peer, "eof s", "eof")
        call(peer, "shutdown s", "shutdown")
        call(driver, "eof s", "eof")

        # A new connection after the decrease.
        peer.send("accept n")
        later = call(driver, f"connect n {destination} {PEER_LISTEN}", "connected")
        peer.read()
        driver.send(f"send n {LATER[0]} {LATER[1]}")
        peer.send(f"recv n {LATER[0]} {LATER[1]}")
        driver.read()
        later_received = peer.read()
        assert later_received["hash"] == fnv(pattern(*LATER)), later_received
        later_query = call(driver, "query n", "query")
        for process in (driver, peer):
            call(process, "shutdown n", "shutdown")
        for process in (driver, peer):
            call(process, "eof n", "eof")
        for process in (driver, peer):
            for name in ("s", "n"):
                call(process, f"close {name}", "closed")
        counter_after = router_counter(command, router.pid)

        events = native.since(marks["native"])
        out = [e for e in events if e.get("protocol") == 6 and e["direction"] == "out" and e["payload"]]
        port = int(established["local"].rsplit(":", 1)[1])
        stream = [e for e in out if e["sport"] == port]
        assert all(e["eth_dst"] == MACS[ROUTER_UP] and e["destination"] == destination and e["checksum_valid"]
                   for e in out), [summary(e) for e in out[:4]]
        originals = [e for e in stream if e["ip_length"] > DOWNSTREAM and e["time_ns"] > changed]
        assert originals, sorted({e["ip_length"] for e in stream})
        ptbs = [e for e in events if e.get("icmp_type") == 2 and e["direction"] == "in"]
        upstream = captures["upstream"].since(marks["upstream"])
        downstream = captures["downstream"].since(marks["downstream"])
        forwarded = [e for e in downstream if e["direction"] == "out" and e.get("protocol") == 6
                     and e["source"] == NATIVE]
        assert forwarded and max(e["ip_length"] for e in forwarded) <= DOWNSTREAM, \
            sorted({e["ip_length"] for e in forwarded})
        arrived = [e for e in upstream if e["direction"] == "in" and e.get("protocol") == 6 and e["source"] == NATIVE
                   and e["ip_length"] > DOWNSTREAM]
        assert arrived, "R received no oversized native packet"
        router_ptbs = [e for e in upstream if e["direction"] == "out" and e.get("icmp_type") == 2]
        if scenario == "black-hole":
            drops = black_hole_drops(command, router.pid)
            assert drops > 0 and not ptbs and not router_ptbs, (drops, [summary(e) for e in ptbs])
            dropped = originals[0]
            first_small = next(i for i, e in enumerate(stream) if e["time_ns"] > dropped["time_ns"]
                               and e["ip_length"] <= DOWNSTREAM and e["payload"] > 0
                               and ((e["seq"] - dropped["seq"]) & 0xffffffff) < dropped["payload"])
            ptb_evidence = dict(router_drops=drops, router_counter=dict(mid=counter_mid, after=counter_after),
                                ptbs_at_native=0)
            # No shared estimate from loss: the readback stays the path's.
            assert existing["path_mtu"] == FIRST_HOP and later_query["path_mtu"] == FIRST_HOP, (existing, later_query)
        else:
            assert ptbs and len(router_ptbs) == len(ptbs), ([summary(e) for e in ptbs], len(router_ptbs))
            correlation = []
            for ptb in ptbs:
                assert ptb["checksum_valid"] and ptb["mtu"] == DOWNSTREAM and ptb["eth_src"] == MACS[ROUTER_UP], \
                    summary(ptb)
                assert ptb["source"] in (ROUTER, ROUTER_LL) and ptb["destination"] == NATIVE, summary(ptb)
                match = next((o for o in out if icmp.quotes(ptb["quote"], o["raw"][14:])), None)
                assert match is not None and match["ip_length"] > DOWNSTREAM, ("PTB quotes no native packet", summary(ptb))
                correlation.append(dict(ptb=summary(ptb), quoted=summary(match), quote_bytes=len(ptb["quote"]),
                                        ptb_hex=ptb["raw"][:120].hex()))
            assert counter_after - counter_mid == len(ptbs), (counter_mid, counter_after, len(ptbs))
            dropped = next(o for o in stream if icmp.quotes(ptbs[0]["quote"], o["raw"][14:]))
            # Below proven 1500-octet delivery the PTB is deferred (RFC 5927
            # section 7.2) until the quoted data times out; its range is then
            # resent at the decreased size, and from there on nothing exceeds it.
            first_small = next(i for i, e in enumerate(stream) if e["time_ns"] > ptbs[0]["time_ns"]
                               and e["ip_length"] <= DOWNSTREAM
                               and ((e["seq"] - dropped["seq"]) & 0xffffffff) < dropped["payload"])
            ptb_evidence = dict(correlation=correlation, router_counter=dict(before=counter_before, mid=counter_mid,
                                                                             after=counter_after),
                                ptbs_at_native=len(ptbs), router_ptbs_upstream=len(router_ptbs))
            # D1: existing and new sockets read the path's 1280.
            assert existing["path_mtu"] == DOWNSTREAM and later_query["path_mtu"] == DOWNSTREAM, (existing, later_query)
        reduced = stream[first_small:]
        assert all(e["ip_length"] <= DOWNSTREAM for e in reduced), sorted({e["ip_length"] for e in reduced})
        assert covered(dropped, reduced), ("dropped range not repaired", summary(dropped))
        later_port = int(later["local"].rsplit(":", 1)[1])
        later_data = [e for e in out if e["sport"] == later_port]
        assert later_data and max(e["ip_length"] for e in later_data) <= DOWNSTREAM, \
            sorted({e["ip_length"] for e in later_data})
        native_link = json.loads(command(["ip", "-j", "link", "show", "dev", NATIVE_PORT]))[0]
        assert native_link["mtu"] == FIRST_HOP, native_link
        evidence.update(second_phase=second, existing_query=existing, later_connection=later, later_query=later_query,
                        later_received=later_received, ptb=ptb_evidence,
                        dropped=summary(dropped), oversized_after_change=len(originals),
                        reduced_segments=len(reduced), reduced_lengths=sorted({e["ip_length"] for e in reduced}),
                        later_lengths=sorted({e["ip_length"] for e in later_data}),
                        router_upstream=dict(oversized_arrivals=len(arrived), ptbs_out=len(router_ptbs)),
                        router_downstream=dict(forwarded=len(forwarded),
                                               max_forwarded=max(e["ip_length"] for e in forwarded)),
                        native_first_hop_mtu=native_link["mtu"],
                        stream_hashes=dict(first_out=first["peer_received"]["hash"],
                                           first_back=first["native_received"]["hash"],
                                           second_out=second["peer_received"]["hash"],
                                           second_back=second["native_received"]["hash"]),
                        frames=dict(native=len(native.since(0)), upstream=len(captures["upstream"].since(0)),
                                    downstream=len(captures["downstream"].since(0))),
                        frame_sample=[summary(e) for e in events[:40]])
        return evidence
    except BaseException:
        for name, capture in captures.items():
            try:
                evidence.setdefault("failure_frames", {})[name] = [summary(e) for e in capture.since(0)[-90:]]
            except Exception as e:
                evidence.setdefault("failure_frames", {})[name] = str(e)
        print("T19_NDPROXY_FAILURE " + json.dumps(evidence, sort_keys=True, default=str), flush=True)
        raise
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (driver and driver.close, peer and peer.close, *(c.close for c in captures.values()),
                      lambda: (router.kill(), router.wait()), lambda: (peer_holder.kill(), peer_holder.wait())):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors and not primary:
            raise RuntimeError(errors)


def peer_main():
    """P's plain kernel TCP endpoint, driven like the native `phased` mode."""
    def emit(**data):
        print(json.dumps(data, sort_keys=True), flush=True)

    emit(event="ready", namespace=os.stat("/proc/self/ns/net").st_ino)
    listener, connections = None, {}
    for line in sys.stdin:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "quit":
            break
        try:
            if fields[0] == "listen":
                listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("::", int(fields[1])))
                listener.listen(4)
                listener.settimeout(25)
                emit(event="listening", port=int(fields[1]))
                continue
            name = fields[1]
            if fields[0] == "accept":
                s, address = listener.accept()
                s.settimeout(25)
                connections[name] = s
                emit(event="accepted", id=name, peer=list(address[:2]), local=list(s.getsockname()[:2]))
            elif fields[0] == "connect":
                s = socket.create_connection((fields[2], int(fields[3])), timeout=25, source_address=(fields[4], 0))
                connections[name] = s
                emit(event="connected", id=name, local=list(s.getsockname()[:2]))
            elif fields[0] == "send":
                n, salt = int(fields[2]), int(fields[3])
                connections[name].sendall(pattern(n, salt))
                emit(event="sent", id=name, tx=n, salt=salt)
            elif fields[0] == "recv":
                n, salt = int(fields[2]), int(fields[3])
                data = bytearray()
                while len(data) < n:
                    chunk = connections[name].recv(n - len(data))
                    if not chunk:
                        raise RuntimeError(f"short stream {len(data)}/{n}")
                    data.extend(chunk)
                assert data == pattern(n, salt), "stream mismatch"
                emit(event="received", id=name, rx=n, salt=salt, hash=fnv(data))
            elif fields[0] == "shutdown":
                connections[name].shutdown(socket.SHUT_WR)
                emit(event="shutdown", id=name)
            elif fields[0] == "eof":
                assert connections[name].recv(1) == b"", "expected EOF"
                emit(event="eof", id=name)
            elif fields[0] == "close":
                connections.pop(name).close()
                emit(event="closed", id=name)
            else:
                raise RuntimeError(f"unknown command {fields[0]}")
        except Exception as e:
            emit(event="error", message=f"{type(e).__name__}: {e}")
            sys.exit(1)


if __name__ == "__main__":
    if sys.argv[1:] == ["peer"]:
        peer_main()
