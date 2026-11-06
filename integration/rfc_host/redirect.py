# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Native Redirect reception from a Linux router (T19): the bridge/R1/R2/P
fixture, one case per family.

N is the native runtime (this harness's binary in its `phased` mode, one
Host configured by the production configuration parser on a resolving
`io.*` port) on t19n in the harness namespace. B, R1, R2 and P are network
namespaces of the harness's user namespace, each held by a sleeping process
and entered by PID. B holds a Linux bridge (no addresses, IPv6 disabled,
multicast snooping off so Neighbor Discovery floods) joining N's link, R1's
t19r1 and R2's t19r2. P owns the destinations D and D2 on its loopback
behind two separate links, R1-P and R2-P, and routes N's network back
through R1.

N routes D's prefix through R1: IPv4 by `io.gateway` with `io.neighbor`
static mappings for R1 and R2 (no ARP; R1 and R2 map N statically too);
IPv6 by `io.gateway` to R1's link-local address, which N resolves by
Neighbor Discovery. R1 first routes D and D2 to P. Two TCP flows to D and
one to D2 are established and exchange data through R1; then only R1's
route to D is replaced by a route via R2 on its bridge interface, so N's
next submission to D enters and leaves R1 through the same interface and
the Linux kernel sends a Redirect (R1 also forwards that packet to R2).
Redirect reception is disabled on every router namespace.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import tempfile
import threading
import time

import admin
import icmp
from linux_peer import fnv, pattern
from ndproxy import held_namespace, namespace_socket, sysctl

HERE = Path(__file__).resolve().parent
NATIVE_PORT = "t19n"
BRIDGE, BRIDGE_PORTS = "t19br", dict(native="t19bn", r1="t19b1", r2="t19b2")
R1_UP, R1_DOWN, R2_UP, R2_DOWN = "t19r1", "t19r1p", "t19r2", "t19r2p"
P_FROM_R1, P_FROM_R2 = "t19p1", "t19p2"
MACS = {NATIVE_PORT: "02:00:00:19:05:02", R1_UP: "02:00:00:19:05:01", R2_UP: "02:00:00:19:05:03",
        R1_DOWN: "02:00:00:19:06:01", P_FROM_R1: "02:00:00:19:06:02",
        R2_DOWN: "02:00:00:19:07:01", P_FROM_R2: "02:00:00:19:07:02"}
ADDRESSES = {
    4: dict(native="10.19.0.2", r1="10.19.0.1", r2="10.19.0.3", prefix=24, gateway_r1="10.19.0.1",
            gateway_r2="10.19.0.3", r1_down="10.19.1.1", p1="10.19.1.2", r2_down="10.19.2.1", p2="10.19.2.2",
            destination="10.19.9.1", other="10.19.9.2", destinations="10.19.9.0/24", host=32),
    6: dict(native="fd19:5::2", r1="fd19:5::1", r2="fd19:5::3", prefix=64, gateway_r1="fe80::1",
            gateway_r2="fe80::3", r1_down="fd19:1::1", p1="fd19:1::2", r2_down="fd19:2::1", p2="fd19:2::2",
            destination="fd19:9::1", other="fd19:9::2", destinations="fd19:9::/64", host=128),
}
PEER_LISTEN = 18192
# (bytes, salt): the first exchange through R1, the exchange after R1's
# route change (native-to-peer, then peer-to-native), and the later flow.
FIRST = ((16384, 31), (4096, 37))
AFTER = ((24576, 41), (6144, 43))
LATER = (8192, 47)


def cases():
    return [dict(kind="redirect", family=family, scenario="linux-router") for family in (4, 6)]


def config(family, control):
    """The native runtime's configuration: a resolving `io.*` port, the
    gateway route for D's prefix through R1, IPv4's static neighbors for
    both routers, and the owner's control socket."""
    a = ADDRESSES[family]
    text = (f"io.backend=af-packet\nio.interface={NATIVE_PORT}\nio.address={a['native']}\nio.prefix={a['prefix']}\nio.source_quiet=never\n"
            f"io.gateway.{a['destinations']}={a['gateway_r1']}\n")
    if family == 4:
        text += f"io.neighbor.{a['r1']}={MACS[R1_UP]}\nio.neighbor.{a['r2']}={MACS[R2_UP]}\n"
    return text + f"control.socket={control}\n"


def mac(octets):
    return ":".join(f"{b:02x}" for b in octets)


def frame(raw):
    """One Ethernet frame: icmp.parse of its IPv4 or IPv6 packet with the
    Ethernet addresses, plus the fields of ICMP Redirects (IPv4 type 5,
    ICMPv6 type 137, with the quoted packet's TCP tuple and sequence) and
    of Neighbor Solicitations and Advertisements. None for anything else."""
    if len(raw) < 34 or struct.unpack_from("!H", raw, 12)[0] not in (0x0800, 0x86dd):
        return None
    ip = raw[14:]
    try:
        event = icmp.parse(ip)
    except Exception:
        return None
    if event is None:
        return None
    event.update(eth_dst=mac(raw[:6]), eth_src=mac(raw[6:12]), ip_length=event["length"],
                 hop_limit=ip[8] if event["family"] == 4 else ip[7])
    body = ip[event["header_len"]:event["length"]]
    if event.get("icmp_type") == 5 and event["family"] == 4 and len(body) >= 36:
        quote = body[8:]
        hl = (quote[0] & 15) * 4
        event.update(gateway=str(ipaddress.ip_address(body[4:8])), quote=quote,
                     quoted=dict(source=str(ipaddress.ip_address(quote[12:16])),
                                 destination=str(ipaddress.ip_address(quote[16:20])), protocol=quote[9],
                                 **tcp_fields(quote[hl:hl + 8])))
    elif event.get("icmp_type") == 137 and event["family"] == 6 and len(body) >= 40:
        event.update(target=str(ipaddress.ip_address(body[8:24])),
                     redirect_destination=str(ipaddress.ip_address(body[24:40])), tllao=None, quote=None)
        at = 40
        while at + 8 <= len(body) and body[at + 1]:
            kind, length = body[at], body[at + 1] * 8
            if kind == 2 and length == 8:
                event["tllao"] = mac(body[at + 2:at + 8])
            elif kind == 4:
                quote = body[at + 8:at + length]
                event["quote"] = quote
                if len(quote) >= 48:
                    event["quoted"] = dict(source=str(ipaddress.ip_address(quote[8:24])),
                                           destination=str(ipaddress.ip_address(quote[24:40])),
                                           protocol=quote[6], **tcp_fields(quote[40:48]))
            at += length
    elif event.get("icmp_type") in (135, 136) and event["family"] == 6 and len(body) >= 24:
        options, at = {}, 24
        while at + 8 <= len(body) and body[at + 1]:
            if body[at] in (1, 2) and body[at + 1] == 1:
                options[body[at]] = mac(body[at + 2:at + 8])
            at += body[at + 1] * 8
        event.update(target=str(ipaddress.ip_address(body[8:24])), sllao=options.get(1), tllao=options.get(2),
                     solicited=bool(body[4] & 0x40))
    return event


def tcp_fields(header):
    if len(header) < 8:
        return {}
    sport, dport, seq = struct.unpack_from("!HHI", header)
    return dict(sport=sport, dport=dport, seq=seq)


def summary(e):
    keys = ("direction", "eth_src", "eth_dst", "source", "destination", "ip_length", "sport", "dport", "seq",
            "payload", "flags", "icmp_type", "icmp_code", "gateway", "target", "redirect_destination", "tllao",
            "quoted", "df")
    return {k: e[k] for k in keys if k in e}


class Capture:
    """Both directions of one interface, in the harness namespace or (PID)
    another one; "out" frames left that namespace through it. Each event
    keeps its capture index, so order is the socket's arrival order."""

    def __init__(self, interface, pid=None):
        if pid is None:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.socket.bind((interface, 0))
        else:
            self.socket = namespace_socket(pid, interface)
        self.events, self.error, self.bytes = [], None, 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.socket], [], [], 0.1)[0]:
                    continue
                raw, address = self.socket.recvfrom(65536)
                event = frame(raw)
                if event is None:
                    continue
                with self.lock:
                    event.update(direction="out" if address[2] == socket.PACKET_OUTGOING else "in",
                                 time_ns=time.monotonic_ns(), raw=raw, index=len(self.events))
                    self.bytes += len(raw)
                    assert len(self.events) < 40000 and self.bytes < 96 * 1024 * 1024, "capture limit"
                    self.events.append(event)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"

    def mark(self):
        with self.lock:
            return len(self.events)

    def since(self, start):
        with self.lock:
            if self.error:
                raise RuntimeError(self.error)
            return list(self.events[start:])

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()


def setup(command, family, pids):
    """Links, addresses, routes and sysctls of N's side, B, R1, R2 and P."""
    a = ADDRESSES[family]
    v = "-" + str(family)
    here = lambda *args: command(list(args))
    inside = {name: (lambda pid: lambda *args: command(["nsenter", "-t", str(pid), "-n", *args]))(pid)
              for name, pid in pids.items()}
    b, r1, r2, p = (inside[n] for n in ("bridge", "r1", "r2", "peer"))
    sysctl(b, "net/ipv6/conf/all/disable_ipv6", 1)
    sysctl(b, "net/ipv6/conf/default/disable_ipv6", 1)
    for run in (here, r1, r2, p):
        # Only explicitly configured addresses; no DAD delay on them.
        for name in ("all", "default"):
            sysctl(run, f"net/ipv6/conf/{name}/addr_gen_mode", 1)
            sysctl(run, f"net/ipv6/conf/{name}/accept_dad", 0)
    for run in (here, b, r1, r2, p):
        run("ip", "link", "set", "lo", "up")
    # The routers forward and never act on Redirects themselves; P accepts
    # the asymmetric return (to N through R1, from N through R2).
    for run in (r1, r2):
        sysctl(run, "net/ipv4/ip_forward", 1)
        sysctl(run, "net/ipv6/conf/all/forwarding", 1)
        for name in ("all", "default"):
            sysctl(run, f"net/ipv4/conf/{name}/accept_redirects", 0)
            sysctl(run, f"net/ipv6/conf/{name}/accept_redirects", 0)
    for name in ("all", "default"):
        sysctl(p, f"net/ipv4/conf/{name}/rp_filter", 0)
    offload = ["tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"]
    b("ip", "link", "add", BRIDGE, "type", "bridge", "stp_state", "0", "mcast_snooping", "0")
    for near, ours, theirs, there, far in (
            (here, NATIVE_PORT, BRIDGE_PORTS["native"], pids["bridge"], b),
            (r1, R1_UP, BRIDGE_PORTS["r1"], pids["bridge"], b),
            (r2, R2_UP, BRIDGE_PORTS["r2"], pids["bridge"], b),
            (r1, R1_DOWN, P_FROM_R1, pids["peer"], p),
            (r2, R2_DOWN, P_FROM_R2, pids["peer"], p)):
        near("ip", "link", "add", ours, "type", "veth", "peer", "name", theirs, "netns", str(there))
        for run, name in ((near, ours), (far, theirs)):
            if name in MACS:
                run("ip", "link", "set", name, "address", MACS[name])
            run("ip", "link", "set", name, "mtu", "1500")
            run("ethtool", "-K", name, *offload)
        if far is b:
            b("ip", "link", "set", theirs, "master", BRIDGE)
    nodad = [] if family == 4 else ["nodad"]
    r1("ip", "addr", "add", f"{a['r1']}/{a['prefix']}", "dev", R1_UP, *nodad)
    r2("ip", "addr", "add", f"{a['r2']}/{a['prefix']}", "dev", R2_UP, *nodad)
    if family == 6:
        r1("ip", "addr", "add", a["gateway_r1"] + "/64", "dev", R1_UP, "nodad")
        r2("ip", "addr", "add", a["gateway_r2"] + "/64", "dev", R2_UP, "nodad")
    down = 24 if family == 4 else 64
    r1("ip", "addr", "add", f"{a['r1_down']}/{down}", "dev", R1_DOWN, *nodad)
    r2("ip", "addr", "add", f"{a['r2_down']}/{down}", "dev", R2_DOWN, *nodad)
    p("ip", "addr", "add", f"{a['p1']}/{down}", "dev", P_FROM_R1, *nodad)
    p("ip", "addr", "add", f"{a['p2']}/{down}", "dev", P_FROM_R2, *nodad)
    for address in (a["destination"], a["other"]):
        p("ip", "addr", "add", f"{address}/{a['host']}", "dev", "lo")
    for run, name in ((b, BRIDGE), *((b, n) for n in BRIDGE_PORTS.values()), (here, NATIVE_PORT),
                      (r1, R1_UP), (r1, R1_DOWN), (r2, R2_UP), (r2, R2_DOWN), (p, P_FROM_R1), (p, P_FROM_R2)):
        run("ip", "link", "set", name, "up")
    # Kernel neighbors are static wherever N is not the resolver: the
    # router-to-P links, R1's entry for R2 (IPv6: so its Redirect carries a
    # Target Link-Layer Address option) and, for IPv4 (N answers no ARP),
    # both routers' entries for N.
    static = [(r1, a["p1"], P_FROM_R1, R1_DOWN), (p, a["r1_down"], R1_DOWN, P_FROM_R1),
              (r2, a["p2"], P_FROM_R2, R2_DOWN), (p, a["r2_down"], R2_DOWN, P_FROM_R2),
              (r1, a["gateway_r2"], R2_UP, R1_UP)]
    if family == 4:
        static += [(r1, a["native"], NATIVE_PORT, R1_UP), (r2, a["native"], NATIVE_PORT, R2_UP)]
    for run, address, owner, device in static:
        run("ip", v, "neigh", "replace", address, "lladdr", MACS[owner], "nud", "permanent", "dev", device)
    for address in (a["destination"], a["other"]):
        r1("ip", v, "route", "replace", f"{address}/{a['host']}", "via", a["p1"], "dev", R1_DOWN)
        r2("ip", v, "route", "replace", f"{address}/{a['host']}", "via", a["p2"], "dev", R2_DOWN)
    network = str(ipaddress.ip_network(f"{a['native']}/{a['prefix']}", strict=False))
    p("ip", v, "route", "replace", network, "via", a["r1_down"], "dev", P_FROM_R1)
    native_link = json.loads(here("ip", "-j", "addr", "show", "dev", NATIVE_PORT))[0]
    assert not native_link.get("addr_info"), ("kernel address on the native-owned port", native_link)
    assert not json.loads(here("ip", "-j", v, "neigh", "show") or "[]"), "no kernel neighbor on N's side"
    to_destination = json.loads(r1("ip", "-j", v, "route", "get", a["destination"]))[0]
    back = json.loads(p("ip", "-j", v, "route", "get", a["native"]))[0]
    assert to_destination["dev"] == R1_DOWN and back["dev"] == P_FROM_R1, (to_destination, back)
    return dict(family=family, addresses=a, macs=MACS, router_sysctls=router_sysctls(r1, r2, p),
                bridge=json.loads(b("ip", "-j", "-d", "link", "show", BRIDGE))[0].get("linkinfo"),
                routes={name: json.loads(run("ip", "-j", v, "route", "show"))
                        for name, run in (("r1", r1), ("r2", r2), ("peer", p))},
                neighbors={name: run("ip", v, "neigh", "show").strip() for name, run in (("r1", r1), ("r2", r2))},
                namespaces={name: os.stat(f"/proc/{pid}/ns/net").st_ino for name, pid in pids.items()},
                mtu=native_link["mtu"], offload="disabled on every veth end")


def router_sysctls(r1, r2, p):
    paths = ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding",
             *(f"net/ipv4/conf/{n}/{k}" for n in ("all", "default") for k in
               ("send_redirects", "shared_media", "accept_redirects")),
             "net/ipv6/conf/all/accept_redirects", "net/ipv6/conf/default/accept_redirects",
             "net/ipv4/icmp_ratelimit", "net/ipv4/icmp_ratemask", "net/ipv6/icmp/ratelimit"]
    found = {name: {path: sysctl(run, path) for path in paths} for name, run in (("r1", r1), ("r2", r2))}
    for name, run, device in (("r1", r1, R1_UP), ("r2", r2, R2_UP)):
        found[name].update({f"net/ipv4/conf/{device}/{k}": sysctl(run, f"net/ipv4/conf/{device}/{k}")
                            for k in ("send_redirects", "shared_media", "accept_redirects", "forwarding")})
        found[name].update({f"net/ipv6/conf/{device}/{k}": sysctl(run, f"net/ipv6/conf/{device}/{k}")
                            for k in ("forwarding", "accept_redirects")})
    found["peer"] = {path: sysctl(p, path) for path in ("net/ipv4/conf/all/rp_filter",
                                                         "net/ipv4/conf/default/rp_filter")}
    return found


def redirect_counter(command, pid, family):
    """A router's kernel-generated Redirect count: IPv4 Icmp OutRedirects
    (/proc/net/snmp), IPv6 Icmp6OutRedirects (/proc/net/snmp6)."""
    if family == 6:
        text = command(["nsenter", "-t", str(pid), "-n", "cat", "/proc/net/snmp6"])
        return int(dict(line.split() for line in text.splitlines())["Icmp6OutRedirects"])
    lines = [line.split() for line in command(["nsenter", "-t", str(pid), "-n", "cat", "/proc/net/snmp"]).splitlines()
             if line.startswith("Icmp:")]
    return int(dict(zip(lines[0][1:], lines[1][1:]))["OutRedirects"])


def transition(segments, before, after):
    """Whether the Ethernet destinations of SEGMENTS (capture order) are
    BEFORE and then AFTER, never back; the first AFTER segment's index."""
    destinations = [e["eth_dst"] for e in segments]
    if after not in destinations:
        return None
    first = destinations.index(after)
    if any(d != before for d in destinations[:first]) or any(d != after for d in destinations[first:]):
        return None
    return segments[first]["index"]


def tcp_out(events, port, destination):
    return [e for e in events if e.get("protocol") == 6 and e["direction"] == "out" and e.get("sport") == port
            and e["destination"] == destination]


def quiet(capture, idle=0.5, limit=5.0):
    """Wait until CAPTURE saw no native TCP segment for IDLE seconds (the
    last delayed acknowledgments of an exchange have left), at most LIMIT."""
    deadline = time.monotonic() + limit
    seen = capture.mark()
    while time.monotonic() < deadline:
        time.sleep(idle)
        now = capture.mark()
        if not any(e.get("protocol") == 6 and e["direction"] == "out" for e in capture.since(seen)):
            return
        seen = now
    raise TimeoutError("native output did not go quiet")


def path_view(ctl, destination):
    """The valid ntcp-pathctl path record for DESTINATION and its TCP clients."""
    found = [p for p in ctl.paths() if p["destination"] == destination and p["valid"] == "1"]
    assert len(found) == 1, (destination, found)
    clients = admin.parse_records(ctl.run("clients", found[0]["token"]).stdout, "client")
    return dict(found[0], tcp_clients=sum(c["kind"] == "tcp" for c in clients))


def child(case, proof, binary, pathctl, Peer, command):
    family = case["family"]
    a = ADDRESSES[family]
    r1_mac, r2_mac = MACS[R1_UP], MACS[R2_UP]
    holders = {}
    peer = driver = None
    captures = {}
    directory = tempfile.mkdtemp(prefix="t19-redirect-control-")
    control = Path(directory) / "control.sock"
    evidence = dict(case=case)

    def call(process, line, event):
        process.send(line)
        result = process.read()
        assert result["event"] == event, result
        return result

    def exchange(name, sizes):
        (out_n, out_salt), (back_n, back_salt) = sizes
        driver.send(f"send {name} {out_n} {out_salt}")
        peer.send(f"recv {name} {out_n} {out_salt}")
        sent, received = driver.read(), peer.read()
        assert received["hash"] == fnv(pattern(out_n, out_salt)), received
        peer.send(f"send {name} {back_n} {back_salt}")
        driver.send(f"recv {name} {back_n} {back_salt}")
        back_sent, back_received = peer.read(), driver.read()
        assert back_received["hash"] == fnv(pattern(back_n, back_salt)), back_received
        return dict(native_sent=sent, peer_received=received, peer_sent=back_sent, native_received=back_received)

    def connect(name, destination):
        peer.send(f"accept {name}")
        connected = call(driver, f"connect {name} {destination} {PEER_LISTEN}", "connected")
        accepted = peer.read()
        assert accepted["event"] == "accepted", accepted
        return connected

    try:
        for name in ("bridge", "r1", "r2", "peer"):
            holders[name] = held_namespace(proof)
        pids = {name: h.pid for name, h in holders.items()}
        settings = setup(command, family, pids)
        evidence.update(settings=settings, configuration=config(family, control).splitlines())
        captures = dict(native=Capture(NATIVE_PORT), r1=Capture(R1_UP, pids["r1"]), r2=Capture(R2_UP, pids["r2"]))
        peer = Peer(["nsenter", "-t", str(pids["peer"]), "-n", sys.executable, "-B", HERE / "ndproxy.py", "peer"])
        assert peer.ready["namespace"] == settings["namespaces"]["peer"], peer.ready
        call(peer, f"listen {PEER_LISTEN}", "listening")
        driver = Peer([binary, "phased", config(family, control)])
        ctl = admin.Pathctl(pathctl, control)

        # Two flows to D and one to D2, established and exchanging through R1.
        flows = {name: connect(name, destination) for name, destination in
                 (("a", a["destination"]), ("b", a["destination"]), ("e", a["other"]))}
        first = {name: exchange(name, FIRST) for name in flows}
        ports = {name: int(c["local"].rsplit(":", 1)[1]) for name, c in flows.items()}
        native = captures["native"]
        initial = native.since(0)
        for name, destination in (("a", a["destination"]), ("b", a["destination"]), ("e", a["other"])):
            out = tcp_out(initial, ports[name], destination)
            assert out and all(e["eth_dst"] == r1_mac for e in out), [summary(e) for e in out[:4]]
        if family == 6:
            solicitations = [e for e in initial if e.get("icmp_type") == 135 and e["direction"] == "out"
                             and e["target"] == a["gateway_r1"]]
            advertisements = [e for e in initial if e.get("icmp_type") == 136 and e["direction"] == "in"
                              and e["target"] == a["gateway_r1"]]
            assert solicitations and advertisements and advertisements[0]["tllao"] == r1_mac, \
                [summary(e) for e in initial[:12]]
            first_tcp = min(e["index"] for e in initial if e.get("protocol") == 6 and e["direction"] == "out")
            assert advertisements[0]["index"] < first_tcp, "a native segment before R1 was resolved"
            evidence.update(resolution=dict(solicitation=summary(solicitations[0]),
                                            advertisement=summary(advertisements[0])))
        before_d, before_other = path_view(ctl, a["destination"]), path_view(ctl, a["other"])
        assert before_d["next_hop"] == before_other["next_hop"] == a["gateway_r1"], (before_d, before_other)
        assert before_d["tcp_clients"] == 2 and before_other["tcp_clients"] == 1, (before_d, before_other)

        # Only R1's route to D changes: via R2 on its bridge interface.
        quiet(native)
        marks = {name: c.mark() for name, c in captures.items()}
        counter_before = redirect_counter(command, pids["r1"], family)
        command(["nsenter", "-t", str(pids["r1"]), "-n", "ip", "-" + str(family), "route", "replace",
                 f"{a['destination']}/{a['host']}", "via", a["gateway_r2"], "dev", R1_UP])
        changed_route = json.loads(command(["nsenter", "-t", str(pids["r1"]), "-n", "ip", "-j", "-" + str(family),
                                            "route", "get", a["destination"]]))[0]
        assert changed_route["dev"] == R1_UP and changed_route.get("gateway") == a["gateway_r2"], changed_route
        after = {name: exchange(name, AFTER) for name in ("a", "b")}
        after_d = path_view(ctl, a["destination"])
        later = connect("c", a["destination"])
        ports["c"] = int(later["local"].rsplit(":", 1)[1])
        driver.send(f"send c {LATER[0]} {LATER[1]}")
        peer.send(f"recv c {LATER[0]} {LATER[1]}")
        driver.read()
        later_received = peer.read()
        assert later_received["hash"] == fnv(pattern(*LATER)), later_received
        with_later = path_view(ctl, a["destination"])
        other_after = exchange("e", AFTER)
        after_other = path_view(ctl, a["other"])
        for name in ("a", "b", "c", "e"):
            call(driver, f"shutdown {name}", "shutdown")
            call(peer, f"eof {name}", "eof")
            call(peer, f"shutdown {name}", "shutdown")
            call(driver, f"eof {name}", "eof")
            for process in (driver, peer):
                call(process, f"close {name}", "closed")
        counter_after = redirect_counter(command, pids["r1"], family)

        events = native.since(marks["native"])
        redirect_type = 5 if family == 4 else 137
        redirects = [e for e in events if e.get("icmp_type") == redirect_type and e["direction"] == "in"]
        assert redirects, [summary(e) for e in events[:30]]
        assert counter_after - counter_before == len(redirects), (counter_before, counter_after, len(redirects))
        first_redirect = redirects[0]
        out_a = tcp_out(events, ports["a"], a["destination"])
        correlation = []
        for r in redirects:
            assert r["checksum_valid"] and r["eth_src"] == r1_mac and r["destination"] == a["native"], summary(r)
            if family == 4:
                assert r["source"] == a["r1"] and r["icmp_code"] == 1 and r["gateway"] == a["r2"], summary(r)
            else:
                assert r["source"] == a["gateway_r1"] and r["icmp_code"] == 0 and r["hop_limit"] == 255, summary(r)
                assert r["target"] == a["gateway_r2"] and r["redirect_destination"] == a["destination"], summary(r)
                assert r["tllao"] == r2_mac, summary(r)
            quoted = r["quoted"]
            assert (quoted["source"], quoted["destination"], quoted["protocol"]) == \
                (a["native"], a["destination"], 6), summary(r)
            original = next((o for o in tcp_out(events, quoted["sport"], a["destination"])
                             if o["index"] < r["index"] and icmp.quotes(r["quote"], o["raw"][14:])), None)
            assert original is not None and original["eth_dst"] == r1_mac, ("Redirect quotes no submission", summary(r))
            assert (original["sport"], original["dport"], original["seq"]) == \
                (quoted["sport"], quoted["dport"], quoted["seq"]), (summary(original), quoted)
            correlation.append(dict(redirect=summary(r), original=dict(summary(original), index=original["index"]),
                                    quote_bytes=len(r["quote"]),
                                    redirect_hex=r["raw"][:96].hex()))
        # The first Redirect answers N's first submission to D after the
        # change: flow a's first data segment.
        assert out_a and correlation[0]["original"]["index"] == out_a[0]["index"], (correlation[0],
                                                                                    summary(out_a[0]))
        assert min(e["index"] for e in events if e.get("protocol") == 6 and e["direction"] == "out"
                   and e["destination"] == a["destination"]) == out_a[0]["index"], summary(out_a[0])
        # Native output to D moves from R1 to R2 after the Redirect arrived.
        switched = {}
        for name in ("a", "b", "c"):
            out = tcp_out(events, ports[name], a["destination"])
            index = transition(out, r1_mac, r2_mac)
            assert index is not None and index > first_redirect["index"], (name, [summary(e) for e in out[:8]])
            switched[name] = dict(segments=len(out), via_r1=sum(e["eth_dst"] == r1_mac for e in out),
                                  via_r2=sum(e["eth_dst"] == r2_mac for e in out), first_r2_index=index)
        later_out = tcp_out(events, ports["c"], a["destination"])
        syn = next(e for e in later_out if e["flags"] & 0x12 == 0x02)
        assert all(e["eth_dst"] == r2_mac for e in later_out) and syn["eth_dst"] == r2_mac, summary(syn)
        other_out = tcp_out(events, ports["e"], a["other"])
        assert other_out and all(e["eth_dst"] == r1_mac for e in other_out), [summary(e) for e in other_out[:4]]
        assert all(e["checksum_valid"] for e in events if e.get("protocol") == 6 and e["direction"] == "out")
        # R2 received N's segments to D from N's MAC on the bridge.
        at_r2 = [e for e in captures["r2"].since(marks["r2"]) if e.get("protocol") == 6 and e["direction"] == "in"
                 and e["source"] == a["native"] and e["eth_src"] == MACS[NATIVE_PORT]]
        assert at_r2 and all(e["eth_dst"] == r2_mac for e in at_r2), [summary(e) for e in at_r2[:4]]
        # R1 sent every Redirect N captured, through its bridge interface.
        from_r1 = [e for e in captures["r1"].since(marks["r1"]) if e.get("icmp_type") == redirect_type
                   and e["direction"] == "out"]
        assert len(from_r1) == len(redirects), (len(from_r1), len(redirects))
        # ntcp-pathctl: D's replacement path leaves to R2 with both flows,
        # then the later one too; D2's path keeps R1.
        assert after_d["next_hop"] == a["gateway_r2"] and after_d["token"] != before_d["token"], (before_d, after_d)
        assert after_d["route"] == before_d["route"] and after_d["tcp_clients"] == 2, (before_d, after_d)
        assert with_later["token"] == after_d["token"] and with_later["tcp_clients"] == 3, with_later
        assert after_other["next_hop"] == a["gateway_r1"] and after_other["tcp_clients"] == 1, after_other
        if family == 6:
            evidence["r2_resolution"] = [summary(e) for e in events if e.get("icmp_type") in (135, 136)
                                         and e.get("target") == a["gateway_r2"]][:8]
        native_link = json.loads(command(["ip", "-j", "link", "show", "dev", NATIVE_PORT]))[0]
        evidence.update(first_phase=first, after_phase=after, later_connection=later, later_received=later_received,
                        other_after=other_after, changed_route=changed_route, correlation=correlation,
                        redirect_counter=dict(before=counter_before, after=counter_after), redirects=len(redirects),
                        switched=switched, later_segments=len(later_out), other_segments=len(other_out),
                        at_r2=len(at_r2), from_r1=len(from_r1),
                        pathctl=dict(before=dict(destination=before_d, other=before_other),
                                     after=dict(destination=after_d, with_later=with_later, other=after_other),
                                     requests=len(ctl.log)),
                        stream_hashes={name: dict(first_out=first[name]["peer_received"]["hash"],
                                                  first_back=first[name]["native_received"]["hash"])
                                       for name in first} | {
                            "after_" + name: dict(out=after[name]["peer_received"]["hash"],
                                                  back=after[name]["native_received"]["hash"]) for name in after},
                        native_mtu=native_link["mtu"],
                        frames={name: len(c.since(0)) for name, c in captures.items()},
                        frame_sample=[summary(e) for e in events[:40]])
        return evidence
    except BaseException:
        for name, capture in captures.items():
            try:
                evidence.setdefault("failure_frames", {})[name] = [summary(e) for e in capture.since(0)[-90:]]
            except Exception as e:
                evidence.setdefault("failure_frames", {})[name] = str(e)
        print("T19_REDIRECT_FAILURE " + json.dumps(evidence, sort_keys=True, default=str), flush=True)
        raise
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (driver and driver.close, peer and peer.close, *(c.close for c in captures.values()),
                      *((lambda h=h: (h.kill(), h.wait())) for h in holders.values())):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        try:
            control.unlink()
        except FileNotFoundError:
            pass
        os.rmdir(directory)
        if errors and not primary:
            raise RuntimeError(errors)
