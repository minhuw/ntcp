# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Isolated ICMP scenario: ntcp <-> TUN(1500) <-> Linux router <-> veth <-> Linux peer.

The router namespace is the guarded harness namespace; the peer gets its own
network namespace inside the same harness-owned user namespace. Requests use a
1500-octet veth into the router. Replies leave the router on a separate veth
whose MTU is 1280 (a veth drops frames larger than its receiving end's MTU, so
one veth cannot carry 1500-octet requests in and limit replies to 1280). The
router kernel therefore generates every real Packet Too Big in these cases;
the harness only forges messages in the forged control. The staged cases
replace tun_echo with the harness-only ptb_stage sender, which controls only
when the application writes and when ingress is serviced; the driven cases
replace it with the harness-only datagram_drive driver (one Host UDP flow),
which controls only each send's mode and size and how long it is serviced.
"""
import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from bridge import checksum
from linux_peer import fnv, pattern

HERE = Path(__file__).resolve().parent
PORT = 18080
PEER_UDP_PORT = 18090
TUN = "t9tun"
TCP_BYTES = 49152
ADDRESSES = {
    4: dict(router="198.18.1.1", ntcp="198.18.1.2", ingress_router="198.18.2.1", peer="198.18.2.2",
            egress_router="198.18.3.1", egress_peer="198.18.3.2", wrong="198.18.2.3", prefix="24"),
    6: dict(router="2001:db8:91::1", ntcp="2001:db8:91::2", ingress_router="2001:db8:92::1",
            peer="2001:db8:92::2", egress_router="2001:db8:93::1", egress_peer="2001:db8:93::2",
            wrong="2001:db8:92::3", prefix="64"),
}
MACS = dict(t9ra="02:00:00:00:09:01", t9pa="02:00:00:00:09:02", t9rb="02:00:00:00:09:03", t9pb="02:00:00:00:09:04")
# The driven scenarios use the harness-only datagram_drive driver.
DRIVEN = ("probe-mode", "fragment-ptb", "adjunct-silence", "probe-report", "route-isolation")
SCENARIOS = ("udp-quoted", "tcp-quoted", "forged", "shared-fanout", "tcp-staged", "tcp-burst", "fragment") + DRIVEN
# The fragment scenario's Linux peer port (fragmentation-enabled socket),
# request size (larger than the 1500-octet links) and the peer reassembly
# capacity stated to tun_echo: Linux reassembles complete IP datagrams of up
# to 65535 octets (deployment knowledge of this topology's peer).
PEER_FRAGMENT_PORT = 18091
FRAGMENTED_REQUEST = 3000
PEER_REASSEMBLY = 65535
# The connectionless initial effective PMTU tun_echo uses (ntcp-host
# ConnectionlessSizing::default, RFC 4821 section 7.2).
CONNECTIONLESS_INITIAL = {4: 1024, 6: 1280}
# The adjunct's real waits: its first probe follows the first fragmented
# send, each probe waits up to the 3 s reply timeout.
ADJUNCT_WAIT = 30
STAGED = ("tcp-staged", "tcp-burst")
# The driver's peer: a receive-only socket (kernel reassembly) on this port.
SINK_PORT = 18092
# The driven cases' deployment configuration, stated per case and recorded:
# the connectionless initial effective PMTU (None: the ntcp-host default,
# CONNECTIONLESS_INITIAL) and the Echo adjunct's path table (0: disabled).
# fragment-ptb states 1500 so that, with nothing learned, its first
# fragments are cut to the 1500-octet first hop and exceed the 1280 egress.
DRIVER_SETTINGS = {"probe-mode": dict(initial=None, adjunct=0), "fragment-ptb": dict(initial=1500, adjunct=0),
                   "adjunct-silence": dict(initial=None, adjunct=4), "probe-report": dict(initial=None, adjunct=0),
                   "route-isolation": dict(initial=None, adjunct=0)}
# route-isolation's neighbor route and flow: selected by this DSCP (AF11).
NEIGHBOR_DSCP = 10
# RFC 1122 3.3.3: EMTU_S <= 576 off the connected network (Forwarder route).
IPV4_OFFLINK = 576
# The scenarios whose subject (the RFC 1191 6.6 DF policy) is IPv4-only.
IPV4_ONLY = ("route-isolation",)
# The owned drop rule of adjunct-silence: Echo Requests arriving from ntcp
# are dropped at the router's prerouting hook, before forwarding, so a
# probe draws neither an Echo Reply nor a router PTB.
SILENCE_TABLE = "t13silence"
# Real adjunct waits for two lost probes (3 s reply timeout each).
SILENCE_WAIT = 30
# The staged scenarios use the harness-only ptb_stage sender against a Linux
# listener on this port; its ACKs to ntcp are delayed by netem on t9pa.
STAGED_PORT = 18082
ACK_DELAY_MS = 200
# Router ICMP generation must not be rate limited: every oversized original
# needs its own PTB. Linux 6.12 already exempts IPv4 fragmentation-needed from
# the ratemask and the IPv6 default mask excludes type 2; both are recorded.
ROUTER_ICMP_SYSCTLS = (("net/ipv4/icmp_ratelimit", "0"), ("net/ipv4/icmp_msgs_per_sec", "100000"),
                       ("net/ipv4/icmp_msgs_burst", "100000"), ("net/ipv6/icmp/ratelimit", "0"),
                       # Default 6168 without bit 3 (destination unreachable).
                       ("net/ipv4/icmp_ratemask", "6160"), ("net/ipv6/icmp/ratemask", "0-1,3-127"))
# tun_echo's consumed per-flow UdpEvent::PacketTooBig: remote, dropped size, MTU.
ADVICE = r"UDP echo reply to (\S+) \((\d+) octets\) dropped by the path \(next-hop MTU (?:Some\()?(\d+)"
# The echo's local refusal of an oversize reply: by its path query before
# encoding, on a change notification while held, or by the send's own check.
# The echo's report of a shared path change it read without sending.
CHANGED = r"UDP echo path to (\S+) changed: MMS_S (\d+), payload limit (\d+)"
REFUSED = r"UDP echo of (\d+) octets to (\S+) refused(?: at send)?: exceeds the (?:changed )?path payload limit of (\d+)"


def cases():
    return [dict(kind="icmp", family=family, scenario=scenario) for family in (4, 6) for scenario in SCENARIOS
            if family == 4 or scenario not in IPV4_ONLY]


def header_len(family):
    return 20 if family == 4 else 40


def large_udp(family):
    return 1500 - header_len(family) - 8


def allowed_udp(family):
    return 1280 - header_len(family) - 8


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


def parse(packet):
    """Decode one raw IP packet; every checksum must be valid unless reported.

    A fragment (IPv4 MF or nonzero offset; IPv6 Fragment header) reports its
    fragment fields only: transport fields exist only in the reassembled
    datagram (`reassemble`)."""
    version = packet[0] >> 4
    if version == 4:
        hl = (packet[0] & 15) * 4
        total = u16(packet, 2)
        protocol = packet[9]
        source, destination = packet[12:16], packet[16:20]
        fragment = u16(packet, 6)
        # ip_id: the whole-packet Identification field, whatever DF says.
        info = dict(family=4, df=bool(fragment & 0x4000), fragmented=bool(fragment & 0x3fff),
                    ip_checksum_valid=checksum(packet[:hl]) == 0, ip_id=u16(packet, 4))
        if info["fragmented"]:
            info.update(ident=u16(packet, 4), offset=(fragment & 0x1fff) * 8, more=bool(fragment & 0x2000))
        pseudo = source + destination + bytes([0, protocol]) + struct.pack("!H", total - hl)
    elif version == 6:
        hl, total, protocol = 40, 40 + u16(packet, 4), packet[6]
        source, destination = packet[8:24], packet[24:40]
        info = dict(family=6, df=None, fragmented=protocol == 44, ip_checksum_valid=True)
        if protocol == 44 and total >= 48:
            # RFC 8200 section 4.5: base header -> Fragment header -> data.
            field = u16(packet, 42)
            info.update(ident=struct.unpack_from("!I", packet, 44)[0], offset=field & 0xfff8,
                        more=bool(field & 1), inner=packet[40])
            hl = 48
        pseudo = source + destination + struct.pack("!I", total - hl) + bytes([0, 0, 0, protocol])
    else:
        return None
    body = packet[hl:total]
    info.update(length=total, captured=len(packet), protocol=protocol, header_len=hl,
                source=str(ipaddress.ip_address(source)), destination=str(ipaddress.ip_address(destination)))
    if info["fragmented"]:
        info.update(data=len(body))
        if version == 6:
            info.update(protocol=info["inner"])
        return info
    if protocol == 6 and len(body) >= 20:
        offset = (body[12] >> 4) * 4
        sport, dport, seq, ack = struct.unpack_from("!HHII", body)
        info.update(sport=sport, dport=dport, seq=seq, ack=ack, flags=body[13], payload=len(body) - offset,
                    checksum_valid=checksum(pseudo + body) == 0, sack=sack_blocks(body[20:offset]))
    elif protocol == 17 and len(body) >= 8:
        sport, dport, length, value = struct.unpack_from("!HHHH", body)
        info.update(sport=sport, dport=dport, udp_length=length, udp_checksum=value, payload=length - 8,
                    checksum_valid=(value == 0 and version == 4) or checksum(pseudo + body) == 0)
    elif (protocol, version) in ((1, 4), (58, 6)) and len(body) >= 8:
        valid = checksum(body if version == 4 else pseudo + body) == 0
        info.update(icmp_type=body[0], icmp_code=body[1], checksum_valid=valid)
        if body[0] in ((0, 8) if version == 4 else (128, 129)):
            info.update(echo=body[0] in (8, 128), identifier=u16(body, 4), sequence=u16(body, 6), data=body[8:])
        if (version, body[0], body[1]) == (4, 3, 4):
            info.update(ptb=True, mtu=u16(body, 6), quote=body[8:])
        elif (version, body[0]) == (6, 2):
            info.update(ptb=True, mtu=struct.unpack_from("!I", body, 4)[0], quote=body[8:])
    return info


def reassemble(events):
    """Reconstruct complete datagrams from captured fragments before any
    transport parsing (RFC 791 section 3.2, RFC 8200 section 4.5).

    Fragments are keyed by direction, family, addresses, Identification and
    (IPv4) protocol. A datagram is complete when offset zero and a final
    fragment are present and the data is contiguous; overlapping fragments
    must carry identical bytes. Returns (datagram, fragments) pairs, where
    the datagram is `parse` of the reconstructed packet (so transport
    checksums cover the complete datagram)."""
    groups = {}
    for e in events:
        if not e["fragmented"]:
            continue
        key = (e["direction"], e["family"], e["source"], e["destination"], e["ident"],
               e["protocol"] if e["family"] == 4 else None)
        groups.setdefault(key, []).append(e)
    complete = []
    for fragments in groups.values():
        first = next((f for f in fragments if f["offset"] == 0), None)
        last = next((f for f in fragments if not f["more"]), None)
        if first is None or last is None:
            continue
        size = last["offset"] + last["data"]
        data, filled = bytearray(size), set()
        for f in fragments:
            raw = f["raw"][f["header_len"]:f["length"]]
            for i, byte in enumerate(raw):
                at = f["offset"] + i
                assert at < size and (at not in filled or data[at] == byte), ("inconsistent fragments", public(f))
                data[at] = byte
                filled.add(at)
        if len(filled) != size:
            continue
        raw = first["raw"]
        if first["family"] == 4:
            header = bytearray(raw[:first["header_len"]])
            struct.pack_into("!HH", header, 4, first["ident"], 0)
            struct.pack_into("!H", header, 2, len(header) + size)
            header[10:12] = b"\0\0"
            struct.pack_into("!H", header, 10, checksum(bytes(header)))
        else:
            header = bytearray(raw[:40])
            header[6] = first["inner"]
            struct.pack_into("!H", header, 4, size)
        datagram = parse(bytes(header) + bytes(data))
        datagram.update(direction=first["direction"], time_ns=max(f["time_ns"] for f in fragments),
                        raw=bytes(header) + bytes(data), sha256=None)
        complete.append((datagram, sorted(fragments, key=lambda f: f["offset"])))
    return sorted(complete, key=lambda c: c[0]["time_ns"])


def sack_blocks(options):
    """SACK option (kind 5) blocks as (left, right) pairs; None without one."""
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options) or options[i + 1] < 2 or i + options[i + 1] > len(options):
            return None  # malformed options: no SACK information
        length = options[i + 1]
        if kind == 5:
            if (length - 2) % 8:
                return None
            return [struct.unpack_from("!II", options, j) for j in range(i + 2, i + length - 7, 8)]
        i += length
    return None


def quotes(quote, original):
    """The quote is a prefix of the original except the forwarding-mutated TTL/hop limit and IPv4 header checksum."""
    mutable = {8, 10, 11} if original[0] >> 4 == 4 else {7}
    return 28 <= len(quote) <= len(original) and all(
        quote[i] == original[i] for i in range(len(quote)) if i not in mutable)


def public(event):
    return {k: v for k, v in event.items() if k not in ("raw", "quote", "data") or k == "data" and type(v) is int}


class Capture:
    """Both directions of the actual TUN device in the router namespace."""

    def __init__(self, name):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.socket.bind((name, 0))
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
                packet, address = self.socket.recvfrom(65536)
                event = parse(packet)
                if event is None:
                    continue
                # PACKET_OUTGOING is the router kernel (or the forged-control
                # injector) sending to ntcp; everything else came from ntcp.
                event.update(direction="to-ntcp" if address[2] == socket.PACKET_OUTGOING else "from-ntcp",
                             time_ns=time.monotonic_ns(), raw=packet)
                with self.lock:
                    self.bytes += len(packet)
                    assert len(self.events) < 20000 and self.bytes < 64 * 1024 * 1024, "capture limit"
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


class Ntcp:
    """The unmodified tun_echo example: TCP and UDP echo through one Host."""

    def __init__(self, binary, local, udp_mode, settings=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NTCP_") and k != "LD_PRELOAD"}
        # The UDP echo's send mode is selected explicitly per case; other
        # operational settings (deployment knowledge) are per case too.
        env["NTCP_UDP_ECHO_MODE"] = udp_mode
        env.update(settings or {})
        self.udp_mode, self.settings = udp_mode, dict(settings or {})
        self.p = subprocess.Popen([str(binary), TUN, local, str(PORT)], env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.lines = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        self.wait(r"echo listening on", 0, 10)

    def read(self):
        for line in self.p.stderr:
            with self.lock:
                if len(self.lines) < 4096:
                    self.lines.append(line.rstrip("\n"))

    def mark(self):
        with self.lock:
            return len(self.lines)

    def since(self, start):
        with self.lock:
            return list(self.lines[start:])

    def wait(self, expression, start, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.since(start):
                found = re.search(expression, line)
                if found:
                    return found
            assert self.p.poll() is None, dict(exit=self.p.returncode, stderr=self.since(0)[-20:])
            time.sleep(0.02)
        raise TimeoutError(dict(expected=expression, stderr=self.since(start)[-20:]))

    def close(self):
        # tun_echo serves until killed; it must still be serving at the end.
        alive = self.p.poll() is None
        self.p.kill()
        self.p.wait()
        self.thread.join(2)
        assert alive, dict(exit=self.p.returncode, stderr=self.since(0)[-20:])


def setup(family, egress_mtu, command, peer_pid):
    a = ADDRESSES[family]
    v = "-" + str(family)
    nodad = [] if family == 4 else ["nodad"]

    def router(*args):
        return command(["ip", *args])

    def peer(*args):
        return command(["nsenter", "-t", str(peer_pid), "-n", *args])

    def sysctl(run, path, value):
        run("sh", "-c", f"echo {value} > /proc/sys/{path}")

    for run in (lambda *x: command(list(x)), peer):
        # Asymmetric routing: strict reverse-path filtering would drop it.
        for name in ("all", "default"):
            sysctl(run, f"net/ipv4/conf/{name}/rp_filter", 0)
            sysctl(run, f"net/ipv6/conf/{name}/accept_dad", 0)
            sysctl(run, f"net/ipv6/conf/{name}/addr_gen_mode", 1)  # no kernel link-local noise
    sysctl(lambda *x: command(list(x)), "net/ipv4/ip_forward", 1)
    for path, value in ROUTER_ICMP_SYSCTLS:
        sysctl(lambda *x: command(list(x)), path, value)
    icmp_sysctls = {path: Path("/proc/sys/" + path).read_text().strip() for path, _ in ROUTER_ICMP_SYSCTLS}
    assert icmp_sysctls == dict(ROUTER_ICMP_SYSCTLS), icmp_sysctls
    sysctl(lambda *x: command(list(x)), "net/ipv6/conf/all/forwarding", 1)
    router("link", "set", "lo", "up")
    router("tuntap", "add", "dev", TUN, "mode", "tun")
    router("link", "set", TUN, "mtu", "1500")
    for ours, theirs, mtu in (("t9ra", "t9pa", 1500), ("t9rb", "t9pb", egress_mtu)):
        router("link", "add", ours, "type", "veth", "peer", "name", theirs)
        for name in (ours, theirs):
            router("link", "set", name, "address", MACS[name], "mtu", str(mtu))
    for name in (TUN, "t9ra", "t9rb", "t9pa", "t9pb"):
        # Complete checksums and no GSO/GRO aggregates on every owned interface.
        command(["ethtool", "-K", name, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"])
    router("link", "set", "t9pa", "netns", str(peer_pid))
    router("link", "set", "t9pb", "netns", str(peer_pid))
    router("addr", "add", a["router"] + "/" + a["prefix"], "dev", TUN, *nodad)
    router("addr", "add", a["ingress_router"] + "/" + a["prefix"], "dev", "t9ra", *nodad)
    router("addr", "add", a["egress_router"] + "/" + a["prefix"], "dev", "t9rb", *nodad)
    for name in (TUN, "t9ra", "t9rb"):
        router("link", "set", name, "up")
    peer("ip", "link", "set", "lo", "up")
    peer("ip", "addr", "add", a["peer"] + "/" + a["prefix"], "dev", "t9pa", *nodad)
    peer("ip", "addr", "add", a["egress_peer"] + "/" + a["prefix"], "dev", "t9pb", *nodad)
    for name in ("t9pa", "t9pb"):
        peer("ip", "link", "set", name, "up")
    ntcp_prefix = str(ipaddress.ip_network(a["ntcp"] + "/" + a["prefix"], strict=False))
    host = "/32" if family == 4 else "/128"
    # Explicit forward and return routes. Replies to the peer leave through
    # the 1280-octet egress veth; the ntcp address routes only to the TUN.
    router(v, "route", "replace", a["peer"] + host, "via", a["egress_peer"], "dev", "t9rb")
    router(v, "route", "replace", a["ntcp"] + host, "dev", TUN)
    peer("ip", v, "route", "replace", ntcp_prefix, "via", a["ingress_router"], "dev", "t9pa")
    router(v, "neigh", "replace", a["egress_peer"], "lladdr", MACS["t9pb"], "nud", "permanent", "dev", "t9rb")
    peer("ip", v, "neigh", "replace", a["ingress_router"], "lladdr", MACS["t9ra"], "nud", "permanent", "dev", "t9pa")
    owned = json.loads(router("-j", "addr", "show")) + json.loads(peer("ip", "-j", "addr", "show"))
    assert all(i["local"] != a["ntcp"] for link in owned for i in link.get("addr_info", [])), "ntcp address owned by Linux"
    to_peer = json.loads(router("-j", v, "route", "get", a["peer"]))[0]
    to_ntcp = json.loads(router("-j", v, "route", "get", a["ntcp"]))[0]
    from_peer = json.loads(peer("ip", "-j", v, "route", "get", a["ntcp"]))[0]
    assert to_peer["dev"] == "t9rb" and to_ntcp["dev"] == TUN and from_peer["dev"] == "t9pa", (to_peer, to_ntcp, from_peer)
    mtus = {link["ifname"]: link["mtu"] for link in json.loads(router("-j", "link", "show"))
            + json.loads(peer("ip", "-j", "link", "show"))}
    return dict(addresses=a, router_to_peer=to_peer, router_to_ntcp=to_ntcp, peer_to_ntcp=from_peer, mtu=mtus,
                ip_forward=1, ipv6_forwarding=1, offload="disabled on TUN and all four veth ends",
                router_icmp_sysctls=icmp_sysctls,
                peer_namespace=os.stat(f"/proc/{peer_pid}/ns/net").st_ino)


def counters(family):
    """Kernel-generated PTB count in the router namespace."""
    if family == 4:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        names, values = (l.split()[1:] for l in lines if l.startswith("Icmp:"))
        return int(dict(zip(names, values))["OutDestUnreachs"])
    return int(dict(l.split() for l in Path("/proc/net/snmp6").read_text().splitlines())["Icmp6OutPktTooBigs"])


def forge(family, quote, mtu, a, corrupt_icmp=False):
    """A PTB from the router's own TUN address: on-path impersonation."""
    src, dst = (ipaddress.ip_address(a[k]).packed for k in ("router", "ntcp"))
    if family == 4:
        icmp = bytearray(struct.pack("!BBHHH", 3, 4, 0, 0, mtu) + quote)
        struct.pack_into("!H", icmp, 2, checksum(bytes(icmp)))
    else:
        icmp = bytearray(struct.pack("!BBHI", 2, 0, 0, mtu) + quote)
        pseudo = src + dst + struct.pack("!I", len(icmp)) + b"\0\0\0\x3a"
        struct.pack_into("!H", icmp, 2, checksum(pseudo + bytes(icmp)))
    if corrupt_icmp:
        icmp[2] ^= 0x5a
    if family == 4:
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0, src, dst))
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(icmp), 58, 255, src, dst)
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    with s:
        packet = bytes(header) + bytes(icmp)
        assert s.sendto(packet, (a["ntcp"], 0)) == len(packet)
    return packet


def mutate(family, original, name):
    """Quote variants of an actually submitted packet that must not correlate."""
    limit = 576 - 28 if family == 4 else 1280 - 48  # Linux-sized quotes
    quote = bytearray(original[:limit])
    hl = header_len(family)
    if name == "udp-checksum":
        quote[hl + 6] ^= 0x01
        quote[hl + 7] ^= 0x01
    elif name == "udp-port":
        struct.pack_into("!H", quote, hl + 2, u16(quote, hl + 2) + 1)
    elif name == "ip-length":
        struct.pack_into("!H", quote, 2 if family == 4 else 4, u16(quote, 2 if family == 4 else 4) - 4)
    elif name == "destination":
        offset = 16 if family == 4 else 24
        packed = ipaddress.ip_address(ADDRESSES[family]["wrong"]).packed
        quote[offset:offset + len(packed)] = packed
    if family == 4 and name in ("ip-length", "destination"):
        quote[10:12] = b"\0\0"  # a well-formed inner header: rejection is correlation's
        struct.pack_into("!H", quote, 10, checksum(bytes(quote[:hl])))
    return bytes(quote)


def fragment_packet(family, effective):
    """The non-final fragment size the Host cuts at effective size E: the
    largest multiple of 8 data octets after the header (RFC 791, RFC 8200
    section 4.5)."""
    header = 20 if family == 4 else 48
    return header + ((effective - header) & ~7)


def fragmented(family, a, capture, ntcp, peer, ptbs):
    """Fragmented UDP and ICMP Echo in both directions plus the Echo adjunct.

    Linux sends fragmented >1500-octet requests; tun_echo (Fragment mode,
    stated peer capacity) reassembles them and source-fragments its replies
    to the connectionless effective size E. The capture keeps ntcp's physical
    fragments separate from the reconstructed messages. The adjunct's probes
    then run on the real path: a real Echo Reply is the only thing that may
    raise E above its configured initial value, and a probe above the
    1280-octet egress draws a real router PTB."""
    def reply_fragments(start, protocol, dport=None):
        events = capture.since(start)
        found = []
        for datagram, fragments in reassemble(events):
            if datagram["direction"] != "from-ntcp" or datagram["protocol"] != protocol:
                continue
            if (datagram["source"], datagram["destination"]) != (a["ntcp"], a["peer"]):
                continue
            if dport is not None and datagram.get("dport") != dport:
                continue
            assert datagram["checksum_valid"], ("reassembled transport checksum", public(datagram))
            for f in fragments:
                # DF on every originated IPv4 fragment; no IPv6 atomic fragment.
                assert f["ip_checksum_valid"] and (family == 6 or f["df"]), ("IPv4 DF", public(f))
                assert f["offset"] or f["more"], ("atomic fragment", public(f))
            found.append((datagram, fragments))
        return events, found

    def received(start, protocol):
        return [(d, f) for d, f in reassemble(capture.since(start)) if d["direction"] == "to-ntcp"
                and d["protocol"] == protocol and d["source"] == a["peer"] and d["destination"] == a["ntcp"]]

    def probes(events):
        return [e for e in events if e["direction"] == "from-ntcp" and not e["fragmented"]
                and e["protocol"] == (1 if family == 4 else 58) and e.get("echo") is True
                and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]

    def answers(events, probe):
        return [e for e in events if e["direction"] == "to-ntcp" and e.get("echo") is False
                and e["source"] == a["peer"] and (e["identifier"], e["sequence"]) == (probe["identifier"], probe["sequence"])
                and e["data"] == probe["data"] and e["checksum_valid"] and e["time_ns"] > probe["time_ns"]]

    def sizes(fragments):
        return [f["length"] for f in fragments]

    start = capture.mark()
    peer.send(f"fudp {FRAGMENTED_REQUEST} 41 5")
    first = peer.read()
    assert first["event"] == "fudp" and first["reply"] == FRAGMENTED_REQUEST and first["match"], first
    assert first["sha256"] == first["request_sha256"], first
    requests = received(start, 17)
    assert len(requests) == 1 and len(requests[0][1]) > 1, ("Linux fragmented the request", len(requests))
    assert requests[0][0]["payload"] == FRAGMENTED_REQUEST and requests[0][0]["checksum_valid"]
    events, replies = reply_fragments(start, 17, PEER_FRAGMENT_PORT)
    assert len(replies) == 1, [public(e) for e in events if e["direction"] == "from-ntcp"][:8]
    reply, pieces = replies[0]
    assert reply["payload"] == FRAGMENTED_REQUEST and reply["raw"][reply["header_len"] + 8:] == requests[0][0]["raw"][
        requests[0][0]["header_len"] + 8:], "reassembled reply differs from the request"
    # The first fragmented send precedes any probe: E is the configured
    # initial value (1020-octet IPv4 / 1280-octet IPv6 fragments).
    initial = fragment_packet(family, CONNECTIONLESS_INITIAL[family])
    assert all(size == initial for size in sizes(pieces)[:-1]) and sizes(pieces)[-1] <= initial, sizes(pieces)
    assert not probes([e for e in events if e["time_ns"] < pieces[0]["time_ns"]])

    # ICMP Echo: a fragmented request answered exactly with a fragmented reply.
    mark = capture.mark()
    peer.send(f"ping {FRAGMENTED_REQUEST} 42 5")
    echo = peer.read()
    assert echo["event"] == "ping" and echo["reply"] == FRAGMENTED_REQUEST and echo["match"], echo
    assert echo["checksum_valid"], echo
    echo_requests = received(mark, 1 if family == 4 else 58)
    assert len(echo_requests) == 1 and len(echo_requests[0][1]) > 1, "Linux fragmented the Echo Request"
    _, echo_replies = reply_fragments(mark, 1 if family == 4 else 58)
    echo_replies = [(d, f) for d, f in echo_replies if d.get("echo") is False]
    assert len(echo_replies) == 1 and echo_replies[0][0]["identifier"] == echo["identifier"], len(echo_replies)
    assert echo_replies[0][0]["data"] == echo_requests[0][0]["data"], "Echo Reply data differs"

    # The adjunct, driven by the retained demand of those fragmented sends
    # (no further sends): wait for a probe above 1280 drawing a real PTB.
    deadline = time.monotonic() + ADJUNCT_WAIT
    while True:
        events = capture.since(start)
        sent_probes = probes(events)
        drawn = [(p, q) for p in sent_probes if p["length"] > 1280 for q in ptbs(events)
                 if quotes(q["quote"], p["raw"])]
        if drawn:
            break
        assert time.monotonic() < deadline, ("no probe above 1280 drew a PTB", [public(p) for p in sent_probes])
        time.sleep(0.2)
    time.sleep(1)
    events = capture.since(start)
    sent_probes = probes(events)
    for p in sent_probes:
        assert p["checksum_valid"] and (family == 6 or p["df"]) and p["length"] <= 1500, public(p)
    confirmed = [(p, answers(events, p)) for p in sent_probes]
    confirmed = [(p, r[0]) for p, r in confirmed if r]
    for p, q in drawn:
        assert q["source"] == a["router"] and q["mtu"] == 1280 and q["checksum_valid"], public(q)
        assert not answers(events, p), "a probe beyond the egress MTU was answered"
    # Only a real Echo Reply raises E: the largest answered probe, under the
    # learned 1280 ceiling of the PTB.
    raised = max([CONNECTIONLESS_INITIAL[family]] + [p["length"] for p, _ in confirmed])
    effective = min(1280, raised)
    if family == 4:
        assert confirmed and effective > CONNECTIONLESS_INITIAL[4], [public(p) for p in sent_probes]

    # A later fragmented reply is cut to the raised E (IPv4) or stays at the
    # configured initial value where no reply could confirm more (IPv6 on a
    # 1280 path); never below it.
    mark = capture.mark()
    peer.send(f"fudp {FRAGMENTED_REQUEST} 43 5")
    later = peer.read()
    assert later["event"] == "fudp" and later["reply"] == FRAGMENTED_REQUEST and later["match"], later
    _, replies = reply_fragments(mark, 17, PEER_FRAGMENT_PORT)
    assert len(replies) == 1, len(replies)
    expected = fragment_packet(family, effective)
    later_sizes = sizes(replies[0][1])
    assert all(size == expected for size in later_sizes[:-1]) and later_sizes[-1] <= expected, (later_sizes, expected)
    if confirmed:
        first_confirmation = min(r["time_ns"] for _, r in confirmed)
        assert first_confirmation < replies[0][1][0]["time_ns"]
    return dict(peer_reassembly=PEER_REASSEMBLY, connectionless_initial=CONNECTIONLESS_INITIAL[family],
                fragmented_udp=dict(result=first, request_fragments=sizes(requests[0][1]), reply_fragments=sizes(pieces)),
                fragmented_echo=dict(result=echo, request_fragments=sizes(echo_requests[0][1]),
                                     reply_fragments=sizes(echo_replies[0][1])),
                adjunct=dict(probes=[dict(length=p["length"], df=p["df"], answered=bool(answers(events, p)))
                                     for p in sent_probes],
                             confirmed=[p["length"] for p, _ in confirmed],
                             ptb=[dict(probe=p["length"], mtu=q["mtu"], ptb_hex=q["raw"][:96].hex()) for p, q in drawn]),
                effective_after=effective, later_udp=dict(result=later, reply_fragments=later_sizes))


def silence_rule(command):
    """Install the owned drop rule in the router namespace; return its JSON."""
    nft = lambda *args: command(["nft", *args])
    nft("add", "table", "inet", SILENCE_TABLE)
    nft("add", "chain", "inet", SILENCE_TABLE, "pre", "{ type filter hook prerouting priority -300; }")
    nft("add", "rule", "inet", SILENCE_TABLE, "pre", "iifname", TUN, "icmp", "type", "echo-request", "counter", "drop")
    nft("add", "rule", "inet", SILENCE_TABLE, "pre", "iifname", TUN, "icmpv6", "type", "echo-request", "counter", "drop")
    return silence_counters(command)


def silence_counters(command):
    ruleset = json.loads(command(["nft", "-j", "list", "table", "inet", SILENCE_TABLE]))["nftables"]
    rules = [item["rule"] for item in ruleset if "rule" in item]
    drops = sum(next(e["counter"]["packets"] for e in r["expr"] if "counter" in e) for r in rules)
    return dict(rules=rules, dropped=drops)


def driven(family, scenario, a, capture, driver, peer, command, ptbs):
    """Host UDP send modes and the adjunct, attributed from the TUN capture.

    The driver reports each send's DatagramReport (and ProbeRecord), the
    flow's UdpDatagramLimits before and after, the consumed UdpEvents, the
    connectionless effective size, the shared learned estimate and the
    adjunct counters; the capture shows what physically left."""
    hl = header_len(family)
    ready = driver.ready
    initial = ready["connectionless_initial"]
    remote = f"[{a['peer']}]:{SINK_PORT}" if family == 6 else f"{a['peer']}:{SINK_PORT}"
    assert ready["learned_mtu"] is None and ready["budget"] == 1500, ready
    assert ready["effective_size"] == min(1500, initial) and ready["limits"]["guarantee_stated"], ready
    peer.send(f"sink {SINK_PORT}")
    assert peer.read()["event"] == "sinking"

    def send(mode, size, salt, wait=1000):
        mark = capture.mark()
        driver.send(f"send {mode} {size} {salt} {wait}")
        result = driver.read()
        assert result["event"] == "sent" and result["size"] == size, result
        time.sleep(0.2)
        return result, capture.since(mark)

    def own(events):
        """ntcp's physical UDP packets to the peer."""
        items = [e for e in events if e["direction"] == "from-ntcp" and e["protocol"] == 17
                 and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]
        for e in items:
            assert e["ip_checksum_valid"] and (family == 6 or e["df"]), ("IPv4 DF", public(e))
        return items

    def quoting(events, packet):
        found = [q for q in ptbs(events) if quotes(q["quote"], packet["raw"])]
        for q in found:
            assert q["checksum_valid"] and q["source"] == a["router"] and q["mtu"] == 1280, public(q)
        return found

    def too_big(result, length):
        return [e for e in result["events"] if e["kind"] == "packet_too_big" and e["remote"] == remote
                and e["dropped_len"] == length and e["mtu"] == 1280]

    def drain(wait=1.0):
        peer.send(f"drain {wait}")
        result = peer.read()
        assert result["event"] == "drain", result
        return result["datagrams"]

    def digest(size, salt):
        return hashlib.sha256(pattern(size, salt)).hexdigest()

    def sizes(packets):
        return [p["length"] for p in sorted(packets, key=lambda p: p.get("offset", 0))]

    if scenario == "probe-mode":
        # A real router PTB for an ordinary whole datagram teaches 1280.
        big = 1500 - hl - 8
        taught, events = send("refuse", big, 51)
        assert taught["report"] and taught["report"]["fragments"] == 1 and taught["report"]["probe"] is None, taught
        whole = own(events)
        assert sizes(whole) == [1500] and not whole[0]["fragmented"], [public(e) for e in whole]
        assert len(quoting(events, whole[0])) == 1 and too_big(taught, 1500), taught
        assert taught["learned_before"] is None and taught["learned_mtu"] == 1280 and taught["budget"] == 1280, taught
        probes = []
        for length, salt in ((1400, 52), (1500, 53)):
            probe, events = send("probe", length - hl - 8, salt)
            report, record = probe["report"], probe["report"] and probe["report"]["probe"]
            assert record and record["definite"] and record["size"] == length and record["above"] == 1280, probe
            assert (report["fragments"], report["submitted"], report["possibly_submitted"]) == (1, 1, 0), report
            assert probe["learned_before"] == 1280 and probe["limits_before"]["max_payload"] == 1500 - hl - 8, probe
            packets = own(events)
            # One unfragmented packet: IPv4 with DF, IPv6 without a Fragment header.
            assert sizes(packets) == [length] and not packets[0]["fragmented"] and packets[0]["checksum_valid"], (
                [public(e) for e in packets])
            # The submission raised nothing shared; the router's PTB for it
            # is an ordinary report to the flow.
            assert probe["learned_mtu"] == 1280 and probe["budget"] == 1280, probe
            assert probe["limits"]["unfragmented_payload"] == 1280 - hl - 8, probe
            drawn = quoting(events, packets[0])
            assert len(drawn) == 1 and too_big(probe, length), probe
            probes.append(dict(record=record, report=report, ip_length=length, df=packets[0]["df"],
                               fragment_header=packets[0]["fragmented"], events=probe["events"],
                               learned_after=probe["learned_mtu"], ptb_hex=drawn[0]["raw"][:96].hex()))
        # The learned estimate still governs ordinary sends.
        refused, events = send("refuse", big, 54)
        assert refused["report"] is None and refused["error"] == f"TooBig {{ max_payload: {1280 - hl - 8} }}", refused
        assert not own(events)
        return dict(taught=dict(report=taught["report"], events=taught["events"], learned=taught["learned_mtu"]),
                    probes=probes, refused_after=refused["error"], peer_received=drain(0.5))
    if scenario == "route-isolation":
        return route_isolation(a, capture, driver, drain, digest)
    if scenario == "probe-report":
        return probe_report(family, hl, send, own, quoting, drain, digest, sizes, driver)
    if scenario == "fragment-ptb":
        size = 2000
        first, events = send("fragment", size, 61)
        report, lengths = first["report"], first["submitted_lengths"]
        assert report and report["fragments"] == report["submitted"] == 2 and report["identification"] is not None, first
        assert first["limits_before"]["effective_size"] == 1500 and first["learned_before"] is None, first
        assert lengths[0] == fragment_packet(family, 1500) > 1280, lengths
        pieces = [e for e in own(events) if e["fragmented"] and e["ident"] == report["identification"]]
        assert sorted(sizes(pieces)) == sorted(lengths) and len(own(events)) == 2, [public(e) for e in own(events)]
        head = next(p for p in pieces if p["offset"] == 0)
        assert head["more"] and head["length"] == lengths[0] and head["header_len"] == (20 if family == 4 else 48)
        drawn = quoting(events, head)
        # The real router PTB quotes the first fragment; the Host correlated
        # it to the UDP owner and lowered the shared estimate.
        assert len(drawn) == 1 and too_big(first, head["length"]), first
        assert first["learned_mtu"] == 1280 and first["effective_size"] == 1280, first
        later, events = send("fragment", size, 62)
        expected = fragment_packet(family, 1280)
        later_lengths = later["submitted_lengths"]
        assert len(later_lengths) > 1 and all(n == expected for n in later_lengths[:-1]), (later_lengths, expected)
        assert later_lengths[-1] <= expected and not ptbs(events), later_lengths
        assert sorted(sizes(own(events))) == sorted(later_lengths)
        (datagram, _), = reassemble(own(events))
        assert datagram["checksum_valid"] and datagram["payload"] == size, public(datagram)
        received = drain(1.0)
        # The first datagram lost its first fragment; the later one arrives.
        assert [(d["size"], d["sha256"]) for d in received] == [(size, digest(size, 62))], received
        return dict(first=dict(report=report, fragments=lengths, events=first["events"], learned_after=first["learned_mtu"],
                               effective_after=first["effective_size"], ptb_hex=drawn[0]["raw"][:96].hex(),
                               quoted_fragment=public(head)),
                    later=dict(report=later["report"], fragments=later_lengths, effective=later["effective_size"]),
                    peer_received=received)
    # adjunct-silence: fragmented sends create demand; the drop rule makes
    # every probe go unanswered.
    rule = silence_rule(command)
    assert rule["dropped"] == 0 and len(rule["rules"]) == 2, rule
    start = capture.mark()
    expected = fragment_packet(family, initial)
    size = 3000
    states = []
    first, events = send("fragment", size, 71, 200)
    assert first["report"]["fragments"] == first["report"]["submitted"] > 1, first
    assert all(n == expected for n in first["submitted_lengths"][:-1]), first["submitted_lengths"]
    states.append(first)
    deadline = time.monotonic() + SILENCE_WAIT
    while states[-1]["adjunct"]["lost"] < 2:
        assert time.monotonic() < deadline, ("probes were not lost", states[-1])
        driver.send("serve 1000")
        served = driver.read()
        assert served["event"] == "served", served
        states.append(served)
    later, _ = send("fragment", size, 72, 200)
    assert later["submitted_lengths"] == first["submitted_lengths"], (later["submitted_lengths"], first["submitted_lengths"])
    states.append(later)
    for state in states:
        # Silence never lowers E or anything shared.
        assert state["effective_size"] == initial and state["learned_mtu"] is None and state["budget"] == 1500, state
        assert not state["events"], state
    counters = later["adjunct"]
    assert counters["lost"] >= 2 and counters["confirmed"] == counters["too_big"] == 0, counters
    time.sleep(0.3)
    events = capture.since(start)
    probes = [e for e in events if e["direction"] == "from-ntcp" and not e["fragmented"] and e.get("echo") is True
              and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]
    assert len(probes) == counters["probes"] >= 2, ([public(p) for p in probes], counters)
    for p in probes:
        assert p["checksum_valid"] and (family == 6 or p["df"]) and initial < p["length"] <= 1500, public(p)
    replies = [e for e in events if e["direction"] == "to-ntcp" and (e.get("echo") is False or e.get("ptb"))]
    assert not replies, [public(e) for e in replies]
    dropped = silence_counters(command)
    assert dropped["dropped"] == len(probes), (dropped, len(probes))
    received = drain(1.0)
    assert [(d["size"], d["sha256"]) for d in received] == [(size, digest(size, 71)), (size, digest(size, 72))], received
    return dict(drop_rule=dict(rule, dropped=dropped["dropped"], hook="inet prerouting priority -300", namespace="router"),
                probes=[dict(length=p["length"], df=p["df"], time_ns=p["time_ns"]) for p in probes],
                adjunct=counters, fragments=first["submitted_lengths"], later_fragments=later["submitted_lengths"],
                effective=[s["effective_size"] for s in states], learned=[s["learned_mtu"] for s in states],
                peer_received=received)


def route_isolation(a, capture, driver, drain, digest):
    """RFC 1191 6.6 route flag isolation between two routes on the wire.

    The driver's Host has its default route and a neighbor route on the same
    link and Forwarder next hop, selected by DSCP; one Fragment-mode flow to
    the peer resolves through each. After the owner disables discovery on
    the default route (one Host administration transaction through the
    owner's capability), that route's source fragments leave DF clear with
    one nonzero leased Identification per datagram, at most 576 octets
    (RFC 1122 3.3.3 EMTU_S off the connected network), while the neighbor
    route keeps DF on its fragments. The peer reassembles both."""
    driver.send(f"neighbor {NEIGHBOR_DSCP}")
    added = driver.read()
    assert added["event"] == "neighbor" and added["separate_route"] and added["resolved_neighbor_route"], added

    def sendvia(flow, salt):
        mark = capture.mark()
        driver.send(f"sendvia {flow} fragment {FRAGMENTED_REQUEST} {salt} 1000")
        result = driver.read()
        assert result["event"] == "sent" and result["error"] is None and result["report"], result
        time.sleep(0.2)
        packets = [e for e in capture.since(mark) if e["direction"] == "from-ntcp" and e["protocol"] == 17
                   and (e["source"], e["destination"]) == (a["ntcp"], a["peer"])]
        assert packets and all(e["fragmented"] and e["ip_checksum_valid"] for e in packets), [public(e) for e in packets]
        assert len({e["ident"] for e in packets}) == 1, "one Identification per datagram"
        offsets = sorted((e["offset"], e["data"], e["more"]) for e in packets)
        assert offsets[0][0] == 0 and not offsets[-1][2] and all(
            o + d == n for (o, d, _), (n, _, _) in zip(offsets, offsets[1:])), offsets
        return [dict(length=e["length"], df=e["df"], ident=e["ident"], offset=e["offset"], more=e["more"])
                for e in sorted(packets, key=lambda e: e["offset"])]

    before = dict(main=sendvia("main", 81), neighbor=sendvia("neighbor", 82))
    for name, packets in before.items():
        assert all(p["df"] for p in packets), (name, packets)
    driver.send("disable main")
    disabled = driver.read()
    assert disabled["event"] == "disabled" and disabled["route"] == "main", disabled
    after = dict(main=sendvia("main", 83), neighbor=sendvia("neighbor", 84))
    assert all(not p["df"] and p["ident"] != 0 and p["length"] <= IPV4_OFFLINK for p in after["main"]), after["main"]
    assert all(p["df"] for p in after["neighbor"]), after["neighbor"]
    assert after["main"][0]["ident"] != before["main"][0]["ident"], (before, after)
    received = drain(1.0)
    expected = sorted((port, FRAGMENTED_REQUEST, digest(FRAGMENTED_REQUEST, salt))
                      for port, salt in ((18083, 81), (18084, 82), (18083, 83), (18084, 84)))
    assert sorted((d["port"], d["size"], d["sha256"]) for d in received) == expected, received
    return dict(neighbor=added, disabled=disabled, before=before, after=after,
                peer_received=[dict(port=d["port"], size=d["size"]) for d in received])


def probe_report(family, hl, send, own, quoting, drain, digest, sizes, driver):
    """RFC 4821 section 9 outcome reports from a real receiver (T12).

    The application learns each probe's fate from the Linux sink (the
    receiver), then reports it with the probe's receipt. Success raises only
    this flow's confirmed size, which then drives its Fragment sizing on the
    wire; nothing shared changes (no shared-writer grant). A replayed
    receipt is refused. A probe the 1280 egress drops draws a router PTB
    that lowers the shared estimate after the submission, so its receipt is
    stale and the late report changes nothing."""
    def report(index, outcome):
        driver.send(f"report {index} {outcome}")
        result = driver.read()
        assert result["event"] == "reported", result
        return result

    delivered = 1200 if family == 4 else 1280
    probe, events = send("probe", delivered - hl - 8, 71)
    record = probe["report"] and probe["report"]["probe"]
    assert record and record["definite"] and record["size"] == delivered and probe["receipts"] == 1, probe
    packets = own(events)
    assert sizes(packets) == [delivered] and not packets[0]["fragmented"] and not quoting(events, packets[0])
    received = drain(1.0)
    assert [(d["size"], d["sha256"]) for d in received] == [(delivered - hl - 8, digest(delivered - hl - 8, 71))], received
    before = probe["limits"]["effective_size"]
    success = report(0, "success")
    assert success["report_error"] is None and success["confirmed"] == delivered, success
    assert success["shared"] == "NotOffered", success
    assert success["learned_mtu"] is None and success["budget"] == 1500, ("shared state unchanged", success)
    assert success["limits"]["effective_size"] == max(before, delivered), (before, success["limits"])
    replay = report(0, "success")
    assert replay["report_error"] == "Consumed" and replay["limits"] == success["limits"], replay
    # The flow-local bound drives this flow's Fragment sizing on the wire.
    fragmented, events = send("fragment", 3000, 72)
    pieces = own(events)
    assert fragmented["report"] and len(pieces) == fragmented["report"]["fragments"] > 1, fragmented
    assert all(length == fragment_packet(family, delivered) for length in sizes(pieces)[:-1]), sizes(pieces)
    assert [(d["size"], d["sha256"]) for d in drain(1.0)] == [(3000, digest(3000, 72))]
    # Lost at the 1280 egress: the router's PTB (a shared decrease after the
    # submission) makes the receipt stale.
    lost, events = send("probe", 1400 - hl - 8, 73)
    assert lost["receipts"] == 2 and sizes(own(events)) == [1400], lost
    assert len(quoting(events, own(events)[0])) == 1 and lost["learned_mtu"] == 1280, lost
    assert drain(0.5) == [], "the receiver got nothing"
    stale = report(1, "isolated-loss")
    assert stale["report_error"] == "StaleRevision" and stale["limits"]["effective_size"] == min(
        1280, success["limits"]["effective_size"]), stale
    return dict(probe=record, received=received, success={k: success[k] for k in ("confirmed", "upper", "shared",
                                                                                  "learned_mtu", "limits")},
                effective_before=before, replay=replay["report_error"], fragment_sizes=sizes(pieces),
                lost=lost["report"]["probe"], stale=stale["report_error"])


def staged(family, scenario, a, capture, stager, peer, command, sent, ptbs, accepted_ptb):
    """Causal attribution of PTB-driven repair from the TUN capture.

    The staged sender writes each segment in its own output pass without
    servicing ingress, while netem delays every peer-to-ntcp packet. A
    retransmission captured before the first useful ACK progress can then
    only be the response to a router PTB: TLP and RACK are off in this
    profile and the 1 s minimum RTO is far beyond the observed delays.
    """
    mss = 1500 - header_len(family) - 20
    ready = stager.ready
    assert ready["sack"] and not ready["tlp"] and not ready["rack"] and ready["rto_min_us"] >= 1_000_000, ready
    peer.send(f"listen {STAGED_PORT}")
    listening = peer.read()
    assert listening["event"] == "listening", listening
    stager.send("connect")
    established = stager.read()
    assert established["event"] == "established", established
    # The peer's ACK path only (t9pa); data toward the peer is undelayed.
    peer_ns = ["nsenter", "-t", str(peer.p.pid), "-n"]
    command([*peer_ns, "tc", "qdisc", "add", "dev", "t9pa", "root", "netem", "delay", f"{ACK_DELAY_MS}ms"])
    qdisc = json.loads(command([*peer_ns, "tc", "-j", "qdisc", "show", "dev", "t9pa"]))
    netem = [q for q in qdisc if q["kind"] == "netem"]
    assert len(netem) == 1 and netem[0]["options"]["delay"]["delay"] == ACK_DELAY_MS / 1000, qdisc
    # A fitting head, an oversized middle and a fitting tail; or several
    # distinct oversized originals (the RFC 5681 initial window holds three).
    sizes = [1000, mss, 600] if scenario == "tcp-staged" else [mss] * 3
    mark = capture.mark()
    stager.send("stage " + " ".join(map(str, sizes)))
    result = stager.read()
    assert result["event"] == "staged" and result["acknowledged"] == sum(sizes), result
    stager.send("close")
    closed = stager.read()
    assert closed["event"] == "closed" and closed["written"] == sum(sizes), closed
    peer.send(f"collect {sum(sizes)}")
    collected = peer.read()
    assert collected["event"] == "collect" and collected["rx"] == sum(sizes), collected
    assert collected["hash"] == fnv(pattern(sum(sizes), closed["salt"])), collected
    events = capture.since(mark)
    ports = (established["local_port"], STAGED_PORT)
    data = [e for e in sent(events, 6) if (e["sport"], e["dport"]) == ports and e["payload"]]
    back = [e for e in events if e["direction"] == "to-ntcp" and e["protocol"] == 6
            and (e["sport"], e["dport"]) == ports[::-1] and e["flags"] & 0x10]
    base = data[0]["seq"]

    def rel(seq):
        return (seq - base) & 0xffffffff

    def span(e):
        return rel(e["seq"]), rel(e["seq"]) + e["payload"]

    originals = data[:len(sizes)]
    assert [e["payload"] for e in originals] == sizes, [public(e) for e in data[:8]]
    assert [span(e)[0] for e in originals] == [sum(sizes[:i]) for i in range(len(sizes))], [public(e) for e in originals]
    oversized = [e for e in originals if e["length"] == 1500]
    assert len(oversized) == (1 if scenario == "tcp-staged" else 3), [public(e) for e in originals]
    assert all(e["length"] <= 1280 for e in originals if e not in oversized)
    # One router PTB per oversized original, each quoting exactly one of them.
    correlation = accepted_ptb(events, oversized)
    quoted = sorted({span(next(o for o in oversized if quotes(p["quote"], o["raw"])))
                     for p in ptbs(events)})
    assert len(correlation) == len(oversized) and quoted == sorted(span(o) for o in oversized), (correlation, quoted)
    # Useful ACK progress: a cumulative advance or newly SACKed bytes.
    progress, acked, sacked = [], 0, set()
    for e in back:
        cumulative = rel(e["ack"])
        blocks = [(rel(l), rel(r)) for l, r in e["sack"] or [] if rel(l) < rel(r) <= sum(sizes)]
        new = {b for l, r in blocks for b in range(l, r)} - sacked
        if cumulative > acked and cumulative <= sum(sizes) or new - set(range(cumulative)):
            progress.append(dict(time_ns=e["time_ns"], ack=cumulative, sack=blocks))
        acked = max(acked, cumulative) if cumulative <= sum(sizes) else acked
        sacked |= new
    assert progress, "no ACK progress captured"
    repairs = data[len(sizes):]
    # Every later data packet resends staged bytes (nothing new was written).
    assert all(span(e)[1] <= sum(sizes) for e in repairs), [public(e) for e in repairs]
    early = [e for e in repairs if e["time_ns"] < progress[0]["time_ns"]]
    assert len(early) == 1, ("exactly one PTB repair packet before useful ACK progress", [public(e) for e in early])
    first = early[0]
    within = next((q for q in quoted if q[0] <= span(first)[0] and span(first)[1] <= q[1]), None)
    assert within is not None and first["length"] <= 1280, (span(first), quoted)
    first_ptb = min(p["time_ns"] for p in ptbs(events))
    # PTB-caused: after the router's PTB, within milliseconds of it, and
    # long before the minimum RTO could have expired for any original.
    assert first_ptb < first["time_ns"] < first_ptb + 100_000_000, (first_ptb, first["time_ns"])
    assert first["time_ns"] - originals[0]["time_ns"] < ready["rto_min_us"] * 500, first
    acked_before = [e for e in back if e["time_ns"] < first["time_ns"] and rel(e["ack"]) > 0]
    if scenario == "tcp-staged":
        # Non-head: inside the quoted middle while the head is unacknowledged.
        assert within == span(oversized[0]) and span(first)[0] >= sizes[0] and not acked_before, (
            span(first), [public(e) for e in acked_before])
    # Between successive useful-progress events no byte is resent twice.
    epochs = {}
    for e in repairs:
        epoch = sum(p["time_ns"] < e["time_ns"] for p in progress)
        seen = epochs.setdefault(epoch, set())
        resent = set(range(*span(e)))
        assert not seen & resent, ("range retransmitted twice before ACK progress", epoch, span(e))
        seen |= resent
    # Repair stays inside the quoted ranges and completes them.
    covered = {b for e in repairs for b in range(*span(e))}
    assert covered == {b for l, r in quoted for b in range(l, r)}, (sorted(span(e) for e in repairs), quoted)
    return dict(profile=ready, netem=netem[0], sizes=sizes, start_sequence=result["start_sequence"],
                originals=[dict(span=span(e), ip_length=e["length"], time_ns=e["time_ns"]) for e in originals],
                quoted_ranges=quoted, correlation=correlation,
                first_repair=dict(span=span(first), ip_length=first["length"], time_ns=first["time_ns"],
                                  after_first_ptb_ns=first["time_ns"] - first_ptb),
                first_progress=progress[0], progress_events=len(progress),
                repairs=[dict(span=span(e), ip_length=e["length"], time_ns=e["time_ns"]) for e in repairs],
                head_acknowledged_before_first_repair=bool(acked_before), stream=collected,
                path_mtu=result["path_mtu"])


def child(case, proof, binary, Peer, command, emit, staged_binary=None, driver_binary=None):
    family, scenario = case["family"], case["scenario"]
    a = ADDRESSES[family]
    egress_mtu = 1500 if scenario == "forged" else 1280
    big, allowed = large_udp(family), allowed_udp(family)
    small_mss = 1280 - header_len(family) - 20
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", a["peer"], a["ntcp"], PORT])
    ntcp = capture = stager = driver = None
    evidence = dict(case=case)
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = setup(family, egress_mtu, command, peer.p.pid)
        assert settings["peer_namespace"] == peer.ready["namespace"]
        capture = Capture(TUN)
        if scenario in STAGED:
            # The staged sender, not tun_echo, owns the TUN in these cases.
            port = f"[{a['peer']}]:{STAGED_PORT}" if family == 6 else f"{a['peer']}:{STAGED_PORT}"
            stager = Peer([staged_binary, TUN, a["ntcp"], port])
        elif scenario in DRIVEN:
            # The datagram driver owns the TUN: one Host UDP flow to the
            # peer's sink, with the case's stated deployment configuration.
            config = DRIVER_SETTINGS[scenario]
            initial = config["initial"] or CONNECTIONLESS_INITIAL[family]
            port = f"[{a['peer']}]:{SINK_PORT}" if family == 6 else f"{a['peer']}:{SINK_PORT}"
            driver = Peer([driver_binary, TUN, a["ntcp"], port, initial, PEER_REASSEMBLY, config["adjunct"]])
            evidence.update(driver_configuration=dict(
                connectionless_initial=initial, peer_reassembly=PEER_REASSEMBLY, adjunct_paths=config["adjunct"],
                stated="deployment configuration of this case (Linux peer reassembles 65535-octet datagrams)",
                identifier_continuity=driver.ready["continuity"], mdl_seconds=driver.ready["mdl_seconds"],
                source_quiet_assertion="harness-created address in a fresh namespace: no earlier emission"))
        elif scenario == "fragment":
            # Fragment mode with the Linux peer's reassembly capacity stated
            # (deployment knowledge). The harness created the ntcp address in
            # a fresh namespace for this case, so it asserts that nothing
            # emitted from it before (decision D14; recorded as evidence).
            ntcp = Ntcp(binary, a["ntcp"], "fragment", {
                f"NTCP_PEER_REASSEMBLY_IPV{family}": str(PEER_REASSEMBLY), "NTCP_SOURCE_QUIET": "never"})
            evidence.update(tun_echo_udp_mode=ntcp.udp_mode, tun_echo_settings=ntcp.settings,
                            source_quiet_assertion="harness-created address in a fresh namespace: no earlier emission")
        else:
            # These cases' evidence is whole UDP replies and the refusal of
            # oversize ones (the path payload limit wording): Refuse mode.
            ntcp = Ntcp(binary, a["ntcp"], "refuse")
            evidence.update(tun_echo_udp_mode=ntcp.udp_mode)
        kernel_before = counters(family)

        def udp(size, salt, wait=2.0):
            peer.send(f"udp {size} {salt} {wait}")
            result = peer.read()
            assert result["event"] == "udp" and result["salt"] == salt, result
            return result

        def tcp(salt):
            peer.send(f"tcp {TCP_BYTES} {salt}")
            result = peer.read()
            assert result["event"] == "tcp" and (result["tx"], result["rx"]) == (TCP_BYTES, TCP_BYTES), result
            assert result["hash"] == fnv(pattern(TCP_BYTES, salt)), result
            return result

        def sent(events, protocol):
            items = [e for e in events if e["direction"] == "from-ntcp" and e["protocol"] == protocol
                     and e["source"] == a["ntcp"] and e["destination"] == a["peer"]]
            for e in items:
                assert not e["fragmented"] and e["checksum_valid"] and e["ip_checksum_valid"], public(e)
                assert family == 6 or e["df"], ("IPv4 DF is required", public(e))
            return items

        def ptbs(events):
            return [e for e in events if e["direction"] == "to-ntcp" and e.get("ptb")]

        def accepted_ptb(events, originals):
            found = []
            for ptb in ptbs(events):
                assert ptb["checksum_valid"] and ptb["source"] == a["router"] != a["peer"], public(ptb)
                assert ptb["destination"] == a["ntcp"] and ptb["mtu"] == 1280, public(ptb)
                match = next((o for o in originals if quotes(ptb["quote"], o["raw"])), None)
                assert match is not None, ("PTB quotes no captured ntcp packet", public(ptb))
                found.append(dict(ptb=public(ptb), quoted_bytes=len(ptb["quote"]), original=public(match),
                                  ptb_hex=ptb["raw"][:96].hex()))
            return found

        # Warm-up proves both routes before any oversize traffic.
        if ntcp is not None:
            warm = udp(64, 1)
            assert warm["reply"] == 64 and warm["match"], warm
        def stream(command, name, size, salt):
            peer.send(f"{command} {name} {size} {salt}")
            result = peer.read()
            assert result["event"] == command and result["name"] == name and result["rx"] == size, result
            return result

        def inner(ptb):
            """The quoted packet's transport tuple (the quote is truncated)."""
            quoted = parse(ptb["quote"])
            assert quoted is not None and quoted["source"] == a["ntcp"] and quoted["destination"] == a["peer"], public(ptb)
            return dict(protocol=quoted["protocol"], sport=quoted.get("sport"), dport=quoted.get("dport"),
                        seq=quoted.get("seq"), length=quoted["length"])

        if scenario == "fragment":
            evidence.update(fragmented(family, a, capture, ntcp, peer, ptbs))
        elif scenario in DRIVEN:
            evidence.update(driven(family, scenario, a, capture, driver, peer, command, ptbs))
        elif scenario in STAGED:
            evidence.update(staged(family, scenario, a, capture, stager, peer, command, sent, ptbs, accepted_ptb))
        elif scenario == "shared-fanout":
            # A UDP client and TCP streams A and B, all established on the one
            # path before any oversize packet. Only A then sends large data.
            b_open = stream("open", "b", 64, 31)
            a_open = stream("open", "a", 64, 32)
            assert a_open["local_port"] != b_open["local_port"]
            mark, line = capture.mark(), ntcp.mark()
            a_done = stream("finish", "a", TCP_BYTES, 33)
            assert a_done["hash"] == fnv(pattern(TCP_BYTES, 33)), a_done
            # The UDP echo reports the shared change without sending.
            changed = ntcp.wait(CHANGED, line, 5)
            assert (changed.group(1), int(changed.group(2)), int(changed.group(3))) == (
                a["peer"], 1280 - header_len(family), allowed), changed.group(0)
            events = capture.since(mark)
            assert not sent(events, 17), "UDP sent nothing while A was quoted"
            b_quiet = [e for e in sent(events, 6) if b_open["local_port"] in (e["sport"], e["dport"])]
            assert not b_quiet, ("B was quiescent", [public(e) for e in b_quiet[:4]])
            data = [e for e in sent(events, 6) if e["payload"] and e["dport"] == a_open["local_port"]]
            originals = [e for e in data if e["length"] == 1500]
            assert originals, [public(e) for e in data[:8]]
            # Every PTB the capture holds, from setup on, quotes A's TCP tuple:
            # none quotes B or the UDP flow.
            all_ptbs = ptbs(capture.since(0))
            tuples = [inner(p) for p in all_ptbs]
            assert tuples and all(t["protocol"] == 6 and (t["sport"], t["dport"]) == (PORT, a_open["local_port"])
                                  for t in tuples), tuples
            correlation = accepted_ptb(events, originals)
            assert len(correlation) == len(all_ptbs), (correlation, tuples)
            # B, never quoted, completes within the new limit with no PTB.
            mark = capture.mark()
            b_done = stream("finish", "b", TCP_BYTES, 34)
            assert b_done["hash"] == fnv(pattern(TCP_BYTES, 34)), b_done
            events = capture.since(mark)
            b_data = [e for e in sent(events, 6) if e["payload"] and e["dport"] == b_open["local_port"]]
            assert b_data and max(e["length"] for e in b_data) == 1280 and not ptbs(events), (
                [public(e) for e in b_data[:8]], [public(e) for e in ptbs(events)])
            # The UDP echo refuses an oversize reply locally and returns a
            # fitting one exactly.
            mark, line = capture.mark(), ntcp.mark()
            refused_udp = udp(big, 35, 1.0)
            assert refused_udp["reply"] is None, refused_udp
            refused = ntcp.wait(REFUSED, line, 5)
            assert (int(refused.group(1)), int(refused.group(3))) == (big, allowed), refused.group(0)
            fitted = udp(allowed, 36)
            assert fitted["reply"] == allowed and fitted["match"], fitted
            later = sent(capture.since(mark), 17)
            assert [e["length"] for e in later] == [1280] and not ptbs(capture.since(mark)), [public(e) for e in later]
            evidence.update(a=dict(open=a_open, finish=a_done, large_segments=len(originals)),
                            b=dict(open=b_open, finish=b_done, data_packets=len(b_data),
                                   max_ip_length=max(e["length"] for e in b_data)),
                            quoted_tuples=tuples, correlation=correlation, udp_change=changed.group(0),
                            oversize_refusal=refused.group(0), fitting_udp=dict(reply=fitted, ip_length=later[0]["length"]))
        elif scenario == "udp-quoted":
            mark, line = capture.mark(), ntcp.mark()
            dropped = udp(big, 2, 1.0)
            assert dropped["reply"] is None, dropped
            # The consumed per-flow advice event exists only after the Host
            # correlated the router's PTB with its own submission evidence.
            advice = ntcp.wait(ADVICE, line, 5)
            assert int(advice.group(3)) == 1280 and int(advice.group(2)) == 1500, advice.group(0)
            events = capture.since(mark)
            originals = [e for e in sent(events, 17) if e["length"] == 1500]
            assert len(originals) == 1 and originals[0]["dport"] == PEER_UDP_PORT, [public(e) for e in sent(events, 17)]
            correlation = accepted_ptb(events, originals)
            assert len(correlation) == 1, correlation
            mark, line = capture.mark(), ntcp.mark()
            again = udp(big, 3, 1.0)
            assert again["reply"] is None, again
            refused = ntcp.wait(REFUSED, line, 5)
            assert (int(refused.group(1)), int(refused.group(3))) == (big, allowed), refused.group(0)
            fitted = udp(allowed, 4)
            assert fitted["reply"] == allowed and fitted["match"], fitted
            later = sent(capture.since(mark), 17)
            assert [e["length"] for e in later] == [1280] and not ptbs(capture.since(mark)), [public(e) for e in later]
            # TCP on the same path inherits the shared decrease at its egress.
            mark = capture.mark()
            stream = tcp(5)
            events = capture.since(mark)
            data = [e for e in sent(events, 6) if e["payload"]]
            assert data and max(e["length"] for e in data) == 1280 and not ptbs(events), (
                [public(e) for e in data[:8]], [public(e) for e in ptbs(events)])
            evidence.update(udp_dropped=dropped, advice=advice.group(0), correlation=correlation,
                            oversize_refusal=refused.group(0), smaller_udp=dict(reply=fitted, ip_length=later[0]["length"]),
                            tcp_after_udp_ptb=dict(stream=stream, data_packets=len(data),
                                                   max_ip_length=max(e["length"] for e in data)))
        elif scenario == "tcp-quoted":
            mark = capture.mark()
            stream = tcp(7)
            events = capture.since(mark)
            data = [e for e in sent(events, 6) if e["payload"]]
            originals = [e for e in data if e["length"] == 1500]
            assert originals, [public(e) for e in data[:8]]
            correlation = accepted_ptb(events, originals)
            assert correlation and all(c["original"]["protocol"] == 6 for c in correlation), correlation
            # Once ntcp sends its first reduced data segment it never again
            # sends 1500 octets, and the first dropped range is resent smaller.
            first_small = next(i for i, e in enumerate(data) if e["length"] <= 1280)
            assert all(e["length"] <= 1280 for e in data[first_small:]), [public(e) for e in data[first_small:][:8]]
            assert max(e["length"] for e in data[first_small:]) == 1280 and max(e["payload"] for e in data) == 1500 - header_len(family) - 20
            dropped = next(o for o in originals if quotes(ptbs(events)[0]["quote"], o["raw"]))
            covered = set()
            for e in data[first_small:]:
                start = (e["seq"] - dropped["seq"]) & 0xffffffff
                if start < 1 << 31:
                    covered.update(range(start, min(start + e["payload"], dropped["payload"])))
            assert covered == set(range(dropped["payload"])), ("dropped range not resent", public(dropped))
            assert data.index(next(e for e in data if e["raw"] == dropped["raw"])) < first_small
            # The TCP owner's accepted decrease is the Host's shared estimate.
            mark, line = capture.mark(), ntcp.mark()
            refused_udp = udp(big, 8, 1.0)
            assert refused_udp["reply"] is None, refused_udp
            refused = ntcp.wait(REFUSED, line, 5)
            assert (int(refused.group(1)), int(refused.group(3))) == (big, allowed), refused.group(0)
            fitted = udp(allowed, 9)
            assert fitted["reply"] == allowed and fitted["match"], fitted
            assert not [e for e in sent(capture.since(mark), 17) if e["length"] > 1280]
            evidence.update(stream=stream, correlation=correlation, dropped_range=dict(seq=dropped["seq"], payload=dropped["payload"]),
                            large_segments=len(originals), reduced_segments=len(data) - first_small,
                            reduced_payload=small_mss, udp_after_tcp_ptb=refused.group(0), smaller_udp=fitted)
        else:
            mark = capture.mark()
            first = udp(big, 11)
            assert first["reply"] == big and first["match"], first
            stream = tcp(12)
            events = capture.since(mark)
            replies = [e for e in sent(events, 17) if e["length"] == 1500]
            segments = [e for e in sent(events, 6) if e["length"] == 1500]
            assert len(replies) == 1 and segments and not ptbs(events), "no real PTB on a 1500-octet path"
            line = ntcp.mark()
            rejected = []
            # Off-path forgery of every correlated field: transport selector,
            # port, size, address, stale TCP data, and wire checksum.
            for name, original in (("udp-checksum", replies[0]), ("udp-port", replies[0]),
                                   ("ip-length", replies[0]), ("destination", replies[0]),
                                   ("tcp-stale", segments[0]), ("icmp-checksum", replies[0])):
                start = ntcp.mark()
                packet = forge(family, mutate(family, original["raw"], name), 1280, a,
                               corrupt_icmp=name == "icmp-checksum")
                time.sleep(0.3)
                assert not ntcp.since(start), (name, ntcp.since(start))
                rejected.append(dict(variant=name, forged_hex=packet[:96].hex(), length=len(packet)))
            mark = capture.mark()
            after = udp(big, 13)
            assert after["reply"] == big and after["match"], after
            stream_after = tcp(14)
            events = capture.since(mark)
            unchanged = [e for e in sent(events, 17) if e["length"] == 1500]
            assert len(unchanged) == 1 and [e for e in sent(events, 6) if e["length"] == 1500], "forgery changed the path"
            forged_seen = [e for e in capture.since(0) if e["direction"] == "to-ntcp" and e.get("ptb")]
            assert len(forged_seen) == len(rejected), "every forged PTB reached the TUN"
            assert not ntcp.since(line), ntcp.since(line)
            # Positive control from the same injector: an exact quote of a
            # real reply is plausible to the Host (not authentication).
            line = ntcp.mark()
            control = forge(family, mutate(family, unchanged[0]["raw"], "exact"), 1280, a)
            advice = ntcp.wait(ADVICE, line, 5)
            assert int(advice.group(3)) == 1280 and int(advice.group(2)) == 1500, advice.group(0)
            line = ntcp.mark()
            refused_udp = udp(big, 15, 1.0)
            assert refused_udp["reply"] is None, refused_udp
            refused = ntcp.wait(REFUSED, line, 5)
            assert (int(refused.group(1)), int(refused.group(3))) == (big, allowed), refused.group(0)
            evidence.update(rejected=rejected, unchanged_udp=after, unchanged_tcp=stream_after, stream=stream,
                            positive_control=dict(forged_hex=control[:96].hex(), advice=advice.group(0),
                                                  refusal=refused.group(0)))
        kernel_after = counters(family)
        generated = len(ptbs(capture.since(0))) if scenario != "forged" else 0
        if scenario in ("adjunct-silence", "route-isolation"):
            # Silence: the drop rule precedes forwarding; route-isolation's
            # fragments (at most the 1024-octet connectionless size) fit the
            # 1280 egress. Neither draws a PTB.
            assert kernel_after - kernel_before == generated == 0, (kernel_before, kernel_after, generated)
        elif scenario != "forged":
            assert kernel_after - kernel_before == generated >= 1, (kernel_before, kernel_after, generated)
        evidence.update(settings=settings, kernel_ptb_counter=dict(before=kernel_before, after=kernel_after),
                        router_generated_ptbs=generated, ntcp_stderr=ntcp.since(0)[-12:] if ntcp else None)
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (ntcp and ntcp.close, stager and stager.close, driver and driver.close, peer.close,
                      capture and capture.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors:
            emit("T9_ICMP_CLEANUP", dict(case=case, errors=errors))
            if not primary:
                raise RuntimeError(errors)
    return evidence
