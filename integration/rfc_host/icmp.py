# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Isolated ICMP scenario: ntcp <-> TUN(1500) <-> Linux router <-> veth <-> Linux peer.

The router namespace is the guarded harness namespace; the peer gets its own
network namespace inside the same harness-owned user namespace. Requests use a
1500-octet veth into the router. Replies leave the router on a separate veth
whose MTU is 1280 (a veth drops frames larger than its receiving end's MTU, so
one veth cannot carry 1500-octet requests in and limit replies to 1280). The
router kernel therefore generates every real Packet Too Big in these cases;
the harness only forges messages in the forged control.
"""
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
SCENARIOS = ("udp-quoted", "tcp-quoted", "forged", "shared-fanout")
# tun_echo's consumed per-flow UdpEvent::PacketTooBig: remote, dropped size, MTU.
ADVICE = r"UDP echo reply to (\S+) \((\d+) octets\) dropped by the path \(next-hop MTU (?:Some\()?(\d+)"
# The echo's local refusal of an oversize reply: by its path query before
# encoding, on a change notification while held, or by the send's own check.
# The echo's report of a shared path change it read without sending.
CHANGED = r"UDP echo path to (\S+) changed: MMS_S (\d+), payload limit (\d+)"
REFUSED = r"UDP echo of (\d+) octets to (\S+) refused(?: at send)?: exceeds the (?:changed )?path payload limit of (\d+)"


def cases():
    return [dict(kind="icmp", family=family, scenario=scenario) for family in (4, 6) for scenario in SCENARIOS]


def header_len(family):
    return 20 if family == 4 else 40


def large_udp(family):
    return 1500 - header_len(family) - 8


def allowed_udp(family):
    return 1280 - header_len(family) - 8


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


def parse(packet):
    """Decode one raw IP packet; every checksum must be valid unless reported."""
    version = packet[0] >> 4
    if version == 4:
        hl = (packet[0] & 15) * 4
        total = u16(packet, 2)
        protocol = packet[9]
        source, destination = packet[12:16], packet[16:20]
        fragment = u16(packet, 6)
        info = dict(family=4, df=bool(fragment & 0x4000), fragmented=bool(fragment & 0x3fff),
                    ip_checksum_valid=checksum(packet[:hl]) == 0)
        pseudo = source + destination + bytes([0, protocol]) + struct.pack("!H", total - hl)
    elif version == 6:
        hl, total, protocol = 40, 40 + u16(packet, 4), packet[6]
        source, destination = packet[8:24], packet[24:40]
        info = dict(family=6, df=None, fragmented=protocol == 44, ip_checksum_valid=True)
        pseudo = source + destination + struct.pack("!I", total - hl) + bytes([0, 0, 0, protocol])
    else:
        return None
    body = packet[hl:total]
    info.update(length=total, captured=len(packet), protocol=protocol, header_len=hl,
                source=str(ipaddress.ip_address(source)), destination=str(ipaddress.ip_address(destination)))
    if protocol == 6 and len(body) >= 20:
        offset = (body[12] >> 4) * 4
        sport, dport, seq, ack = struct.unpack_from("!HHII", body)
        info.update(sport=sport, dport=dport, seq=seq, ack=ack, flags=body[13], payload=len(body) - offset,
                    checksum_valid=checksum(pseudo + body) == 0)
    elif protocol == 17 and len(body) >= 8:
        sport, dport, length, value = struct.unpack_from("!HHHH", body)
        info.update(sport=sport, dport=dport, udp_length=length, udp_checksum=value, payload=length - 8,
                    checksum_valid=(value == 0 and version == 4) or checksum(pseudo + body) == 0)
    elif (protocol, version) in ((1, 4), (58, 6)) and len(body) >= 8:
        valid = checksum(body if version == 4 else pseudo + body) == 0
        info.update(icmp_type=body[0], icmp_code=body[1], checksum_valid=valid)
        if (version, body[0], body[1]) == (4, 3, 4):
            info.update(ptb=True, mtu=u16(body, 6), quote=body[8:])
        elif (version, body[0]) == (6, 2):
            info.update(ptb=True, mtu=struct.unpack_from("!I", body, 4)[0], quote=body[8:])
    return info


def quotes(quote, original):
    """The quote is a prefix of the original except the forwarding-mutated TTL/hop limit and IPv4 header checksum."""
    mutable = {8, 10, 11} if original[0] >> 4 == 4 else {7}
    return 28 <= len(quote) <= len(original) and all(
        quote[i] == original[i] for i in range(len(quote)) if i not in mutable)


def public(event):
    return {k: v for k, v in event.items() if k not in ("raw", "quote")}


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

    def __init__(self, binary, local):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NTCP_") and k != "LD_PRELOAD"}
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


def child(case, proof, binary, Peer, command, emit):
    family, scenario = case["family"], case["scenario"]
    a = ADDRESSES[family]
    egress_mtu = 1500 if scenario == "forged" else 1280
    big, allowed = large_udp(family), allowed_udp(family)
    small_mss = 1280 - header_len(family) - 20
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", a["peer"], a["ntcp"], PORT])
    ntcp = capture = None
    evidence = dict(case=case)
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = setup(family, egress_mtu, command, peer.p.pid)
        assert settings["peer_namespace"] == peer.ready["namespace"]
        capture = Capture(TUN)
        ntcp = Ntcp(binary, a["ntcp"])
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
                assert e["checksum_valid"] and e["ip_checksum_valid"] and not e["fragmented"], public(e)
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

        if scenario == "shared-fanout":
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
        if scenario != "forged":
            assert kernel_after - kernel_before == generated >= 1, (kernel_before, kernel_after, generated)
        evidence.update(settings=settings, kernel_ptb_counter=dict(before=kernel_before, after=kernel_after),
                        router_generated_ptbs=generated, ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (ntcp and ntcp.close, peer.close, capture and capture.close):
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
