# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Scoped link-local namespace cases (T18).

two-link: one native runtime (this harness's binary in its `scoped` mode:
one Host and Endpoint configured by the production configuration parser
from `io.*` and `port.b.*` keys without a next-hop MAC, so both AF_PACKET
ports resolve their next hops by Neighbor Discovery) owns two veth
interfaces of the harness namespace. Their opposite ends belong to one Linux
peer namespace. Both links carry the same link-local address pair (native
fe80::2, Linux fe80::1); link A's first-hop MTU is 1500 and link B's 1400.
No neighbor is configured anywhere and the kernel owns no native address.
Each interface is captured separately in the harness namespace, where the
native runtime and the kernel joins it requests send: the native runtime's
Duplicate Address Detection, its own and the Linux kernel's address
resolution, the kernel's MLD reports. Complete TCP streams run in both
directions, with one identical address and port pair established on both
links at once. Then a peer-side filter drops link A's packets above 1280
octets beyond the first hop, and the harness injects a checksummed ICMPv6
Packet Too Big from the link-local peer quoting a captured native packet
that filter dropped: two directly connected link-local peers have no router
that could send one (RFC 4007 section 9 forbids forwarding link-local
traffic), so this PTB is the harness's, labelled as injected. It lowers
only link A's path MTU; link B keeps its 1400-octet packets and both
first-hop MTUs stay as configured.

tun_echo: the unmodified tun_echo example on a TUN whose kernel side has the
link-local address fe80::1 (the scoped peer); tun_echo serves fe80::2 and
actively opens to [fe80::1%TUN]:18083. The kernel peer completes TCP echoes
in both directions and a UDP echo, every socket scoped to the TUN.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import sys
import threading
import time

import icmp
from bridge import checksum
from linux_peer import fnv, pattern

HERE = Path(__file__).resolve().parent
NATIVE, PEER = "fe80::2", "fe80::1"
LINKS = (dict(name="A", native="t18na", peer="t18pa", mtu=1500, native_mac="02:00:00:18:0a:02",
              peer_mac="02:00:00:18:0a:01"),
         dict(name="B", native="t18nb", peer="t18pb", mtu=1400, native_mac="02:00:00:18:0b:02",
              peer_mac="02:00:00:18:0b:01"))
# The injected report's next-hop MTU: below link B's MTU, so B's packets
# stay larger than everything link A may send after it.
PTB_MTU = 1280
DROP_TABLE = "t18constriction"
TUN = "t18tun"
TUN_PORT, TUN_PEER_PORT = 18080, 18083
SCENARIOS = (("native", "two-link"), ("tun_echo", "link-local-peer"))


def cases():
    return [dict(kind="scoped", family=6, embedding=e, scenario=s) for e, s in SCENARIOS]


def config():
    """The native runtime's configuration: the `io.*` port on link A and
    `port.b` on link B, the same link-local address on both, each port
    resolving its own next hops (no next_hop_mac)."""
    a, b = LINKS
    return (f"io.backend=af-packet\nio.interface={a['native']}\nio.address={NATIVE}\nio.prefix=64\nio.source_quiet=never\n"
            f"port.b.interface={b['native']}\nport.b.address={NATIVE}\nport.b.prefix=64\nport.b.source_quiet=never\n")


def solicited_node(address):
    return str(ipaddress.ip_address(bytes.fromhex("ff02" + "00" * 9 + "01ff") + ipaddress.ip_address(address).packed[13:]))


def mac(octets):
    return ":".join(f"{b:02x}" for b in octets)


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


def frame(raw):
    """Decode one Ethernet frame: the IPv6 header, extension headers before
    the transport, ND (NS/NA with flags, target and options), MLDv2 report
    records, Packet Too Big and TCP. None for anything else."""
    if len(raw) < 54 or u16(raw, 12) != 0x86dd or raw[14] >> 4 != 6:
        return None
    ip = raw[14:]
    total = 40 + u16(ip, 4)
    protocol, offset, extensions = ip[6], 40, []
    while protocol in (0, 43, 60) and offset + 8 <= total:
        extensions.append(protocol)
        protocol, offset = ip[offset], offset + (ip[offset + 1] + 1) * 8
    source, destination = ip[8:24], ip[24:40]
    body = ip[offset:total]
    event = dict(eth_dst=mac(raw[:6]), eth_src=mac(raw[6:12]), ip_length=total, captured=len(ip),
                 hop_limit=ip[7], source=str(ipaddress.ip_address(source)),
                 destination=str(ipaddress.ip_address(destination)), protocol=protocol, extensions=extensions)
    pseudo = source + destination + struct.pack("!I", len(body)) + bytes([0, 0, 0, protocol])
    if protocol == 58 and len(body) >= 8:
        event.update(icmp_type=body[0], icmp_code=body[1], checksum_valid=checksum(pseudo + body) == 0)
        if body[0] in (135, 136) and len(body) >= 24:
            options, at = [], 24
            while at + 2 <= len(body) and body[at + 1]:
                kind, length = body[at], body[at + 1] * 8
                value = body[at + 2:at + length]
                options.append(dict(type=kind, length=length, value=mac(value) if kind in (1, 2) and length == 8
                                    else value.hex()))
                at += length
            event.update(target=str(ipaddress.ip_address(body[8:24])), options=options,
                         router=bool(body[4] & 0x80), solicited=bool(body[4] & 0x40), override=bool(body[4] & 0x20))
        elif body[0] == 143:
            records, at = [], 8
            for _ in range(u16(body, 6)):
                if at + 20 > len(body):
                    break
                records.append(dict(type=body[at], group=str(ipaddress.ip_address(body[at + 4:at + 20]))))
                at += 20 + body[at + 1] * 4 + u16(body, at + 2) * 16
            event.update(records=records)
        elif body[0] == 2:
            event.update(mtu=struct.unpack_from("!I", body, 4)[0], quote=body[8:])
    elif protocol == 6 and len(body) >= 20:
        sport, dport, seq, ack = struct.unpack_from("!HHII", body)
        event.update(sport=sport, dport=dport, seq=seq, ack=ack, flags=body[13],
                     payload=len(body) - (body[12] >> 4) * 4, checksum_valid=checksum(pseudo + body) == 0)
    return event


def packet_too_big(quoted, mtu, source, destination, eth_source, eth_destination):
    """An Ethernet frame carrying an ICMPv6 Packet Too Big (RFC 4443 3.2)
    from SOURCE to DESTINATION quoting as much of the IPv6 packet QUOTED as
    fits the IPv6 minimum MTU, with its checksum."""
    quote = quoted[:1280 - 48]
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    body = bytearray(struct.pack("!BBHI", 2, 0, 0, mtu) + quote)
    struct.pack_into("!H", body, 2, checksum(src + dst + struct.pack("!I", len(body)) + bytes([0, 0, 0, 58]) + bytes(body)))
    header = struct.pack("!IHBB", 6 << 28, len(body), 58, 64) + src + dst
    return (bytes.fromhex(eth_destination.replace(":", "")) + bytes.fromhex(eth_source.replace(":", ""))
            + b"\x86\xdd" + header + bytes(body))


def public(event):
    return {k: v for k, v in event.items() if k not in ("raw", "quote")}


class Capture:
    """Both directions of one interface of the harness namespace, Ethernet
    headers included. PACKET_OUTGOING frames ("out") were sent from this
    namespace (the native runtime, or its kernel's MLD); every other frame
    ("in") arrived from the peer end."""

    def __init__(self, interface):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.socket.bind((interface, 0))
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
                event.update(direction="out" if address[2] == socket.PACKET_OUTGOING else "in",
                             time_ns=time.monotonic_ns(), raw=raw)
                with self.lock:
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


def nd(events, kind, **match):
    """The ND messages (135 NS, 136 NA) matching every field in MATCH."""
    return [e for e in events if e.get("icmp_type") == kind and all(e.get(k) == v for k, v in match.items())]


def checked_nd(message):
    """RFC 4861's fixed checks on a captured ND message."""
    assert message["checksum_valid"] and message["hop_limit"] == 255 and message["icmp_code"] == 0, public(message)
    assert not message["extensions"], ("ND without extension headers", public(message))
    return dict(direction=message["direction"], source=message["source"], destination=message["destination"],
                eth_src=message["eth_src"], eth_dst=message["eth_dst"], target=message["target"],
                options=message["options"], solicited=message["solicited"], override=message["override"],
                router=message["router"], time_ns=message["time_ns"])


def lladdr(message, kind):
    """The link-layer address option KIND (1 source, 2 target), or None."""
    values = [o["value"] for o in message["options"] if o["type"] == kind]
    assert len(values) <= 1, message["options"]
    return values[0] if values else None


def tcp_flow(events, local_port, remote_port):
    """The TCP segments of one connection (native port LOCAL_PORT) by direction."""
    out = [e for e in events if e.get("protocol") == 6 and e["direction"] == "out"
           and (e["sport"], e["dport"]) == (local_port, remote_port)]
    back = [e for e in events if e.get("protocol") == 6 and e["direction"] == "in"
            and (e["sport"], e["dport"]) == (remote_port, local_port)]
    return out, back


def lengths(segments):
    """IP packet lengths of the data-bearing segments."""
    return [e["ip_length"] for e in segments if e["payload"]]


def scoped_name(name, address, port, index):
    """A Rust-formatted scoped socket address the driver reports."""
    return name == f"[{address}%{index}]:{port}"


def setup(command, peer_pid):
    """Two veth pairs from the harness namespace to the peer namespace."""
    peer = lambda *args: command(["nsenter", "-t", str(peer_pid), "-n", *args])
    for run in (lambda *x: command(list(x)), peer):
        # No kernel-generated link-local address on any interface created
        # below: the native address belongs to the native runtime alone, the
        # peer's is configured explicitly.
        run("sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/default/addr_gen_mode")
    command(["ip", "link", "set", "lo", "up"])
    peer("ip", "link", "set", "lo", "up")
    for link in LINKS:
        command(["ip", "link", "add", link["native"], "type", "veth", "peer", "name", link["peer"],
                 "netns", str(peer_pid)])
        command(["ip", "link", "set", link["native"], "address", link["native_mac"], "mtu", str(link["mtu"])])
        peer("ip", "link", "set", link["peer"], "address", link["peer_mac"], "mtu", str(link["mtu"]))
        # Complete wire checksums and no aggregates at either end.
        offload = ["tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"]
        command(["ethtool", "-K", link["native"], *offload])
        peer("ethtool", "-K", link["peer"], *offload)
        peer("ip", "addr", "add", PEER + "/64", "dev", link["peer"], "nodad")
        command(["ip", "link", "set", link["native"], "up"])
        peer("ip", "link", "set", link["peer"], "up")
    native_links = {l["ifname"]: l for l in json.loads(command(["ip", "-j", "addr", "show"]))}
    peer_links = {l["ifname"]: l for l in json.loads(peer("ip", "-j", "addr", "show"))}
    interfaces = []
    for link in LINKS:
        n, p = native_links[link["native"]], peer_links[link["peer"]]
        assert not n.get("addr_info"), ("kernel address on a native-owned port", n)
        assert [(a["local"], a["prefixlen"]) for a in p["addr_info"]] == [(PEER, 64)], p
        assert (n["mtu"], p["mtu"]) == (link["mtu"], link["mtu"]), (n, p)
        assert (n["address"], p["address"]) == (link["native_mac"], link["peer_mac"]), (n, p)
        interfaces.append(dict(link=link["name"], native=dict(name=n["ifname"], index=n["ifindex"], mac=n["address"],
                                                               mtu=n["mtu"]),
                               peer=dict(name=p["ifname"], index=p["ifindex"], mac=p["address"], mtu=p["mtu"],
                                         address=PEER)))
    assert not any(a["local"] == NATIVE for l in native_links.values() for a in l.get("addr_info", [])), \
        "native address assigned to the kernel"
    return interfaces


def neighbors(command, peer_pid=None, permanent=False):
    args = ["ip", "-j", "-6", "neigh", "show"] + (["nud", "permanent"] if permanent else [])
    prefix = ["nsenter", "-t", str(peer_pid), "-n"] if peer_pid else []
    return json.loads(command(prefix + args) or "[]")


def group_joins(interfaces):
    """The kernel's IPv6 multicast memberships (/proc/net/igmp6) per
    interface of the harness namespace."""
    joins = {}
    for line in Path("/proc/net/igmp6").read_text().splitlines():
        fields = line.split()
        if fields[1] in interfaces:
            joins.setdefault(fields[1], []).append(str(ipaddress.ip_address(bytes.fromhex(fields[2]))))
    return joins


def drop_rule(command, peer_pid):
    """The emulated downstream constriction: the peer kernel drops native
    packets above PTB_MTU arriving on link A (counted)."""
    nft = lambda *args: command(["nsenter", "-t", str(peer_pid), "-n", "nft", *args])
    nft("add", "table", "inet", DROP_TABLE)
    nft("add", "chain", "inet", DROP_TABLE, "pre", "{ type filter hook prerouting priority -300; }")
    nft("add", "rule", "inet", DROP_TABLE, "pre", "iifname", LINKS[0]["peer"], "ip6", "saddr", NATIVE,
        "ip6", "length", "gt", str(PTB_MTU - 40), "counter", "drop")


def dropped(command, peer_pid):
    ruleset = json.loads(command(["nsenter", "-t", str(peer_pid), "-n", "nft", "-j", "list", "table", "inet",
                                  DROP_TABLE]))["nftables"]
    return sum(e["counter"]["packets"] for item in ruleset if "rule" in item for e in item["rule"]["expr"]
               if "counter" in e)


def two_link(case, proof, binary, Peer, command):
    evidence = dict(case=case)
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "scoped_peer.py", PEER,
                 *(l["peer"] for l in LINKS)])
    driver = None
    captures = []

    def call(process, line, event):
        process.send(line)
        result = process.read()
        assert result["event"] == event, result
        return result

    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        interfaces = setup(command, peer.p.pid)
        index = [i["native"]["index"] for i in interfaces]
        peer_index = [i["peer"]["index"] for i in interfaces]
        assert not neighbors(command, permanent=True) and not neighbors(command, peer.p.pid, permanent=True), \
            "no permanent IPv6 neighbor in this case"
        captures = [Capture(l["native"]) for l in LINKS]
        started = time.monotonic_ns()
        driver = Peer([binary, "scoped", config()])
        assert [(l["name"], l["index"]) for l in driver.ready["links"]] == [(l["native"], i) for l, i in
                                                                             zip(LINKS, index)], driver.ready
        evidence.update(interfaces=interfaces, namespaces=dict(native=proof["net"]["current"],
                                                                peer=peer.ready["namespace"]),
                        configuration=config().splitlines(), driver=driver.ready)

        # Duplicate Address Detection (RFC 4862 5.4): the first bind is
        # refused while the address is tentative and succeeds once DAD ends.
        listening = call(driver, "listen 18081", "listening")
        assigned = time.monotonic_ns()
        assert listening["sockets"][0]["bind_attempts"] > 1, ("tentative address refused first", listening)
        for s, i in zip(listening["sockets"], index):
            assert s["index"] == i and scoped_name(s["local"], NATIVE, 18081, i), listening
        dad = []
        for link, capture in zip(LINKS, captures):
            events = capture.since(0)
            probes = nd(events, 135, direction="out", source="::", target=NATIVE)
            assert len(probes) == 1, ("one DAD probe (DupAddrDetectTransmits 1)", [public(p) for p in probes])
            probe = checked_nd(probes[0])
            assert probe["destination"] == solicited_node(NATIVE) and probe["eth_dst"] == "33:33:ff:00:00:02", probe
            assert probe["eth_src"] == link["native_mac"] and not probe["options"], probe
            # Assigned no earlier than one RetransTimer after the probe;
            # nothing else left the native runtime before that.
            waited = (assigned - probe["time_ns"]) / 1e6
            assert waited >= 900, ("RetransTimer after the final DAD probe", waited)
            early = [e for e in events if e["direction"] == "out" and e["time_ns"] < probe["time_ns"] + 900_000_000
                     and e.get("icmp_type") not in (135, 143)]
            assert not early, [public(e) for e in early]
            assert not nd(events, 136, target=NATIVE), "no defending advertisement"
            reports = [e for e in events if e.get("icmp_type") == 143 and e["direction"] == "out"]
            groups = {r["group"] for e in reports for r in e["records"]}
            assert solicited_node(NATIVE) in groups and all(e["checksum_valid"] for e in reports), \
                [public(e) for e in reports]
            dad.append(dict(link=link["name"], probe=probe, assigned_after_probe_ms=round(waited, 1),
                            mld_reports=[dict(source=e["source"], destination=e["destination"], hop_limit=e["hop_limit"],
                                              extensions=e["extensions"], records=e["records"], time_ns=e["time_ns"])
                                         for e in reports]))
        # The kernel joins the runtime requested, per interface, apart from
        # the AF_PACKET reception shown by the answers below.
        joins = group_joins([l["native"] for l in LINKS])
        for link in LINKS:
            assert {"ff02::1", solicited_node(NATIVE)} <= set(joins.get(link["native"], [])), joins
        evidence.update(dad=dad, kernel_group_joins=joins, listening=listening,
                        dad_wait_ms=round((assigned - started) / 1e6, 1))

        def streams(name, marks, native_port, peer_port, results, mtus):
            """Per-link packet lengths of one connection per link."""
            per_link = []
            for link, capture, mark, mtu in zip(LINKS, captures, marks, mtus):
                out, back = tcp_flow(capture.since(mark), native_port, peer_port)
                assert out and back and all(e["checksum_valid"] for e in out + back), name
                sent, received = lengths(out), lengths(back)
                assert sent and received, (name, link["name"])
                assert max(sent) == mtu and max(received) == min(mtu, link["mtu"]), (name, link["name"], sent, received)
                per_link.append(dict(link=link["name"], native_lengths=sorted(set(sent)),
                                     peer_lengths=sorted(set(received)), native_packets=len(out),
                                     peer_packets=len(back), native_max=max(sent), peer_max=max(received)))
            return per_link

        def identical(connections, local, lport, remote, rport, key):
            """One identical address and port pair on every link, each named
            with its own link's scope."""
            for c, i in zip(connections, index):
                assert scoped_name(c[key]["local"], local, lport, i), c
                assert scoped_name(c[key]["peer"], remote, rport, i), c

        def linux_names(connections, key, lport, rport):
            for c, i in zip(connections, peer_index):
                assert c[key]["local"] == dict(address=PEER, port=lport, scope_id=i), c
                assert c[key]["peer"] == dict(address=NATIVE, port=rport, scope_id=i), c

        # Native clients first: the native runtime resolves fe80::1 on each
        # link (multicast NS with its SLLAO; the kernel's solicited NA).
        call(peer, "listen 18080", "listening")
        marks = [c.mark() for c in captures]
        peer.send("serve 16384 16384 41 42")
        paired = call(driver, "pair 40000 fe80::1 18080 16384 16384 41 42", "paired")
        served = peer.read()
        assert served["event"] == "served", served
        identical(paired["connections"], NATIVE, 40000, PEER, 18080, "established")
        linux_names(served["connections"], "accepted", 18080, 40000)
        for c, s, salt in zip(paired["connections"], served["connections"], (41, 42)):
            assert c["response_hash"] == fnv(pattern(16384, salt + 100)) and s["request_hash"] == fnv(pattern(16384, salt))
        native_open = streams("native-client", marks, 40000, 18080, paired, [l["mtu"] for l in LINKS])
        resolution = []
        for link, capture, mark in zip(LINKS, captures, marks):
            events = capture.since(mark)
            solicitations = [checked_nd(m) for m in nd(events, 135, direction="out", source=NATIVE, target=PEER)]
            assert solicitations and solicitations[0]["destination"] == solicited_node(PEER), solicitations
            assert all(lladdr(s, 1) == link["native_mac"] for s in solicitations), solicitations
            answers = [checked_nd(m) for m in nd(events, 136, direction="in", target=PEER)]
            assert answers and answers[0]["solicited"] and answers[0]["destination"] == NATIVE, answers
            assert lladdr(answers[0], 2) == link["peer_mac"] and answers[0]["eth_dst"] == link["native_mac"], answers
            out, _ = tcp_flow(events, 40000, 18080)
            # The native runtime's learned mapping: every segment to the
            # identical peer address goes to this link's peer MAC.
            assert {e["eth_dst"] for e in out} == {link["peer_mac"]}, {e["eth_dst"] for e in out}
            assert out[0]["time_ns"] > answers[0]["time_ns"], "the first SYN waited for resolution"
            resolution.append(dict(link=link["name"], native_solicitations=solicitations, peer_advertisements=answers,
                                   learned_mac=link["peer_mac"]))
        peer_learned = neighbors(command, peer.p.pid)
        for link in LINKS:
            entry = [n for n in peer_learned if n["dst"] == NATIVE and n["dev"] == link["peer"]]
            assert len(entry) == 1 and entry[0]["lladdr"] == link["native_mac"], peer_learned

        # Linux clients: the kernel's entries go, so it resolves fe80::2 on
        # each link by multicast NS; the runtime's AF_PACKET port receives it
        # and answers.
        for link in LINKS:
            command(["nsenter", "-t", str(peer.p.pid), "-n", "ip", "-6", "neigh", "flush", "dev", link["peer"]])
        flushed = [n for n in neighbors(command, peer.p.pid) if n["dst"] == NATIVE and n.get("lladdr")
                   and "FAILED" not in n.get("state", [])]
        assert not flushed, flushed
        marks = [c.mark() for c in captures]
        driver.send("serve 16384 16384 51 52")
        linux_pair = call(peer, "pair 40001 fe80::2 18081 16384 16384 51 52", "paired")
        native_served = driver.read()
        assert native_served["event"] == "served", native_served
        identical(native_served["connections"], NATIVE, 18081, PEER, 40001, "accepted")
        linux_names(linux_pair["connections"], "established", 40001, 18081)
        for c, s, salt in zip(linux_pair["connections"], native_served["connections"], (51, 52)):
            assert c["response_hash"] == fnv(pattern(16384, salt + 100)) and s["request_hash"] == fnv(pattern(16384, salt))
        linux_open = streams("linux-client", marks, 18081, 40001, native_served, [l["mtu"] for l in LINKS])
        for link, capture, mark, item in zip(LINKS, captures, marks, resolution):
            events = capture.since(mark)
            solicitations = [checked_nd(m) for m in nd(events, 135, direction="in", source=PEER, target=NATIVE,
                                                       destination=solicited_node(NATIVE))]
            assert solicitations and lladdr(solicitations[0], 1) == link["peer_mac"], solicitations
            assert solicitations[0]["eth_dst"] == "33:33:ff:00:00:02", solicitations
            answers = [checked_nd(m) for m in nd(events, 136, direction="out", source=NATIVE, target=NATIVE)]
            assert answers and answers[0]["solicited"] and answers[0]["override"], answers
            assert answers[0]["destination"] == PEER and answers[0]["eth_dst"] == link["peer_mac"], answers
            assert lladdr(answers[0], 2) == link["native_mac"] and answers[0]["time_ns"] > solicitations[0]["time_ns"]
            item.update(peer_solicitations=solicitations, native_advertisements=answers,
                        multicast_reception="the AF_PACKET port received the solicited-node NS and answered it")
        peer_relearned = neighbors(command, peer.p.pid)
        for link in LINKS:
            entry = [n for n in peer_relearned if n["dst"] == NATIVE and n["dev"] == link["peer"]]
            assert len(entry) == 1 and entry[0]["lladdr"] == link["native_mac"], peer_relearned
        evidence.update(native_client=dict(native=paired, linux=served, per_link=native_open),
                        linux_client=dict(native=native_served, linux=linux_pair, per_link=linux_open),
                        resolution=resolution, peer_neighbors=dict(after_native_client=peer_learned,
                                                                    after_linux_client=peer_relearned))

        # The injected Packet Too Big on link A.
        drop_rule(command, peer.p.pid)
        marks = [c.mark() for c in captures]
        peer.send("serve 32768 8192 61 62")
        driver.send("pair 40002 fe80::1 18080 32768 8192 61 62")
        deadline = time.monotonic() + 20
        quoted = None
        while quoted is None:
            assert time.monotonic() < deadline, "no oversized native packet on link A"
            out, _ = tcp_flow(captures[0].since(marks[0]), 40002, 18080)
            quoted = next((e for e in out if e["payload"] and e["ip_length"] > PTB_MTU), None)
            time.sleep(0.01)
        a = LINKS[0]
        report = packet_too_big(quoted["raw"][14:14 + quoted["ip_length"]], PTB_MTU, PEER, NATIVE, a["peer_mac"],
                                a["native_mac"])
        # A separate process in the peer namespace: the peer is serving.
        injected = json.loads(command(["nsenter", "-t", str(peer.p.pid), "-n", sys.executable, "-B",
                                       HERE / "scoped_peer.py", "inject", a["peer"], report.hex()]))
        assert injected["event"] == "injected" and injected["namespace"] == peer.ready["namespace"], injected
        ptb_paired = driver.read()
        assert ptb_paired["event"] == "paired", ptb_paired
        ptb_served = peer.read()
        assert ptb_served["event"] == "served", ptb_served
        identical(ptb_paired["connections"], NATIVE, 40002, PEER, 18080, "established")
        for c, s, salt in zip(ptb_paired["connections"], ptb_served["connections"], (61, 62)):
            assert c["response_hash"] == fnv(pattern(8192, salt + 100)) and s["request_hash"] == fnv(pattern(32768, salt))
        drops = dropped(command, peer.p.pid)
        assert drops >= 1, "the quoted packet was dropped beyond the first hop"
        events_a = captures[0].since(marks[0])
        arrival = [e for e in events_a if e["direction"] == "in" and e.get("icmp_type") == 2]
        assert len(arrival) == 1 and arrival[0]["raw"] == report and arrival[0]["checksum_valid"], \
            [public(e) for e in arrival]
        assert arrival[0]["mtu"] == PTB_MTU and arrival[0]["quote"] == quoted["raw"][14:14 + 1232], "complete quote"
        # Capture order on link A: before and after the report's arrival.
        boundary = next(i for i, e in enumerate(events_a) if e is arrival[0])
        before, _ = tcp_flow(events_a[:boundary], 40002, 18080)
        after, _ = tcp_flow(events_a[boundary + 1:], 40002, 18080)
        before, after = lengths(before), lengths(after)
        assert before and max(before) == a["mtu"], before
        assert after and max(after) == PTB_MTU, ("link A repaired at the reported MTU", after)
        out_b, _ = tcp_flow(captures[1].since(marks[1]), 40002, 18080)
        sizes_b = lengths(out_b)
        assert sizes_b and max(sizes_b) == LINKS[1]["mtu"] > PTB_MTU, sizes_b
        connection_a, connection_b = ptb_paired["connections"]
        assert connection_a["established"]["path_mtu"] == a["mtu"], connection_a
        assert connection_a["done"]["path_mtu"] == PTB_MTU, ("link A's learned PMTU", connection_a)
        assert connection_b["established"]["path_mtu"] == connection_b["done"]["path_mtu"] == LINKS[1]["mtu"], \
            connection_b
        assert not [e for e in captures[1].since(marks[1]) if e.get("icmp_type") == 2], "no report on link B"

        # A later connection on each link: link A starts at the learned PMTU,
        # link B at its own first-hop MTU.
        marks = [c.mark() for c in captures]
        peer.send("serve 16384 8192 71 72")
        later = call(driver, "pair 40003 fe80::1 18080 16384 8192 71 72", "paired")
        later_served = peer.read()
        assert later_served["event"] == "served", later_served
        for c, s, salt in zip(later["connections"], later_served["connections"], (71, 72)):
            assert c["response_hash"] == fnv(pattern(8192, salt + 100)) and s["request_hash"] == fnv(pattern(16384, salt))
        later_a = lengths(tcp_flow(captures[0].since(marks[0]), 40003, 18080)[0])
        later_b = lengths(tcp_flow(captures[1].since(marks[1]), 40003, 18080)[0])
        # Its send MSS follows link A's learned PMTU (the connection's own
        # IPV6_MTU estimate is recorded as reported), link B's its MTU.
        later_mss = [c["established"]["snd_mss"] for c in later["connections"]]
        assert later_a and max(later_a) == PTB_MTU and later_mss[0] == PTB_MTU - 60, (later_a, later["connections"])
        assert later_b and max(later_b) == LINKS[1]["mtu"] and later_mss[1] == LINKS[1]["mtu"] - 60, later_b
        assert dropped(command, peer.p.pid) == drops, "nothing above the reported MTU after the report"
        # Both first-hop MTUs are unchanged.
        mtus = {l["ifname"]: l["mtu"] for l in json.loads(command(["ip", "-j", "link", "show"]))
                + json.loads(command(["nsenter", "-t", str(peer.p.pid), "-n", "ip", "-j", "link", "show"]))}
        for link in LINKS:
            assert mtus[link["native"]] == mtus[link["peer"]] == link["mtu"], mtus
        ptb = dict(origin="harness-injected", reason="two directly connected link-local peers have no router to send "
                   "a Packet Too Big; kernel PTBs are the routed topology's", link="A", interface=a["peer"],
                   source=PEER, destination=NATIVE, mtu=PTB_MTU, frame_sha256=injected["sha256"],
                   ptb_hex=report[:14 + 48 + 64].hex(), quoted=dict(public(quoted), raw_hex=quoted["raw"][:96].hex()),
                   constriction=dict(table=DROP_TABLE, dropped=drops, above=PTB_MTU), link_a_before=sorted(set(before)),
                   link_a_after=sorted(set(after)), link_b=sorted(set(sizes_b)), connections=ptb_paired,
                   peer=ptb_served, later=dict(native=later, linux=later_served, link_a=sorted(set(later_a)),
                                               link_b=sorted(set(later_b))),
                   first_hop_mtus={link["name"]: mtus[link["native"]] for link in LINKS})
        evidence.update(ptb=ptb, native_addresses_in_kernel=False,
                        native_kernel_addresses=[a for l in json.loads(command(["ip", "-j", "addr", "show"]))
                                                 for a in l.get("addr_info", []) if l["ifname"] in
                                                 [x["native"] for x in LINKS]])
        assert not evidence["native_kernel_addresses"], evidence["native_kernel_addresses"]
        assert not neighbors(command, permanent=True) and not neighbors(command, peer.p.pid, permanent=True)
        for link, capture in zip(LINKS, captures):
            events = capture.since(0)
            # Every native frame left through its own link's interface.
            assert all(e["eth_src"] == link["native_mac"] for e in events if e["direction"] == "out"), link
        evidence.update(frames={l["name"]: len(c.since(0)) for l, c in zip(LINKS, captures)})
    finally:
        primary = sys.exc_info()[0] is not None
        if primary:
            for link, capture in zip(LINKS, captures):
                trace = [public(e) for e in capture.events[:80]]
                print(json.dumps(dict(case=case, link=link["name"], trace=trace), default=str), file=sys.stderr)
        errors = []
        for close in [driver and driver.close, peer.close] + [c.close for c in captures]:
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors:
            evidence.update(cleanup_errors=errors)
            print(json.dumps(dict(case=case, cleanup_errors=errors)), file=sys.stderr)
            if not primary:
                raise RuntimeError(errors)
    return evidence


class TunEcho(icmp.Ntcp):
    """The unmodified tun_echo example on this case's TUN."""

    @staticmethod
    def command(binary, local, peer=None):
        return [str(binary), TUN, local, str(TUN_PORT)] + ([peer] if peer else [])


def tun_echo(case, proof, binary, Peer, command):
    evidence = dict(case=case)
    command(["sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/default/addr_gen_mode"])
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "tuntap", "add", "dev", TUN, "mode", "tun"])
    command(["ip", "link", "set", TUN, "mtu", "1500"])
    command(["ethtool", "-K", TUN, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"])
    command(["ip", "addr", "add", PEER + "/64", "dev", TUN, "nodad"])
    command(["ip", "link", "set", TUN, "up"])
    link = next(l for l in json.loads(command(["ip", "-j", "addr", "show"])) if l["ifname"] == TUN)
    index = link["ifindex"]
    assert [(a["local"], a["prefixlen"]) for a in link["addr_info"]] == [(PEER, 64)], link
    assert not any(a["local"] == NATIVE for l in json.loads(command(["ip", "-j", "addr", "show"]))
                   for a in l.get("addr_info", [])), "tun_echo address assigned to the kernel"
    route = json.loads(command(["ip", "-j", "-6", "route", "get", NATIVE, "oif", TUN]))[0]
    assert route["dev"] == TUN, route
    peer = Peer([sys.executable, "-B", HERE / "scoped_peer.py", PEER, TUN])
    capture = echo = None
    try:
        capture = icmp.Capture(TUN)
        peer.send(f"listen {TUN_PEER_PORT}")
        listening = peer.read()
        assert listening["event"] == "listening", listening
        echo = TunEcho(binary, NATIVE, "fragment", peer=f"[{PEER}%{index}]:{TUN_PEER_PORT}")
        scope = dict(address=NATIVE, scope_id=index)

        def call(line, event):
            peer.send(line)
            result = peer.read()
            assert result["event"] == event, result
            return result
        originated = call("originate 24576 81", "originated")
        assert originated["hash"] == fnv(pattern(24576, 81)), originated
        assert originated["accepted"]["peer"] == dict(scope, port=originated["accepted"]["peer"]["port"]), originated
        assert originated["accepted"]["local"] == dict(address=PEER, port=TUN_PEER_PORT, scope_id=index), originated
        tcp = call(f"echo {NATIVE} {TUN_PORT} 24576 82", "echo")
        assert tcp["hash"] == fnv(pattern(24576, 82)), tcp
        assert tcp["established"]["peer"] == dict(scope, port=TUN_PORT), tcp
        assert tcp["established"]["local"]["scope_id"] == index, tcp
        udp = call(f"udp {NATIVE} {TUN_PORT} 1200 83", "udp")
        assert udp["rx"] == 1200 and udp["source"] == dict(scope, port=TUN_PORT), udp
        events = capture.since(0)
        wire = []
        for name, local_port, remote_port in (("originated", originated["accepted"]["peer"]["port"], TUN_PEER_PORT),
                                              ("echo", TUN_PORT, tcp["established"]["local"]["port"])):
            out = [e for e in events if e.get("protocol") == 6 and e["direction"] == "from-ntcp"
                   and (e["sport"], e["dport"]) == (local_port, remote_port)]
            assert out and all(e["checksum_valid"] and e["source"] == NATIVE and e["destination"] == PEER for e in out)
            data = [e["length"] for e in out if e["payload"]]
            assert data and max(data) <= 1500, data
            wire.append(dict(name=name, tuple=dict(native=[NATIVE, local_port], peer=[PEER, remote_port],
                                                   scope_id=index),
                             packets=len(out), lengths=sorted(set(data))))
        replies = [e for e in events if e.get("protocol") == 17 and e["direction"] == "from-ntcp"
                   and e["sport"] == TUN_PORT and e["dport"] == udp["local"]["port"]]
        assert len(replies) == 1 and replies[0]["checksum_valid"] and replies[0]["payload"] == 1200, \
            [icmp.public(e) for e in replies]
        wire.append(dict(name="udp", tuple=dict(native=[NATIVE, TUN_PORT], peer=[PEER, udp["local"]["port"]],
                                                scope_id=index), lengths=[replies[0]["length"]]))
        evidence.update(interface=dict(name=TUN, index=index, address=PEER, mtu=link["mtu"]), route=route,
                        namespace=proof["net"]["current"], peer_namespace=peer.ready["namespace"],
                        originated=originated, tcp=tcp, udp=udp, wire=wire, stderr=echo.since(0)[-40:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (echo and echo.close, peer.close, capture and capture.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors:
            evidence.update(cleanup_errors=errors)
            print(json.dumps(dict(case=case, cleanup_errors=errors)), file=sys.stderr)
            if not primary:
                raise RuntimeError(errors)
    return evidence


def child(case, proof, binaries, Peer, command):
    if case["embedding"] == "native":
        return two_link(case, proof, binaries["native"], Peer, command)
    return tun_echo(case, proof, binaries["tun_echo"], Peer, command)
