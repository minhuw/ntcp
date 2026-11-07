# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Rejected-SYN regressions through the actual tun_echo example (T19).

The unmodified tun_echo serves one address on a TUN whose kernel side holds
the TUN subnet's other address. A Linux client in the guarded namespace keeps
one live TCP connection to tun_echo's echo service open throughout. Complete
checksummed IP packets carrying a SYN are injected through an AF_PACKET
SOCK_DGRAM socket bound to the TUN device: the kernel transmits them to
tun_echo's descriptor without routing or source validation, which is how a
SYN with an address Linux itself would never accept reaches the stack. Each
injection is followed by one settle wait and one exact echo round on the
live connection.

ipv6-sources: SYNs from the unspecified address and from the all-nodes
multicast group (RFC 9293 MUST-63, RFC 4291 2.5.2 and 2.7). Then a SYN from
an arrival-zoned link-local source is accepted: a real Linux connection
bound to the kernel's link-local address on the TUN, its zone. Before the
main run, tun_echo started with an unscoped link-local PEER_SOCKET_ADDR
refuses that active open before transmitting anything; the main run's
scoped peer is the paired control and completes an echo.

ipv4-options: with NTCP_IPV4_OPTIONS=1, SYNs from the unspecified, multicast
and TUN subnet broadcast sources, and a SYN from a unicast source carrying a
completed loose source route whose recorded hop is the subnet broadcast
(the return route's authorization refuses it). The paired control, the same
SYN with a unicast recorded hop, draws tun_echo's source-routed SYN-ACK.

Required at the TUN boundary for every rejected SYN: nothing from tun_echo
toward the injected tuple (no SYN-ACK, no RST, no ICMP), no RST at all, the
Host's TCP path clients unchanged (no accepted child: ntcp-pathctl through
tun_echo's control socket), tun_echo still serving, and the live stream's
echo advancing by exactly the round's bytes, at the socket and in tun_echo's
captured sequence space.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

import admin
import icmp
from bridge import checksum
from linux_peer import fnv, pattern

TUN = "t19tun"
PORT = 18080
PEER_PORT = 18083
SETTLE = 1.0
ROUND = 4096
ADDRESSES = {6: dict(kernel="2001:db8:19::1", ntcp="2001:db8:19::2", link_local="fe80::1", prefix="64"),
             4: dict(kernel="192.0.2.1", ntcp="192.0.2.2", broadcast="192.0.2.255", prefix="24")}
# A unicast IPv4 source whose completed loose source route (pointer beyond
# its one recorded hop) names RECORDED: the subnet broadcast (refused) or a
# unicast hop (the paired control).
ROUTED_SOURCE = "192.0.2.7"
CONTROL_HOP = "192.0.2.9"
# The refusal tun_echo states for a link-local peer without the TUN scope.
SCOPE_REFUSAL = "scoped to the TUN interface exactly when link-local"
ETH_P = {4: 0x0800, 6: 0x86DD}
SCENARIOS = ((6, "ipv6-sources"), (4, "ipv4-options"))


def cases():
    return [dict(kind="rejected-syn", family=f, embedding="tun_echo", scenario=s) for f, s in SCENARIOS]


def loose_route(hop):
    """A completed loose source route with one recorded HOP, NOP-padded."""
    return bytes([131, 7, 8]) + ipaddress.ip_address(hop).packed + bytes([1])


def syn(family, source, destination, sport, dport, sequence, options=b""):
    """One complete checksummed IP packet carrying a TCP SYN (MSS 1220),
    IPv4 OPTIONS (a multiple of four octets) after the base header."""
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    tcp = bytearray(struct.pack("!HHIIBBHHH", sport, dport, sequence, 0, 6 << 4, 0x02, 65535, 0, 0)
                    + struct.pack("!BBH", 2, 4, 1220))
    if family == 6:
        pseudo = src + dst + struct.pack("!I", len(tcp)) + bytes([0, 0, 0, 6])
    else:
        pseudo = src + dst + bytes([0, 6]) + struct.pack("!H", len(tcp))
    struct.pack_into("!H", tcp, 16, checksum(pseudo + bytes(tcp)))
    if family == 6:
        return struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst + bytes(tcp)
    assert len(options) % 4 == 0 and len(options) <= 40
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0, 20 + len(options) + len(tcp),
                                   sport, 0x4000, 64, 6, 0, src, dst) + options)
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header) + bytes(tcp)


def vectors(family):
    """(name, source, IPv4 options) of every rejected SYN of FAMILY."""
    if family == 6:
        return [("unspecified-source", "::", b""), ("multicast-source", "ff02::1", b"")]
    a = ADDRESSES[4]
    return [("unspecified-source", "0.0.0.0", b""), ("multicast-source", "224.0.0.1", b""),
            ("broadcast-source", a["broadcast"], b""),
            ("broadcast-recorded-hop", ROUTED_SOURCE, loose_route(a["broadcast"]))]


def routed_checksum_valid(packet):
    """The TCP checksum of a source-routed IPv4 PACKET, whose pseudo-header
    names the route's final destination (RFC 791 3.1, RFC 9293 3.1), the
    last address of its one source route option."""
    hl = (packet[0] & 15) * 4
    option = packet[20:hl]
    assert option[0] in (131, 137), option.hex()
    final = option[option[1] - 4:option[1]]
    body = packet[hl:struct.unpack_from("!H", packet, 2)[0]]
    return checksum(packet[12:16] + final + bytes([0, 6]) + struct.pack("!H", len(body)) + body) == 0


def inject(family, packet):
    """Transmit PACKET on the TUN device (to tun_echo's descriptor)."""
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0) as s:
        assert s.sendto(packet, (TUN, ETH_P[family])) == len(packet)
    return dict(length=len(packet), sha256=hashlib.sha256(packet).hexdigest(), hex=packet.hex())


class TunEcho(icmp.Ntcp):
    """The unmodified tun_echo example on this case's TUN."""

    @staticmethod
    def command(binary, local, peer=None):
        return [str(binary), TUN, local, str(PORT)] + ([peer] if peer else [])


def receive(s, n):
    data = bytearray()
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, ("short echo", len(data), n)
        data.extend(chunk)
    return bytes(data)


def sent_end(events, tuple_, isn):
    """The highest relative sequence end tun_echo sent on TUPLE_."""
    ends = [((e["seq"] - isn - 1) & 0xffffffff) + e["payload"] for e in events
            if e["direction"] == "from-ntcp" and e.get("protocol") == 6 and (e["sport"], e["dport"]) == tuple_
            and e["payload"]]
    return max(ends, default=0)


def tcp_clients(ctl):
    """Every Host path's TCP client count (ntcp-pathctl)."""
    counts = {}
    for path in ctl.paths():
        clients = admin.parse_records(ctl.run("clients", path["token"]).stdout, "client")
        counts[path["destination"]] = counts.get(path["destination"], 0) + sum(c["kind"] == "tcp" for c in clients)
    return counts


def provenance(family, command):
    paths = ["net/ipv4/conf/all/rp_filter", "net/ipv4/conf/all/accept_source_route", "net/ipv4/ip_forward",
             f"net/ipv6/conf/{TUN}/addr_gen_mode", f"net/ipv6/conf/{TUN}/accept_dad",
             "net/ipv6/conf/all/forwarding"]
    sysctls = {p: Path("/proc/sys/" + p).read_text().strip() for p in paths}
    link = json.loads(command(["ip", "-j", "-s", "link", "show", TUN]))[0]
    snmp = Path("/proc/net/snmp").read_text().splitlines()
    tcp = dict(zip(*(l.split()[1:] for l in snmp if l.startswith("Tcp:"))))
    return dict(sysctls=sysctls, tun_stats=link.get("stats64"), kernel_tcp=dict(
        OutRsts=int(tcp["OutRsts"]), InSegs=int(tcp["InSegs"]), AttemptFails=int(tcp["AttemptFails"])))


def setup(family, command):
    a = ADDRESSES[family]
    command(["sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/default/addr_gen_mode"])
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "tuntap", "add", "dev", TUN, "mode", "tun"])
    command(["ip", "link", "set", TUN, "mtu", "1500"])
    command(["ethtool", "-K", TUN, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"])
    command(["ip", "addr", "add", a["kernel"] + "/" + a["prefix"], "dev", TUN, *(["nodad"] if family == 6 else [])])
    if family == 6:
        command(["ip", "addr", "add", a["link_local"] + "/64", "dev", TUN, "nodad"])
    command(["ip", "link", "set", TUN, "up"])
    link = next(l for l in json.loads(command(["ip", "-j", "addr", "show"])) if l["ifname"] == TUN)
    owned = [i["local"] for l in json.loads(command(["ip", "-j", "addr", "show"])) for i in l.get("addr_info", [])]
    assert a["ntcp"] not in owned, "tun_echo address assigned to the kernel"
    route = json.loads(command(["ip", "-j", "-" + str(family), "route", "get", a["ntcp"]]))[0]
    assert route["dev"] == TUN, route
    return dict(index=link["ifindex"], mtu=link["mtu"], addresses=[(i["local"], i["prefixlen"]) for i in link["addr_info"]],
                route=route)


def refused_unscoped(binary, capture, environment, listener):
    """tun_echo with an unscoped link-local PEER_SOCKET_ADDR: refused before
    anything is transmitted."""
    a = ADDRESSES[6]
    start = capture.mark()
    p = subprocess.run(TunEcho.command(binary, a["ntcp"], f"[{a['link_local']}]:{PEER_PORT}"),
                       env=environment, capture_output=True, text=True, timeout=10)
    time.sleep(SETTLE)
    sent = [icmp.public(e) for e in capture.since(start) if e["direction"] == "from-ntcp"]
    assert p.returncode != 0 and SCOPE_REFUSAL in p.stderr, (p.returncode, p.stderr[-2000:])
    assert not sent, ("transmitted before the refusal", sent)
    listener.setblocking(False)
    try:
        listener.accept()
        raise AssertionError("the unscoped open reached the listener")
    except BlockingIOError:
        pass
    return dict(peer=f"[{a['link_local']}]:{PEER_PORT}", exit=p.returncode, stderr=p.stderr.strip()[-600:],
                from_ntcp_packets=0, listener_pending=0)


def child(case, proof, binary, pathctl, command):
    family = case["family"]
    a = ADDRESSES[family]
    interface = setup(family, command)
    directory = tempfile.mkdtemp(prefix="t19-rejected-control-")
    socket_path = Path(directory) / "control.sock"
    settings = {"NTCP_CONTROL_SOCKET": str(socket_path)}
    if family == 4:
        settings["NTCP_IPV4_OPTIONS"] = "1"
    evidence = dict(case=case, interface=interface, tun_echo_settings=settings, settle_s=SETTLE,
                    injection="AF_PACKET SOCK_DGRAM on the TUN device", before=provenance(family, command))
    capture = echo = live = listener = originated = None
    try:
        capture = icmp.Capture(TUN)
        index = interface["index"]
        peer = None
        if family == 6:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind((a["link_local"], PEER_PORT, 0, index))
            listener.listen(4)
            evidence["refused_unscoped_connect"] = refused_unscoped(
                binary, capture, TunEcho.environment("fragment", settings), listener)
            peer = f"[{a['link_local']}%{index}]:{PEER_PORT}"
        echo = TunEcho(binary, a["ntcp"], "fragment", settings, peer=peer)
        ctl = admin.Pathctl(pathctl, socket_path)
        if listener is not None:
            # The scoped peer (paired control): tun_echo's active open
            # completes in the listener's backlog before any injection.
            listener.settimeout(10)
            originated, _ = listener.accept()
            originated.settimeout(10)
            originated_names = (list(originated.getpeername()[:2]), originated.getsockname()[3])
        family_socket = socket.AF_INET6 if family == 6 else socket.AF_INET
        live = socket.socket(family_socket, socket.SOCK_STREAM)
        live.settimeout(10)
        live.connect((a["ntcp"], PORT))
        local_port = live.getsockname()[1]
        live_tuple = (PORT, local_port)
        handshake = next(e for e in capture.since(0) if e["direction"] == "from-ntcp" and e.get("protocol") == 6
                         and (e["sport"], e["dport"]) == live_tuple and e["flags"] & 0x12 == 0x12)
        isn = handshake["seq"]
        total, rounds = 0, []

        def exchange(name, salt):
            nonlocal total
            data = pattern(ROUND, salt)
            live.sendall(data)
            assert receive(live, ROUND) == data, name
            total += ROUND
            deadline = time.monotonic() + 5
            while sent_end(capture.since(0), live_tuple, isn) != total and time.monotonic() < deadline:
                time.sleep(0.02)
            end = sent_end(capture.since(0), live_tuple, isn)
            assert end == total, ("echo sequence progress", name, end, total)
            assert echo.p.poll() is None, dict(exit=echo.p.returncode, stderr=echo.since(0)[-20:])
            rounds.append(dict(after=name, bytes=ROUND, hash=fnv(data), echoed_total=total, tun_sequence_end=end))

        exchange("established", 1)
        baseline = tcp_clients(ctl)
        assert sum(baseline.values()) >= 1, baseline
        injected = []
        for number, (name, source, options) in enumerate(vectors(family)):
            sport = 40000 + number
            packet = syn(family, source, a["ntcp"], sport, PORT, 0x1000 * (number + 1), options)
            start = capture.mark()
            record = dict(name=name, source=source, options=options.hex(), sport=sport, **inject(family, packet))
            time.sleep(SETTLE)
            events = capture.since(start)
            seen = [e for e in events if e["direction"] == "to-ntcp" and e.get("protocol") == 6
                    and e["sport"] == sport]
            assert len(seen) == 1 and seen[0]["checksum_valid"], ("injected SYN at the TUN", [icmp.public(e) for e in seen])
            answered = [icmp.public(e) for e in events if e["direction"] == "from-ntcp"
                        and (e.get("dport") == sport or e["destination"] == source or e.get("protocol") != 6
                             or e["flags"] & 0x04 or e["flags"] & 0x12 == 0x12)]
            assert not answered, (name, answered)
            clients = tcp_clients(ctl)
            assert clients == baseline, ("accepted child", name, baseline, clients)
            assert echo.p.poll() is None, dict(exit=echo.p.returncode, stderr=echo.since(0)[-20:])
            exchange(name, 10 + number)
            injected.append(dict(record, tcp_clients=clients, answered=0))
        evidence.update(injected=injected, tcp_clients=baseline)
        if family == 6:
            # An arrival-zoned link-local SYN is accepted: a Linux
            # connection bound to the kernel's link-local address on the TUN.
            start = capture.mark()
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.bind((a["link_local"], 0, 0, index))
                s.connect((a["ntcp"], PORT))
                bound = s.getsockname()
                data = pattern(ROUND, 81)
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
                received = bytearray()
                while chunk := s.recv(65536):
                    received.extend(chunk)
            assert bytes(received) == data, ("link-local echo", len(received))
            events = capture.since(start)
            synack = [e for e in events if e["direction"] == "from-ntcp" and e.get("protocol") == 6
                      and e["flags"] & 0x12 == 0x12 and e["dport"] == bound[1]]
            assert len(synack) >= 1 and synack[0]["source"] == a["ntcp"] and \
                synack[0]["destination"] == a["link_local"] and synack[0]["checksum_valid"], \
                [icmp.public(e) for e in synack]
            evidence["link_local_accepted"] = dict(local=dict(address=a["link_local"], port=bound[1], scope_id=bound[3]),
                                                   synack=icmp.public(synack[0]), bytes=ROUND, hash=fnv(data))
            # The scoped active open (paired control of the refusal).
            control = pattern(ROUND, 82)
            originated.sendall(control)
            originated.shutdown(socket.SHUT_WR)
            back = bytearray()
            while chunk := originated.recv(65536):
                back.extend(chunk)
            assert bytes(back) == control, ("scoped active open echo", len(back))
            evidence["scoped_control"] = dict(peer=peer, accepted=originated_names[0],
                                              scope_id=originated_names[1], bytes=ROUND, hash=fnv(control))
        else:
            # The paired control: the same SYN with a unicast recorded hop
            # draws the source-routed SYN-ACK through that hop.
            sport = 40100
            packet = syn(4, ROUTED_SOURCE, a["ntcp"], sport, PORT, 0x7000, loose_route(CONTROL_HOP))
            start = capture.mark()
            record = dict(source=ROUTED_SOURCE, options=loose_route(CONTROL_HOP).hex(), **inject(4, packet))
            time.sleep(SETTLE)
            synack = [e for e in capture.since(start) if e["direction"] == "from-ntcp" and e.get("protocol") == 6
                      and e["dport"] == sport and e["flags"] & 0x12 == 0x12]
            assert synack and synack[0]["ack"] == 0x7001, [icmp.public(e) for e in synack]
            # The reversed route: first hop CONTROL_HOP, the source last.
            reply = synack[0]
            reversed_route = bytes([131, 7, 4]) + ipaddress.ip_address(ROUTED_SOURCE).packed + bytes(1)
            assert reply["destination"] == CONTROL_HOP and reply["ip_options"] == reversed_route.hex(), icmp.public(reply)
            assert routed_checksum_valid(reply["raw"]), icmp.public(reply)
            evidence["source_route_control"] = dict(record, synack=icmp.public(reply), final_destination=ROUTED_SOURCE,
                                                    checksum="valid with the route's final destination")
        exchange("controls", 90)
        live.shutdown(socket.SHUT_WR)
        assert live.recv(1) == b"", "live echo EOF"
        evidence.update(rounds=rounds, live=dict(kernel=[a["kernel"], local_port], ntcp=[a["ntcp"], PORT],
                                                 echoed=total), after=provenance(family, command),
                        utility_requests=len(ctl.log), stderr=echo.since(0)[-40:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (live and live.close, originated and originated.close, listener and listener.close,
                      echo and echo.close, capture and capture.close):
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
            evidence.update(cleanup_errors=errors)
            if not primary:
                raise RuntimeError(errors)
    return evidence
