# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Owner-configured Segment Routing Header routes (RFC 8754 section 4.1, an
SR source node like Linux seg6 inline encapsulation) against real Linux
SRv6 endpoints, and Linux-originated Hop-by-Hop and Destination Options.

tun_echo: ntcp <-> TUN(1500) <-> transit router <-> 1280-octet veth <->
SRv6 endpoint namespace (seg6local End instantiates the SID S1) <-> 1500
veth <-> peer namespace, whose address is the final destination D (a
seg6local End node does not deliver the next segment locally, so D is a
further node). tun_echo's NTCP_IPV6_SRH sends every packet to D with base
Destination Address S1 and the SRH [D, S1], Segments Left 1. The transit
router neither owns S1 nor processes the SRH; its 1280 egress towards S1
makes the router kernel quote submitted SRH packets (Segments Left 1, base
destination S1 != D) in real Packet Too Big messages. A second peer
address D2, reached directly over the 1500-octet ingress, is the
unaffected comparison path.

native: the AF_PACKET runtime's `ipv6.srh.<prefix>` line (parsed by the
production configuration reader) through the Ethernet bridge, which walks
the chain and validates TCP and ICMPv6 checksums with D. The kernel side is
D and owns S1 as a local SID address: Linux's own SRH processing
(seg6_enabled) advances Segments Left to 0 and delivers to D.
"""
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

import icmp
from bridge import Bridge
from icmp_peer import ext_ping
from linux_peer import fnv, pattern

HERE = Path(__file__).resolve().parent
# RFC 3542 sticky options (Linux socket option numbers).
IPV6_HOPOPTS = 54
IPV6_DSTOPTS = 59
# Option areas the kernel completes with its Next Header: PadN only (RFC
# 8200 4.2), and an unrecognized option whose action bits are 10 (type
# 0x9e, an RFC 4727 experimental type this Host does not recognize): discard
# and Parameter Problem code 2 at the Option Type octet, base header + 2.
PADN = "0000010400000000"
UNKNOWN_10 = "00009e0400000000"
UNKNOWN_POINTER = 40 + 2
TUN_ADDRESSES = dict(sid="2001:db8:94::1", comparison="2001:db8:95::2", transit="2001:db8:96::1",
                     endpoint="2001:db8:96::2", endpoint_peer_side="2001:db8:97::1", peer_side="2001:db8:97::2")
# The transit router's egress to the endpoint and the endpoint's link on to
# the peer: (ours, theirs, MTU, MAC of ours, MAC of theirs).
TRANSIT_LINK = ("t17re", "t17er", 1280, "02:00:00:00:17:01", "02:00:00:00:17:02")
ENDPOINT_LINK = ("t17ep", "t17pe", 1500, "02:00:00:00:17:03", "02:00:00:00:17:04")
# The native port's on-link kernel address, the native address, the SID and
# the final destination D beyond the link (an SR route's final destinations
# are off-link): both kernel addresses on its loopback.
NATIVE_ADDRESSES = dict(kernel="fd54:3500::1", native="fd54:3500::2", sid="fd54:3501::1",
                        destination="fd54:3502::1")
SRH_HEADER = 40 + 8 + 16 * 2  # base header + SRH listing D and S1


def cases():
    return [dict(kind="srh", family=6, embedding="tun_echo", scenario="transit-ptb"),
            dict(kind="srh", family=6, embedding="native", scenario="endpoint")]


def srh_of(event, destination, sid):
    """EVENT's chain is the one emitted SRH: Routing Type 4, Segments Left
    and Last Entry 1, the full list [D, S1], flags and tag 0, base
    Destination Address S1 and transport checksum over D."""
    chain = event["extensions"]
    assert len(chain) == 1 and chain[0]["type"] == 43, ("one Segment Routing Header", chain)
    header = chain[0]
    assert (header["routing_type"], header["segments_left"], header["last_entry"], header["flags"], header["tag"],
            header["length"]) == (4, 1, 1, 0, 0, 40), header
    assert header["segments"] == [destination, sid], header
    assert event["destination"] == sid != destination == event["final_destination"], event
    assert event["checksum_valid"], event
    return header


def sysctls(run, names):
    return {name: run("cat", "/proc/sys/" + name).strip() for name in names}


def tun_child(case, proof, binary, Peer, command):
    a = icmp.ADDRESSES[6]
    d, sid, d2 = a["peer"], TUN_ADDRESSES["sid"], TUN_ADDRESSES["comparison"]
    t = TUN_ADDRESSES
    peer = Peer(["unshare", "--net", sys.executable, "-B", HERE / "icmp_peer.py", d, a["ntcp"], icmp.PORT])
    # The SRv6 endpoint node: a further network namespace of the same
    # harness-owned user namespace, held by a sleeping process.
    endpoint = subprocess.Popen(["unshare", "--net", "sleep", "300"], stdin=subprocess.DEVNULL)
    ntcp = capture = None
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        deadline = time.monotonic() + 5
        while os.stat(f"/proc/{endpoint.pid}/ns/net").st_ino in (proof["net"]["current"], proof["net"]["parent"]):
            assert time.monotonic() < deadline and endpoint.poll() is None, "endpoint namespace"
            time.sleep(0.02)
        endpoint_namespace = os.stat(f"/proc/{endpoint.pid}/ns/net").st_ino
        assert endpoint_namespace != peer.ready["namespace"]
        settings = icmp.setup(6, 1280, command, peer.p.pid)

        def router(*args):
            return command(["ip", *args])

        def in_peer(*args):
            return command(["nsenter", "-t", str(peer.p.pid), "-n", *args])

        def in_endpoint(*args):
            return command(["nsenter", "-t", str(endpoint.pid), "-n", *args])
        def here(*args):
            return command(list(args))
        for (ours, theirs, mtu, our_mac, their_mac), near, there in (
                (TRANSIT_LINK, here, endpoint.pid), (ENDPOINT_LINK, in_endpoint, peer.p.pid)):
            near("ip", "link", "add", ours, "type", "veth", "peer", "name", theirs)
            for name, mac in ((ours, our_mac), (theirs, their_mac)):
                near("ip", "link", "set", name, "address", mac, "mtu", str(mtu))
                near("ethtool", "-K", name, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off")
            near("ip", "link", "set", theirs, "netns", str(there))
        in_endpoint("ip", "link", "set", "lo", "up")
        for run, name, address in ((here, "t17re", t["transit"]), (in_endpoint, "t17er", t["endpoint"]),
                                   (in_endpoint, "t17ep", t["endpoint_peer_side"]), (in_peer, "t17pe", t["peer_side"])):
            run("ip", "addr", "add", address + "/64", "dev", name, "nodad")
            run("ip", "link", "set", name, "up")
        # The transit router forwards S1 over its 1280 egress and D2 over
        # the 1500 ingress veth; it owns neither and has no seg6 route.
        router("-6", "neigh", "replace", t["endpoint"], "lladdr", TRANSIT_LINK[4], "nud", "permanent", "dev", "t17re")
        router("-6", "route", "replace", sid + "/128", "via", t["endpoint"], "dev", "t17re")
        router("-6", "neigh", "replace", d, "lladdr", icmp.MACS["t9pa"], "nud", "permanent", "dev", "t9ra")
        router("-6", "route", "replace", d2 + "/128", "via", d, "dev", "t9ra")
        # The endpoint: SRH processing enabled on its ingress, S1
        # instantiated as End, D forwarded to the peer, owned return route.
        for name in ("all", "t17er"):
            in_endpoint("sh", "-c", f"echo 1 > /proc/sys/net/ipv6/conf/{name}/seg6_enabled")
        in_endpoint("sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
        in_endpoint("ip", "-6", "route", "replace", sid + "/128", "encap", "seg6local", "action", "End", "dev", "t17er")
        in_endpoint("ip", "-6", "neigh", "replace", t["peer_side"], "lladdr", ENDPOINT_LINK[4], "nud", "permanent",
                    "dev", "t17ep")
        in_endpoint("ip", "-6", "route", "replace", d + "/128", "via", t["peer_side"], "dev", "t17ep")
        in_endpoint("ip", "-6", "neigh", "replace", t["transit"], "lladdr", TRANSIT_LINK[3], "nud", "permanent",
                    "dev", "t17er")
        in_endpoint("ip", "-6", "route", "replace", "default", "via", t["transit"], "dev", "t17er")
        # The peer accepts the delivered SRH (Segments Left 0) on its link
        # from the endpoint; D2 is a further peer address.
        for name in ("all", "t17pe"):
            in_peer("sh", "-c", f"echo 1 > /proc/sys/net/ipv6/conf/{name}/seg6_enabled")
        in_peer("ip", "-6", "addr", "add", d2 + "/128", "dev", "lo")
        owned = json.loads(router("-j", "addr", "show")) + json.loads(in_peer("ip", "-j", "addr", "show"))
        assert not any(i["local"] == sid for link in owned for i in link.get("addr_info", [])), owned
        to_sid = json.loads(router("-j", "-6", "route", "get", sid))[0]
        mtus = {link["ifname"]: link["mtu"] for link in json.loads(router("-j", "link", "show"))}
        assert to_sid["dev"] == "t17re" and mtus["t17re"] == 1280 and mtus["t9ra"] == mtus[icmp.TUN] == 1500, to_sid
        seg6 = dict(
            endpoint_seg6local=json.loads(in_endpoint("ip", "-j", "-6", "route", "show", sid + "/128")),
            endpoint=sysctls(in_endpoint, [f"net/ipv6/conf/{n}/seg6_enabled" for n in ("all", "t17er")]
                             + ["net/ipv6/conf/all/forwarding"]),
            peer=sysctls(in_peer, [f"net/ipv6/conf/{n}/seg6_enabled" for n in ("all", "t17pe")]),
            router=sysctls(lambda *x: command(list(x)),
                           [f"net/ipv6/conf/{n}/seg6_enabled" for n in ("all", "t17re", icmp.TUN)]
                           + ["net/ipv6/conf/all/forwarding"]),
            router_to_sid=to_sid, router_mtus=mtus, endpoint_namespace=endpoint_namespace)
        assert set(seg6["endpoint"].values()) == set(seg6["peer"].values()) == {"1"}, seg6
        capture = icmp.Capture(icmp.TUN)
        ntcp = icmp.Ntcp(binary, a["ntcp"], "refuse", {"NTCP_IPV6_SRH": f"{d}/128={sid}"})
        kernel_before = icmp.counters(6)

        def sent(events, protocol, destination):
            return [e for e in events if e["direction"] == "from-ntcp" and e["protocol"] == protocol
                    and e["final_destination"] == destination and not e["fragmented"]]

        def ptbs(events):
            return [e for e in events if e["direction"] == "to-ntcp" and e.get("ptb")]

        # Warm-up: a UDP echo reply leaves with the SRH and reaches D
        # through the endpoint.
        mark = capture.mark()
        peer.send("udp 64 1 2.0")
        warm = peer.read()
        assert warm["reply"] == 64 and warm["match"], (warm, [icmp.public(e) for e in capture.since(mark)][:6])
        warm_reply, = sent(capture.since(mark), 17, d)
        srh_of(warm_reply, d, sid)

        # TCP through the SR route: 1500-octet SR packets draw the transit
        # router's PTB, which quotes Segments Left 1 and base S1.
        mark = capture.mark()
        peer.send(f"tcp {icmp.TCP_BYTES} 7")
        stream = peer.read()
        assert (stream["tx"], stream["rx"], stream["hash"]) == (
            icmp.TCP_BYTES, icmp.TCP_BYTES, fnv(pattern(icmp.TCP_BYTES, 7))), stream
        events = capture.since(mark)
        segments = sent(events, 6, d)
        assert segments and all(srh_of(e, d, sid) for e in segments), [icmp.public(e) for e in segments[:4]]
        synack, = [e for e in segments if e["flags"] & 0x12 == 0x12]
        data = [e for e in segments if e["payload"]]
        originals = [e for e in data if e["length"] > 1280]
        assert originals, [icmp.public(e) for e in data[:8]]
        quoted = []
        for ptb in ptbs(events):
            assert ptb["checksum_valid"] and ptb["source"] == a["router"] and ptb["mtu"] == 1280, icmp.public(ptb)
            inner = icmp.parse(ptb["quote"])
            assert inner["destination"] == sid != inner["final_destination"] == d, inner
            routing, = inner["extensions"]
            assert (routing["routing_type"], routing["segments_left"]) == (4, 1), routing
            match = next((o for o in originals if icmp.quotes(ptb["quote"], o["raw"])), None)
            assert match is not None, ("PTB quotes no captured ntcp packet", icmp.public(ptb))
            quoted.append(dict(ptb=icmp.public(ptb), quoted_bytes=len(ptb["quote"]), quoted_chain=inner["extensions"],
                               quoted_base_destination=inner["destination"],
                               quoted_final_destination=inner["final_destination"],
                               original=icmp.public(match), ptb_hex=ptb["raw"][:160].hex()))
        assert quoted, "no router PTB quoted an SRH packet"
        # Repair: after the first reduced data segment nothing exceeds 1280,
        # every reduced segment still carries the SRH, and the first dropped
        # range is resent.
        first_small = next(i for i, e in enumerate(data) if e["length"] <= 1280)
        assert all(e["length"] <= 1280 for e in data[first_small:]), [icmp.public(e) for e in data[first_small:][:8]]
        dropped = next(o for o in originals if icmp.quotes(ptbs(events)[0]["quote"], o["raw"]))
        covered = set()
        for e in data[first_small:]:
            start = (e["seq"] - dropped["seq"]) & 0xffffffff
            if start < 1 << 31:
                covered.update(range(start, min(start + e["payload"], dropped["payload"])))
        assert covered == set(range(dropped["payload"])), ("dropped range not resent", icmp.public(dropped))
        # Every data segment's transport starts after the 80-octet chain.
        assert all(e["header_len"] == SRH_HEADER for e in data), [e["header_len"] for e in data[:4]]

        # The comparison path to D2 (no SRH, 1500-octet route) is unaffected.
        mark = capture.mark()
        peer.send(f"tcpfrom {d2} {icmp.TCP_BYTES} 9")
        comparison = peer.read()
        assert (comparison["rx"], comparison["hash"]) == (icmp.TCP_BYTES, fnv(pattern(icmp.TCP_BYTES, 9))), comparison
        later = capture.since(mark)
        direct = [e for e in sent(later, 6, d2) if e["payload"]]
        assert direct and all(not e["extensions"] and e["destination"] == d2 for e in direct), direct[:4]
        assert max(e["length"] for e in direct) == 1500 and not ptbs(later), (
            [icmp.public(e) for e in direct[:4]], [icmp.public(e) for e in ptbs(later)])

        # Linux-originated Hop-by-Hop and Destination Options reach ntcp's
        # ingress and are dispatched (Echo Replies over the SR route); an
        # unrecognized action-10 option draws ntcp's Parameter Problem.
        options = {}
        for name, optname, header, salt in (("hop-by-hop", IPV6_HOPOPTS, PADN, 21),
                                            ("destination", IPV6_DSTOPTS, PADN, 22),
                                            ("unknown-action-10", IPV6_DSTOPTS, UNKNOWN_10, 23)):
            mark = capture.mark()
            peer.send(f"xping {optname} {header} 64 {salt} 2.0")
            result = peer.read()
            events = capture.since(mark)
            requests = [e for e in events if e["direction"] == "to-ntcp" and e["protocol"] == 58
                        and e.get("echo") and e["identifier"] == (0x5100 + salt) & 0xffff]
            request, = requests
            chain, = request["extensions"]
            assert (chain["type"], chain["options"]) == (0 if optname == IPV6_HOPOPTS else 60, header[4:]), chain
            assert request["checksum_valid"], icmp.public(request)
            answers = sent(events, 58, d)
            answer, = answers
            srh_of(answer, d, sid)
            body = answer["raw"][answer["header_len"]:]
            if header == UNKNOWN_10:
                assert result["reply"] is None and result["error"] and (
                    result["error"]["type"], result["error"]["code"], result["error"]["pointer"],
                    result["error"]["quoted_next_header"]) == (4, 2, UNKNOWN_POINTER, 60), result
                assert (body[0], body[1], struct.unpack_from("!I", body, 4)[0]) == (4, 2, UNKNOWN_POINTER), body[:8].hex()
                assert body[8:8 + len(request["raw"])] == request["raw"][:len(body) - 8], "quotes the request"
            else:
                assert result["reply"] == 64 and result["match"] and result["error"] is None, result
                assert body[0] == 129, body[:8].hex()
            options[name] = dict(peer=result, request=icmp.public(request), answer=icmp.public(answer),
                                 answer_hex=answer["raw"][:160].hex())

        kernel_after = icmp.counters(6)
        generated = len(ptbs(capture.since(0)))
        assert kernel_after - kernel_before == generated >= 1, (kernel_before, kernel_after, generated)
        return dict(case=case, settings=settings, seg6=seg6, tun_echo_settings=ntcp.settings,
                    addresses=dict(final_destination=d, sid=sid, comparison=d2),
                    warm_udp=dict(peer=warm, reply=icmp.public(warm_reply)),
                    stream=stream, synack=icmp.public(synack), large_segments=len(originals),
                    reduced_segments=len(data) - first_small, correlation=quoted,
                    dropped_range=dict(seq=dropped["seq"], payload=dropped["payload"]),
                    comparison=dict(stream=comparison, data_packets=len(direct),
                                    max_ip_length=max(e["length"] for e in direct)),
                    options=options, kernel_ptb_counter=dict(before=kernel_before, after=kernel_after),
                    router_generated_ptbs=generated, ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for close in (ntcp and ntcp.close, peer.close, capture and capture.close,
                      lambda: (endpoint.kill(), endpoint.wait())):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors and not primary:
            raise RuntimeError(errors)


def native_child(case, proof, binary, Peer, command, setup, peer_script, validate_stream):
    kernel, n, sid, k = (NATIVE_ADDRESSES[x] for x in ("kernel", "native", "sid", "destination"))
    settings = setup(6, kernel, n)

    def run(*args):
        return command(list(args))
    # The kernel side is D and owns the SID S1: with SRH processing
    # enabled on its port it advances Segments Left and delivers to D.
    for name in ("all", "t5k"):
        run("sh", "-c", f"echo 1 > /proc/sys/net/ipv6/conf/{name}/seg6_enabled")
    run("ip", "-6", "addr", "add", sid + "/128", "dev", "lo")
    run("ip", "-6", "addr", "add", k + "/128", "dev", "lo")
    seg6 = dict(kernel_sid=json.loads(run("ip", "-j", "-6", "addr", "show", "dev", "lo")),
                kernel=sysctls(run, [f"net/ipv6/conf/{x}/seg6_enabled" for x in ("all", "t5k")]
                               + ["net/ipv6/conf/all/forwarding"]))
    assert seg6["kernel"]["net/ipv6/conf/t5k/seg6_enabled"] == "1", seg6
    bridge = Bridge(icmp=True)
    peers = []
    try:
        line = f"ipv6.srh.{k}/128={sid}"
        os.environ["T17_SEGMENT_ROUTE"] = line
        try:
            client = Peer([binary, "client", n, k, "hmac", 65536, 3_600_000_000, 1, 0])
        finally:
            del os.environ["T17_SEGMENT_ROUTE"]
        peers.append(client)
        server = Peer([sys.executable, peer_script, "server", k, n, 0])
        peers.append(server)
        start = bridge.configure("none", "native-to-kernel")
        server.send("accept")
        client.send("connect blocking")
        c, s = client.read(), server.read()
        validate_stream(s, c)
        events, _ = bridge.snapshot(start)
        tcp = [e for e in events if "flags" in e]
        out = [e for e in tcp if e["direction"] == "native-to-kernel"]
        back = [e for e in tcp if e["direction"] == "kernel-to-native"]
        assert out and all(srh_of(e, k, sid) for e in out), out[:4]
        assert back and all(not e["extensions"] and e["destination"] == n for e in back), back[:4]
        syn, = [e for e in out if e["flags"] & 0x12 == 2]
        data = [e for e in out if e["payload"]]
        assert data and sum(e["payload"] for e in data) >= 11264, [e["payload"] for e in data]
        # Linux-originated extension headers through the bridge to the
        # native ingress; the native Host answers over its SR route.
        options = {}
        for name, optname, header, salt in (("hop-by-hop", IPV6_HOPOPTS, PADN, 31),
                                            ("destination", IPV6_DSTOPTS, PADN, 32),
                                            ("unknown-action-10", IPV6_DSTOPTS, UNKNOWN_10, 33)):
            start = bridge.configure("none", "native-to-kernel")
            result = ext_ping(n, optname, bytes.fromhex(header), 64, salt, 2.0, source=k)
            events, _ = bridge.snapshot(start)
            icmp6 = [e for e in events if e.get("protocol") == 58]
            request, = [e for e in icmp6 if e["direction"] == "kernel-to-native" and e["icmp_type"] == 128]
            chain, = request["extensions"]
            assert (chain["type"], chain["options"]) == (0 if optname == IPV6_HOPOPTS else 60, header[4:]), chain
            answer, = [e for e in icmp6 if e["direction"] == "native-to-kernel" and e["icmp_type"] in (4, 129)]
            srh_of(answer, k, sid)
            if header == UNKNOWN_10:
                assert (answer["icmp_type"], answer["icmp_code"], answer["word"]) == (4, 2, UNKNOWN_POINTER), answer
                assert result["error"] and (result["error"]["type"], result["error"]["code"],
                                            result["error"]["pointer"]) == (4, 2, UNKNOWN_POINTER), result
            else:
                assert answer["icmp_type"] == 129 and result["reply"] == 64 and result["match"], (answer, result)
            options[name] = dict(peer=result, request=request, answer=answer)
        return dict(case=case, settings=settings, seg6=seg6, configuration=line,
                    addresses=dict(final_destination=k, sid=sid, native=n, kernel_on_link=kernel), client=c, server=s,
                    syn=syn, segments_out=len(out), data_segments=len(data),
                    max_ip_length=max(e["ip_length"] for e in out), options=options)
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for p in peers:
            try:
                p.close()
            except Exception as e:
                errors.append(str(e))
        bridge.close()
        if errors and not primary:
            raise RuntimeError(errors)


def child(case, proof, binaries, Peer, command, setup, validate_stream):
    if case["embedding"] == "native":
        return native_child(case, proof, binaries["native"], Peer, command, setup, HERE / "linux_peer.py",
                            validate_stream)
    return tun_child(case, proof, binaries["tun_echo"], Peer, command)
