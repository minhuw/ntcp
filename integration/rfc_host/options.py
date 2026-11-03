# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""IPv4 Echo option continuation per embedding (RFC 1122 3.2.1.8, 3.2.2.6).

A Linux sender in the guarded namespace writes complete IPv4 Echo Requests
(raw IP_HDRINCL, so the kernel neither records nor rewrites their options)
carrying Record Route and Timestamp, and once also a completed loose source
route. The request is captured where it enters the stack and the reply where
it leaves it: tun_echo's TUN in the ICMP router topology, or the native
runtime's Ethernet port through the bridge's option-aware ICMP forwarding.
Linux records nothing before the ingress capture (header-included output)
and its receive-side recording happens after the egress capture.

Profiles: tun_echo with NTCP_IPV4_OPTIONS=1 (interpretation enabled, source
routes admitted with return-route authorization), tun_echo without it
(interpretation disabled, source routes refused) and the native managed
runtime (interpretation enabled with its marked elapsed clock, source routes
refused). The interpreting profiles answer with RR/TS carried at their
lengths, updated once with this host's address and a timestamp marked
nonstandard by the RFC 791 high bit; the disabled profile answers without
options; refused source routes draw no reply.
"""
import socket
import struct
import sys
import time

from bridge import Bridge, checksum
import icmp

# Record Route with three slots, one already filled by an earlier hop.
RR = bytes([7, 15, 8, 198, 18, 9, 9]) + bytes(8)
# Timestamp, flag 1 (address and time), two slots, overflow 0.
TS_ADDRESSED = bytes([68, 20, 5, 1]) + bytes(16)
# Timestamp, flag 0 (time only), three slots, one filled by an earlier hop.
TS_TIMES = bytes([68, 16, 9, 0, 0, 0, 0, 5]) + bytes(8)
REPLY_WAIT = 2.0
SETTLE_WAIT = 1.0


def cases():
    return [dict(kind="ip-options", family=4, embedding=embedding, scenario=scenario)
            for embedding, scenario in (("tun_echo", "interpreted"), ("tun_echo", "uninterpreted"),
                                        ("native", "interpreted"))]


def pad(options):
    return options + bytes(-len(options) % 4)


def echo_request(source, destination, options, identifier, sequence, data):
    """One complete IPv4 Echo Request with OPTIONS (EOL-padded) after the base header."""
    area = pad(options)
    assert len(area) <= 40
    message = bytearray(struct.pack("!BBHHH", 8, 0, 0, identifier, sequence) + data)
    struct.pack_into("!H", message, 2, checksum(bytes(message)))
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45 + len(area) // 4, 0, 20 + len(area) + len(message),
                                   identifier ^ sequence, 0, 64, 1, 0, socket.inet_aton(source),
                                   socket.inet_aton(destination)) + area)
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header + message)


def tlvs(area):
    """The options of an IPv4 option area: (kind, bytes) without NOP/EOL."""
    found, i = [], 0
    while i < len(area):
        kind = area[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        assert i + 1 < len(area) and 2 <= area[i + 1] <= len(area) - i, ("malformed option area", area.hex())
        found.append((kind, area[i:i + area[i + 1]]))
        i += area[i + 1]
    return found


def recorded(option, local):
    """OPTION (RR or TS) updated by one destination recording at LOCAL:
    returns the expected bytes with the timestamp left as a wildcard (None)."""
    data, pointer = bytearray(option), option[2]
    if option[0] == 7:
        if pointer + 3 <= len(option):
            data[pointer - 1:pointer + 3] = socket.inet_aton(local)
            data[2] = pointer + 4
        return bytes(data), None
    flag = option[3] & 15
    width = 8 if flag in (1, 3) else 4
    if pointer + width - 1 > len(option):
        data[3] = (((option[3] >> 4) + 1) << 4) | flag
        return bytes(data), None
    stamp = pointer - 1
    if flag == 1:
        data[stamp:stamp + 4] = socket.inet_aton(local)
        stamp += 4
    data[2] = pointer + width
    return bytes(data), stamp


def check_continuation(request, reply, local):
    """REPLY's options are REQUEST's RR/TS each recorded once at LOCAL (lengths
    and free capacity kept, the timestamp's high bit set) in their order."""
    received = [o for o in tlvs(request) if o[0] in (7, 68)]
    sent = tlvs(reply)
    assert [k for k, _ in sent] == [k for k, _ in received], ("carried RR/TS", request.hex(), reply.hex())
    stamps = []
    for (kind, before), (_, after) in zip(received, sent):
        expected, stamp = recorded(before, local)
        assert len(after) == len(before), ("length kept", before.hex(), after.hex())
        if stamp is not None:
            value = struct.unpack_from("!I", after, stamp)[0]
            assert value & 0x80000000, ("nonstandard timestamp is high-bit marked", after.hex())
            expected = expected[:stamp] + after[stamp:stamp + 4] + expected[stamp + 4:]
            stamps.append(value)
        assert after == expected, ("recorded once", before.hex(), after.hex(), expected.hex())
    return stamps


class Sender:
    """Header-included raw IPv4 output in the guarded namespace."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    def send(self, packet):
        destination = socket.inet_ntoa(packet[16:20])
        assert self.socket.sendto(packet, (destination, 0)) == len(packet)

    def close(self):
        self.socket.close()


def run_requests(requests, observed, settle):
    """Send each (name, packet, answered) and collect (request at ingress,
    reply at egress) by Echo identifier and sequence."""
    results = []
    for name, packet, answered in requests:
        identifier, sequence = struct.unpack_from("!HH", packet, (packet[0] & 15) * 4 + 4)
        start = observed.mark()
        observed.sender.send(packet)
        deadline = time.monotonic() + (REPLY_WAIT if answered else settle)
        while True:
            events = observed.since(start)
            ingress = [e for e in events if e["to_stack"] and e["icmp_type"] == 8
                       and (e["identifier"], e["sequence"]) == (identifier, sequence)]
            replies = [e for e in events if not e["to_stack"] and e["icmp_type"] == 0
                       and (e["identifier"], e["sequence"]) == (identifier, sequence)]
            if (answered and replies) or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        assert len(ingress) == 1 and ingress[0]["raw"] == packet, ("request captured unchanged at ingress", name)
        assert len(replies) == (1 if answered else 0), (name, [r["raw"].hex() for r in replies])
        results.append((name, ingress[0], replies[0] if replies else None))
    return results


def validate(event):
    """Whole-header checks of one captured IPv4 Echo message."""
    raw = event["raw"]
    hl = (raw[0] & 15) * 4
    assert raw[0] >> 4 == 4 and 20 <= hl <= len(raw) and struct.unpack_from("!H", raw, 2)[0] == len(raw), raw.hex()
    assert checksum(raw[:hl]) == 0 and checksum(raw[hl:]) == 0, ("IPv4 header and ICMP checksums", raw.hex())
    assert struct.unpack_from("!H", raw, 6)[0] & 0x3fff == 0, "whole Echo message"
    return raw[20:hl]


def evaluate(results, local, interpreted):
    """Check every reply against its request; the remote is each request's source."""
    evidence = []
    for name, request, reply in results:
        request_area = validate(request)
        item = dict(name=name, request_options=request_area.hex(), answered=reply is not None)
        if reply is not None:
            reply_area = validate(reply)
            rhl, qhl = (reply["raw"][0] & 15) * 4, (request["raw"][0] & 15) * 4
            assert reply["raw"][rhl + 4:] == request["raw"][qhl + 4:], ("identifier, sequence and data", name)
            assert reply["source"] == local, (name, reply["source"])
            remote = request["source"]
            routes = [o for o in tlvs(request_area) if o[0] in (131, 137)]
            body = reply_area
            if routes:
                kind, route = routes[0]
                hops = [socket.inet_ntoa(route[i:i + 4]) for i in range(3, len(route), 4)]
                # RFC 1122 3.2.2.6: the reversed return route, strictness
                # kept; the reply goes to its first hop.
                first = tlvs(reply_area)[0]
                rest = hops[-2::-1] + [remote]
                assert first[0] == kind and reply["destination"] == hops[-1], (name, reply_area.hex())
                assert first[1] == bytes([kind, 3 + 4 * len(rest), 4]) + b"".join(map(socket.inet_aton, rest)), (
                    name, first[1].hex())
                body = reply_area[len(first[1]):]
            else:
                assert reply["destination"] == remote, name
            if interpreted:
                item["timestamps"] = check_continuation(request_area, body, local)
            else:
                # The disabled profile declines the OPTIONAL RR/TS interpretation
                # and continuation; unknown options are never reflected either.
                assert not tlvs(body), ("no carried options", name, reply_area.hex())
            item.update(reply_options=reply_area.hex(), reply_destination=reply["destination"])
        evidence.append(item)
    return evidence


def requests(source, destination, routed_source, hop, salt, routes_admitted):
    """RR with TS (flag 1), TS (flag 0) with an unknown option, and a
    completed loose source route through HOP from ROUTED_SOURCE with RR and
    TS: answered only where source routes are admitted."""
    data = bytes((i * 13 + salt) % 251 for i in range(56))
    route = bytes([131, 7, 8]) + socket.inet_aton(hop)
    identifier = 0x7e00 + salt
    return [("rr-ts-addressed", echo_request(source, destination, RR + TS_ADDRESSED, identifier, 1, data), True),
            ("ts-times-unknown", echo_request(source, destination, TS_TIMES + bytes([30, 2]), identifier, 2, data),
             True),
            ("source-routed", echo_request(routed_source, destination, route + RR + TS_TIMES, identifier, 3, data),
             routes_admitted)]


class TunObserved:
    def __init__(self, capture, sender):
        self.capture, self.sender = capture, sender

    def mark(self):
        return self.capture.mark()

    def since(self, start):
        return [dict(e, to_stack=e["direction"] == "to-ntcp") for e in self.capture.since(start)
                if e["family"] == 4 and e["protocol"] == 1 and not e["fragmented"] and "identifier" in e]


class BridgeObserved:
    def __init__(self, bridge, sender):
        self.bridge, self.sender = bridge, sender

    def mark(self):
        return self.bridge.configure("none", None)

    def since(self, start):
        events, _ = self.bridge.snapshot(start)
        return [dict(e, to_stack=e["direction"] == "kernel-to-native", raw=bytes.fromhex(e["ip_hex"]))
                for e in events if e.get("icmp_type") is not None]


def tun_child(case, proof, binary, Peer, command):
    a = icmp.ADDRESSES[4]
    interpreted = case["scenario"] == "interpreted"
    peer = Peer(["unshare", "--net", sys.executable, "-B", icmp.HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    closes = [peer.close]
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = icmp.setup(4, 1280, command, peer.p.pid)
        capture = icmp.Capture(icmp.TUN)
        closes.append(capture.close)
        ntcp = icmp.Ntcp(binary, a["ntcp"], "refuse", {"NTCP_IPV4_OPTIONS": "1"} if interpreted else {})
        closes.insert(0, ntcp.close)
        sender = Sender()
        closes.append(sender.close)
        # The router writes from its TUN address. The source-routed request
        # comes from the peer through the router, which recorded itself: a
        # completed route whose reversal returns through the router.
        batch = requests(a["router"], a["ntcp"], a["peer"], a["router"], 1, interpreted)
        evidence = evaluate(run_requests(batch, TunObserved(capture, sender), SETTLE_WAIT), a["ntcp"], interpreted)
        return dict(case=case, settings=settings, tun_echo_settings=ntcp.settings, requests=evidence,
                    profile=dict(interpretation=interpreted, source_routes=interpreted),
                    ntcp_stderr=ntcp.since(0)[-12:])
    finally:
        cleanup(closes)


def native_child(case, proof, binary, Peer, setup):
    kernel, native = "198.18.0.1", "198.18.0.2"
    settings = setup(4, kernel, native)
    bridge = Bridge(icmp=True)
    closes = [bridge.close]
    try:
        # A listening native server starts the managed runtime, which then
        # answers Echo Requests on its owner thread.
        n = Peer([binary, "server", native, kernel, "hmac", 65536, 3_600_000_000, 1, 0])
        closes.insert(0, n.close)
        sender = Sender()
        closes.append(sender.close)
        batch = requests(kernel, native, kernel, "198.18.0.3", 2, False)
        evidence = evaluate(run_requests(batch, BridgeObserved(bridge, sender), SETTLE_WAIT), native, True)
        return dict(case=case, settings=settings, requests=evidence,
                    profile=dict(interpretation=True, source_routes=False, clock="marked elapsed (RFC 791 high bit)"))
    finally:
        cleanup(closes)


def child(case, proof, binaries, Peer, command, setup):
    if case["embedding"] == "native":
        return native_child(case, proof, binaries["native"], Peer, setup)
    return tun_child(case, proof, binaries["tun_echo"], Peer, command)


def cleanup(closes):
    primary = sys.exc_info()[0] is not None
    errors = []
    for close in closes:
        try:
            close()
        except Exception as e:
            errors.append(f"{type(e).__name__}: {e}")
    if errors and not primary:
        raise RuntimeError(errors)
