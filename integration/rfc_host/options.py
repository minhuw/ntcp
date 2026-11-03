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
runtime (interpretation enabled, source routes refused). Both embeddings take
time from the characterized Linux UTC provider. The interpreting profiles
answer with RR/TS carried at their lengths, updated once with this host's
address and a timestamp: a standard value is accepted only when this
harness's own read-only adjtimex reads before and after the exchange both
show a healthy kernel clock and the value lies within their window in
milliseconds since midnight UT; any other value must carry the RFC 791 high
bit. The disabled profile answers without options; refused source routes
draw no reply.

Originated cases: tun_echo's real active open (its PEER_SOCKET_ADDR) toward
a Linux listener behind the router originates RR/TS planned for this known
topology, where ntcp, the router and the destination each record once: RR
and timestamp-only TS with three slots each (15 + 16 octets, padded to 32),
or the addressed TS alone (28 octets). Addressed TS beside three RR records
(43 octets) is refused before tun_echo allocates anything. Every segment is
captured at its origin (the TUN), as the router forwards it (t9rb) and as the
destination delivers it after IP option processing (a raw TCP receiver in the
peer namespace). ntcp's origin time is judged by the bracketing rule above;
the router's and destination's times are Linux's, always standard
(inet_current_timestamp), and must lie within the exchange's realtime window.
"""
from collections import Counter
import ctypes
import json
import socket
import struct
import subprocess
import sys
import time

from bridge import Bridge, checksum
import icmp
from linux_peer import fnv, pattern

# Record Route with three slots, one already filled by an earlier hop.
RR = bytes([7, 15, 8, 198, 18, 9, 9]) + bytes(8)
# Timestamp, flag 1 (address and time), two slots, overflow 0.
TS_ADDRESSED = bytes([68, 20, 5, 1]) + bytes(16)
# Timestamp, flag 0 (time only), three slots, one filled by an earlier hop.
TS_TIMES = bytes([68, 16, 9, 0, 0, 0, 0, 5]) + bytes(8)
REPLY_WAIT = 2.0
SETTLE_WAIT = 1.0

# <sys/timex.h> status bits and states.
STA_PPSFREQ, STA_PPSTIME, STA_UNSYNC, STA_PPSSIGNAL = 0x2, 0x4, 0x40, 0x100
STA_PPSJITTER, STA_PPSWANDER, STA_PPSERROR, STA_CLOCKERR, STA_NANO = 0x200, 0x400, 0x800, 0x1000, 0x2000
TIME_OOP, TIME_ERROR = 3, 5
# Linux NTP_PHASE_LIMIT in microseconds.
MAX_ERROR_US = 16_000_000
DAY_MS = 86_400_000


class Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class Timex(ctypes.Structure):
    _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long),
                ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long), ("status", ctypes.c_int),
                ("constant", ctypes.c_long), ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
                ("time", Timeval), ("tick", ctypes.c_long), ("ppsfreq", ctypes.c_long), ("jitter", ctypes.c_long),
                ("shift", ctypes.c_int), ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long),
                ("calcnt", ctypes.c_long), ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long),
                ("tai", ctypes.c_int), ("padding", ctypes.c_int * 11)]


def healthy_time(state, status, maxerror, seconds, fraction):
    """The time of one read-only adjtimex result in nanoseconds since the
    epoch when it satisfies the UTC provider's per-sample conditions (1) and
    (2): the call succeeded, none of the kernel's is_error_status predicates
    holds, the state is neither TIME_ERROR nor TIME_OOP and the maximum error
    is within 0..=NTP_PHASE_LIMIT; otherwise None."""
    error = (status & (STA_UNSYNC | STA_CLOCKERR)
             or status & (STA_PPSFREQ | STA_PPSTIME) and not status & STA_PPSSIGNAL
             or status & (STA_PPSTIME | STA_PPSJITTER) == STA_PPSTIME | STA_PPSJITTER
             or status & STA_PPSFREQ and status & (STA_PPSWANDER | STA_PPSERROR))
    if state == -1 or error or state in (TIME_ERROR, TIME_OOP) or not 0 <= maxerror <= MAX_ERROR_US:
        return None
    return seconds * 1_000_000_000 + fraction * (1 if status & STA_NANO else 1000)


def utc_read():
    """This harness's own read-only adjtimex read of the kernel clock (modes
    0 changes nothing): its healthy time, or None."""
    tx = Timex()
    state = ctypes.CDLL(None, use_errno=True).adjtimex(ctypes.byref(tx))
    return healthy_time(state, tx.status, tx.maxerror, tx.time.tv_sec, tx.time.tv_usec)


def standard_time(value, window):
    """Whether VALUE, recorded between the reads of WINDOW (before, after),
    is a standard value: an unmarked value needs both reads healthy and must
    lie within their window in milliseconds since midnight UT (across
    midnight too); a value with the RFC 791 high bit set is nonstandard."""
    if value & 0x80000000:
        return False
    before, after = window
    assert before is not None and after is not None, ("unmarked timestamp without a healthy clock bracket", value)
    first, last = before // 1_000_000, after // 1_000_000
    assert value < DAY_MS and (value - first) % DAY_MS <= last - first, (
        "unmarked timestamp outside the UTC window", value, first % DAY_MS, last % DAY_MS)
    return True


# The originated plans for the known topology: ntcp, the router and the
# destination each record once, three expected registrations per option.
ORIGIN_SLOTS = 3
ORIGINATIONS = {"originated-combined": dict(settings=dict(NTCP_ORIGINATE_RR="3,3", NTCP_ORIGINATE_TS="times,3,3"),
                                            octets=32, kinds=[7, 68]),
                "originated-addressed": dict(settings=dict(NTCP_ORIGINATE_TS="addresses,3,3"),
                                             octets=28, kinds=[68])}
# Addressed TS beside three RR records: 15 + 28 = 43 octets, 44 padded.
OVERSIZED_ORIGINATION = dict(NTCP_ORIGINATE_RR="3,3", NTCP_ORIGINATE_TS="addresses,3,3")
OVERSIZED_REFUSAL = "IPv4 registration plan refused: CombinedCapacity { required_octets: 44, maximum: 40 }"
# The Linux listener behind the router and the bytes it sends for echo.
ORIGIN_PORT = 18083
ORIGIN_BYTES = 1024


def cases():
    return [dict(kind="ip-options", family=4, embedding=embedding, scenario=scenario)
            for embedding, scenario in (("tun_echo", "interpreted"), ("tun_echo", "uninterpreted"),
                                        ("native", "interpreted"), ("tun_echo", "originated-combined"),
                                        ("tun_echo", "originated-addressed"))]


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


def check_continuation(request, reply, local, window):
    """REPLY's options are REQUEST's RR/TS each recorded once at LOCAL (lengths
    and free capacity kept, the timestamp standard within WINDOW or marked
    nonstandard) in their order."""
    received = [o for o in tlvs(request) if o[0] in (7, 68)]
    sent = tlvs(reply)
    assert [k for k, _ in sent] == [k for k, _ in received], ("carried RR/TS", request.hex(), reply.hex())
    stamps = []
    for (kind, before), (_, after) in zip(received, sent):
        expected, stamp = recorded(before, local)
        assert len(after) == len(before), ("length kept", before.hex(), after.hex())
        if stamp is not None:
            value = struct.unpack_from("!I", after, stamp)[0]
            standard_time(value, window)
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
    reply at egress) by Echo identifier and sequence, with the kernel clock
    reads bracketing the exchange."""
    results = []
    for name, packet, answered in requests:
        identifier, sequence = struct.unpack_from("!HH", packet, (packet[0] & 15) * 4 + 4)
        start = observed.mark()
        before = utc_read()
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
        window = (before, utc_read())
        assert len(ingress) == 1 and ingress[0]["raw"] == packet, ("request captured unchanged at ingress", name)
        assert len(replies) == (1 if answered else 0), (name, [r["raw"].hex() for r in replies])
        results.append((name, ingress[0], replies[0] if replies else None, window))
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
    for name, request, reply, window in results:
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
                item["timestamps"] = check_continuation(request_area, body, local, window)
                item["clock_window"] = window
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
                    profile=dict(interpretation=True, source_routes=False, clock="characterized Linux UTC provider"))
    finally:
        cleanup(closes)


def registrations(area, octets, kinds, visits):
    """The originated RR/TS of option AREA after VISITS recording visits: the
    planned size OCTETS (options of KINDS in order, then EOL padding), each
    option's fixed ORIGIN_SLOTS length, its pointer just past VISITS
    entries, zero overflow and zero unwritten entries. Returns each kind's
    recorded addresses and times (None where the option records none)."""
    found = tlvs(area)
    used = sum(len(option) for _, option in found)
    assert len(area) == octets and [k for k, _ in found] == kinds, ("planned option area", area.hex())
    assert b"".join(o for _, o in found) == area[:used] and area[used:] == bytes(octets - used), (
        "options then EOL padding", area.hex())
    result = {}
    for kind, option in found:
        if kind == 7:
            header, width, addressed = 3, 4, True
        else:
            flag = option[3] & 15
            assert flag in (0, 1) and option[3] >> 4 == 0, ("timestamp flag and zero overflow", option.hex())
            header, width, addressed = 4, 8 if flag == 1 else 4, flag == 1
        assert len(option) == header + width * ORIGIN_SLOTS, ("fixed length", option.hex())
        assert option[2] == header + 1 + width * visits, ("pointer", visits, option.hex())
        entries = [option[header + i * width:header + (i + 1) * width] for i in range(ORIGIN_SLOTS)]
        assert all(e == bytes(width) for e in entries[visits:]), ("unwritten entries zero", option.hex())
        addresses = [socket.inet_ntoa(e[:4]) for e in entries[:visits]] if addressed else None
        assert addresses is None or "0.0.0.0" not in addresses, ("recorded address", option.hex())
        times = [struct.unpack("!I", e[-4:])[0] for e in entries[:visits]] if kind == 68 else None
        result[kind] = dict(addresses=addresses, times=times)
    return result


def judge_times(times, window, realtime):
    """TIMES recorded by ntcp, the router and the destination in turn within
    one exchange: ntcp's is standard by the bracketing rule (adjtimex WINDOW)
    or marked; Linux's carry no mark and lie within the REALTIME window
    (CLOCK_REALTIME nanoseconds) in recording order. Returns whether ntcp's
    time is standard."""
    origin, *linux = times
    standard = standard_time(origin, window)
    first, last = realtime[0] // 1_000_000, realtime[1] // 1_000_000
    offsets = [(value - first) % DAY_MS for value in ([origin] if standard else []) + linux]
    assert all(value < DAY_MS for value in linux) and all(o <= last - first for o in offsets), (
        "Linux timestamps standard within the realtime window", times, first % DAY_MS, last % DAY_MS)
    assert offsets == sorted(offsets), ("timestamps in recording order", times)
    return standard


def refuse_oversized(binary, a, target, capture):
    """tun_echo refuses an origination over the 40-octet option area at
    startup and sends nothing."""
    mark = capture.mark()
    settings = dict(NTCP_IPV4_OPTIONS="1", **OVERSIZED_ORIGINATION)
    p = subprocess.run(icmp.Ntcp.command(binary, a["ntcp"], target), env=icmp.Ntcp.environment("refuse", settings),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    # A packet sent before exit would be captured within the capture's poll.
    time.sleep(0.3)
    sent = [icmp.public(e) for e in capture.since(mark) if e["direction"] == "from-ntcp"]
    assert p.returncode != 0 and OVERSIZED_REFUSAL in p.stderr and not sent, (p.returncode, p.stderr[-2000:], sent)
    return dict(settings=settings, exit=p.returncode, refusal=OVERSIZED_REFUSAL, sent=0)


def segment(event):
    """The TCP segment of a captured IPv4 packet (forwarding keeps it)."""
    return event["raw"][event["header_len"]:event["length"]]


def trace(boundaries, plan, ntcp, destination):
    """One originated segment as ntcp sent it, as the router forwarded it and
    as the destination delivered it after its IP option processing: the
    planned area at each, recorded by one more visit each (ntcp, the router,
    the destination), earlier entries kept and every other header field kept
    except the forwarded TTL and the checksums. The wire headers' checksums
    are valid; the destination verifies its ingress checksum before recording
    and its delivered header keeps that checksum or a recomputed valid one
    (Linux keeps it for local delivery). Returns the router's recorded address per kind, the three times and the
    option areas."""
    first, hop, last = boundaries
    assert all(e["header_len"] == 20 + plan["octets"] for e in boundaries), [e["header_len"] for e in boundaries]
    assert first["ip_checksum_valid"] and hop["ip_checksum_valid"], "IPv4 header checksums on the wire"
    assert hop["raw"][8] == first["raw"][8] - 1, ("forwarded TTL", first["raw"][8], hop["raw"][8])
    for x, y, kept in ((first, hop, set(range(20)) - {8, 10, 11}), (hop, last, set(range(20)) - {10, 11})):
        assert all(x["raw"][i] == y["raw"][i] for i in kept), ("IPv4 header", x["raw"][:20].hex(), y["raw"][:20].hex())
    assert last["raw"][10:12] == hop["raw"][10:12] or last["ip_checksum_valid"], ("destination header checksum",
                                                                                  last["raw"][:20].hex())
    areas = [bytes.fromhex(e["ip_options"]) for e in boundaries]
    steps = [registrations(areas[i], plan["octets"], plan["kinds"], i + 1) for i in range(3)]
    router = {}
    for kind in plan["kinds"]:
        for key in ("addresses", "times"):
            values = [step[kind][key] for step in steps]
            assert values[0] is None or values[1][:1] == values[0] and values[2][:2] == values[1], (
                "earlier entries kept", kind, values)
        addresses = steps[2][kind]["addresses"]
        if addresses is not None:
            assert addresses[0] == ntcp and addresses[2] == destination, ("origin and destination recorded", addresses)
            router[kind] = addresses[1]
    return dict(router=router, times=steps[2][68]["times"], ttl=[e["raw"][8] for e in boundaries],
                options=[area.hex() for area in areas], destination_checksum_kept=last["raw"][10:12] == hop["raw"][10:12])


def origin_child(case, proof, binary, Peer, command):
    a = icmp.ADDRESSES[4]
    plan = ORIGINATIONS[case["scenario"]]
    peer = Peer(["unshare", "--net", sys.executable, "-B", icmp.HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    closes = [peer.close]
    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = icmp.setup(4, 1280, command, peer.p.pid)
        origin = icmp.Capture(icmp.TUN)
        closes.append(origin.close)
        forwarded = icmp.Capture("t9rb", socket.SOCK_DGRAM)
        closes.append(forwarded.close)
        target = f"{a['peer']}:{ORIGIN_PORT}"
        evidence = dict(case=case, settings=settings)
        if case["scenario"] == "originated-addressed":
            evidence.update(oversized=refuse_oversized(binary, a, target, origin))
        # The listener (and the destination's raw receiver) precede the open.
        peer.send(f"origin {ORIGIN_PORT}")
        listening = peer.read()
        assert listening["event"] == "listening", listening
        realtime, before = time.time_ns(), utc_read()
        tun_settings = dict(NTCP_IPV4_OPTIONS="1", **plan["settings"])
        ntcp = icmp.Ntcp(binary, a["ntcp"], "refuse", tun_settings, peer=target)
        closes.insert(0, ntcp.close)
        peer.send(f"serve {ORIGIN_BYTES} 41")
        served = peer.read()
        window, realtime = (before, utc_read()), (realtime, time.time_ns())
        assert served["event"] == "serve" and served["rx"] == ORIGIN_BYTES and served["match"], served
        assert served["hash"] == fnv(pattern(ORIGIN_BYTES, 41)) and served["remote"] == [a["ntcp"], icmp.PORT], served
        delivered = [icmp.parse(bytes.fromhex(h)) | dict(raw=bytes.fromhex(h)) for h in served["delivered"]]
        assert len(delivered) < 256, "raw receiver limit"
        # The router's interfaces toward ntcp (receiving) and toward the
        # destination (forwarding) and their addresses.
        route = json.loads(command(["ip", "-j", "route", "get", a["peer"], "from", a["ntcp"], "iif", icmp.TUN]))[0]
        assert route["dev"] == "t9rb", route
        interfaces = {name: [i["local"] for link in json.loads(command(["ip", "-j", "addr", "show", "dev", name]))
                             for i in link["addr_info"] if i["family"] == "inet"] for name in (icmp.TUN, route["dev"])}
        flow = (a["ntcp"], a["peer"], icmp.PORT, ORIGIN_PORT)

        def ours(events, direction=None):
            found = [e for e in events if e["family"] == 4 and e["protocol"] == 6 and not e["fragmented"]
                     and (direction is None or e["direction"] == direction)
                     and (e["source"], e["destination"], e.get("sport"), e.get("dport")) == flow]
            for e in found:
                assert e["length"] == e["captured"] and e["checksum_valid"], ("whole TCP segment", icmp.public(e))
            return found

        sent = ours(origin.since(0), "from-ntcp")
        routed = ours(forwarded.since(0), "to-ntcp")  # t9rb's router output
        received = ours(delivered)
        # The same segments, unchanged, at every boundary.
        assert sent and Counter(map(segment, sent)) == Counter(map(segment, routed)) == Counter(map(segment, received)), (
            len(sent), len(routed), len(received))
        assert sent[0]["flags"] & 0x12 == 0x02, ("the active open's SYN first", icmp.public(sent[0]))
        assert sum(e["payload"] for e in sent) >= ORIGIN_BYTES, "echoed bytes carry the options"
        recorders, segments = {}, []
        for first in sent:
            hop = next(e for e in routed if segment(e) == segment(first))
            routed.remove(hop)
            last = next(e for e in received if segment(e) == segment(hop))
            received.remove(last)
            result = trace((first, hop, last), plan, a["ntcp"], a["peer"])
            for kind, address in result["router"].items():
                # RFC 791: Record Route records the address of the interface
                # the datagram is forwarded on; Linux's addressed Timestamp
                # records the address it selects toward the source.
                names = [n for n, owned in interfaces.items() if address in owned]
                assert names and (kind != 7 or names == [route["dev"]]), ("router address", kind, address, interfaces)
                assert recorders.setdefault(kind, dict(address=address, interface=names[0]))["address"] == address
            standard = judge_times(result["times"], window, realtime)
            segments.append(dict(result, flags=first["flags"], payload=first["payload"], ntcp_standard=standard))
        origination = ntcp.wait(r"IPv4 origination toward .*", 0, 1).group(0)
        evidence.update(tun_echo_settings=ntcp.settings, origination=origination,
                        plan=dict(octets=plan["octets"], kinds=plan["kinds"], slots=ORIGIN_SLOTS),
                        stream=dict(served, delivered=len(delivered)), segments=segments[:32], router_route=route,
                        router_recorded=recorders, router_interfaces=interfaces, destination_recorded=a["peer"],
                        clock_window=window, realtime_window=realtime, ntcp_stderr=ntcp.since(0)[-12:])
        return evidence
    finally:
        cleanup(closes)


def child(case, proof, binaries, Peer, command, setup):
    if case["embedding"] == "native":
        return native_child(case, proof, binaries["native"], Peer, setup)
    if case["scenario"] in ORIGINATIONS:
        return origin_child(case, proof, binaries["tun_echo"], Peer, command)
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
