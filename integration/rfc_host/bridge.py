# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Bounded Ethernet fault network. It has no TCP endpoint or response state."""
import hashlib
import ipaddress
import selectors
import socket
import struct
import threading
import time


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


# RFC 8200 section 4: Hop-by-Hop Options, Routing, Fragment and Destination
# Options are the extension headers these captures walk.
EXTENSIONS = (0, 43, 44, 60)


def ipv6_chain(ip, end, strict=True):
    """Walk the extension headers of the IPv6 packet IP (bytes from its base
    header; END its declared end) in wire order. Returns (headers, protocol,
    offset, final, fragment): each header's type, offset and length (Routing
    headers with their type-specific fields, options as hex), the terminal
    Next Header and the offset after the chain, the 16-octet final
    destination a transport pseudo-header uses (RFC 8200 section 8.1: the
    last element of a Routing header whose Segments Left is nonzero, which
    for a Segment Routing Header is Segment List[0], RFC 8754 section 2),
    and the Fragment header's fields. The walk stops after a Fragment header
    (later fragments are opaque until reassembly). STRICT asserts complete
    bounds; otherwise (a truncated ICMP quote) it stops at the first header
    the bytes do not hold and reports protocol None."""
    end = min(end, len(ip)) if not strict else end
    assert not strict or end <= len(ip), "IPv6 length"
    protocol, offset, final = ip[6], 40, bytes(ip[24:40])
    headers, fragment = [], None
    while protocol in EXTENSIONS and fragment is None:
        if offset + 8 > end:
            assert not strict, "truncated extension header"
            return headers, None, offset, final, fragment
        length = 8 if protocol == 44 else (ip[offset + 1] + 1) * 8
        if offset + length > end:
            assert not strict, "extension header length"
            return headers, None, offset, final, fragment
        header = dict(type=protocol, offset=offset, length=length)
        if protocol == 43:
            kind, left = ip[offset + 2], ip[offset + 3]
            header.update(routing_type=kind, segments_left=left)
            if kind == 4:
                last = ip[offset + 4]
                assert 2 * (last + 1) <= ip[offset + 1] and left <= last + 1, "Segment Routing Header bounds"
                segments = [bytes(ip[offset + 8 + 16 * i:offset + 24 + 16 * i]) for i in range(last + 1)]
                header.update(last_entry=last, flags=ip[offset + 5], tag=struct.unpack_from("!H", ip, offset + 6)[0],
                              segments=[str(ipaddress.ip_address(a)) for a in segments])
                if left:
                    final = segments[0]
            elif kind == 0 and left:
                count = ip[offset + 1] // 2
                final = bytes(ip[offset + 8 + 16 * (count - 1):offset + 8 + 16 * count])
        elif protocol == 44:
            field = struct.unpack_from("!H", ip, offset + 2)[0]
            fragment = dict(ident=struct.unpack_from("!I", ip, offset + 4)[0], offset=field & 0xfff8,
                            more=bool(field & 1), inner=ip[offset])
        else:
            header["options"] = bytes(ip[offset + 2:offset + length]).hex()
        headers.append(header)
        protocol = ip[offset]
        offset += length
    return headers, protocol, offset, final, fragment


def decode_icmp6(frame, end, headers, offset, final):
    """A whole ICMPv6 message behind its complete header chain (JSON-safe),
    its checksum validated over the final destination."""
    ip = frame[14:end]
    body = ip[offset:]
    pseudo = ip[8:24] + final + struct.pack("!I", len(body)) + b"\0\0\0\x3a"
    assert len(body) >= 8 and checksum(pseudo + body) == 0, "ICMPv6 checksum"
    event = dict(family=6, protocol=58, ethernet_length=len(frame), ip_length=end - 14, header_len=offset,
                 extensions=headers, ip_hex=ip.hex(), source=str(ipaddress.ip_address(ip[8:24])),
                 destination=str(ipaddress.ip_address(ip[24:40])),
                 final_destination=str(ipaddress.ip_address(final)), icmp_type=body[0], icmp_code=body[1],
                 sha256=hashlib.sha256(ip).hexdigest(), checksum_valid=True)
    if body[0] in (128, 129):
        event.update(identifier=struct.unpack_from("!H", body, 4)[0], sequence=struct.unpack_from("!H", body, 6)[0])
    elif body[0] in (1, 2, 3, 4):
        event.update(word=struct.unpack_from("!I", body, 4)[0], quote_hex=body[8:].hex())
    return event


def decode_icmp(frame, hl, end):
    """A whole IPv4 ICMP message with its complete header, options included
    (JSON-safe: hex), for the option cases' forwarding and capture."""
    ip = frame[14:end]
    assert struct.unpack_from("!H", ip, 6)[0] & 0x3fff == 0, "unexpected fragments"
    assert end - 14 - hl >= 8 and checksum(ip[hl:]) == 0, "ICMP checksum"
    event = dict(family=4, protocol=1, ethernet_length=len(frame), ip_length=end - 14, header_len=hl,
                 ip_options=ip[20:hl].hex(), ip_hex=ip.hex(), source=socket.inet_ntoa(ip[12:16]),
                 destination=socket.inet_ntoa(ip[16:20]), icmp_type=ip[hl], icmp_code=ip[hl + 1],
                 df=bool(struct.unpack_from("!H", ip, 6)[0] & 0x4000), ip_id=struct.unpack_from("!H", ip, 4)[0],
                 sha256=hashlib.sha256(ip).hexdigest(), checksum_valid=True)
    if ip[hl] in (0, 8):
        event.update(identifier=struct.unpack_from("!H", ip, hl + 4)[0],
                     sequence=struct.unpack_from("!H", ip, hl + 6)[0])
    return event


def decode(frame, icmp=False):
    """A TCP segment (or, with ICMP, a whole IPv4 ICMP message) of FRAME;
    None for anything else. IPv4 headers of any valid IHL are checked whole."""
    if len(frame) < 14:
        return None
    eth = struct.unpack_from("!H", frame, 12)[0]
    if eth == 0x800:
        assert len(frame) >= 34 and frame[14] >> 4 == 4, "unsupported IPv4 framing"
        hl = (frame[14] & 15) * 4
        end = 14 + struct.unpack_from("!H", frame, 16)[0]
        assert 20 <= hl and 14 + hl <= end <= len(frame), "IPv4 header/total length"
        assert checksum(frame[14:14 + hl]) == 0, "IPv4 header checksum"
        if icmp and frame[23] == 1:
            return decode_icmp(frame, hl, end)
        if frame[23] != 6:
            return None
        assert struct.unpack_from("!H", frame, 20)[0] & 0x3fff == 0, "unexpected fragments"
        start = 14 + hl
        pseudo = frame[26:34] + b"\0\x06" + struct.pack("!H", end - start)
        family = 4
        ip = dict(df=bool(struct.unpack_from("!H", frame, 20)[0] & 0x4000),
                  ip_id=struct.unpack_from("!H", frame, 18)[0])
    elif eth == 0x86dd:
        assert len(frame) >= 54 and frame[14] >> 4 == 6, "IPv6 framing"
        end = 54 + struct.unpack_from("!H", frame, 18)[0]
        assert end <= len(frame), "IPv6 length"
        headers, protocol, offset, final, fragment = ipv6_chain(frame[14:end], end - 14)
        if fragment is not None:
            return None  # no IPv6 fragments are forwarded, as before
        if icmp and protocol == 58:
            return decode_icmp6(frame, end, headers, offset, final)
        if protocol != 6:
            return None
        start = 14 + offset
        # The TCP checksum covers the final destination (RFC 8200 8.1).
        pseudo = frame[22:38] + final + struct.pack("!I", end - start) + b"\0\0\0\x06"
        family = 6
        ip = dict(df=None, ip_id=None, extensions=headers, destination=str(ipaddress.ip_address(frame[38:54])),
                  final_destination=str(ipaddress.ip_address(final)))
    else:
        return None
    assert end - start >= 20, "short TCP"
    offset = (frame[start + 12] >> 4) * 4
    assert 20 <= offset <= end - start, "TCP data offset"
    assert checksum(pseudo + frame[start:end]) == 0, "TCP checksum"
    options, cookies = [], []
    i = start + 20
    while i < start + offset:
        kind = frame[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        assert i + 1 < start + offset, "truncated option"
        n = frame[i + 1]
        assert n >= 2 and i + n <= start + offset, "option length"
        options.append((kind, i, n))
        if kind == 34:
            cookies.append(frame[i + 2:i + n].hex())
        i += n
    sport, dport, seq, ack = struct.unpack_from("!HHII", frame, start)
    window_scale = next((frame[i + 2] for kind, i, n in options if kind == 3 and n == 3), None)
    mss = next((struct.unpack_from("!H", frame, i + 2)[0] for kind, i, n in options if kind == 2 and n == 4), None)
    event = dict(family=family, ethernet_length=len(frame), sport=sport, dport=dport, seq=seq, ack=ack, window_scale=window_scale, mss=mss,
                 flags=frame[start + 13], window=struct.unpack_from("!H", frame, start + 14)[0],
                 payload=end - start - offset, tcp_header_length=offset, cookie=cookies, length=end,
                 sha256=hashlib.sha256(frame[:end]).hexdigest(), checksum_valid=True,
                 ip_length=end - 14, **ip)
    return event, options, start, end, pseudo


class Bridge:
    """Forwards TCP between the two ports; with ICMP, whole ICMP messages
    too (IPv4 for the option cases, ICMPv6 for the Segment Routing case),
    recorded but never altered. IPv6 extension headers are walked: TCP and
    ICMPv6 behind them are forwarded with checksums over the final
    destination."""

    def __init__(self, icmp=False):
        self.icmp = icmp
        self.selector = selectors.DefaultSelector()
        self.sockets = []
        for name in ("t5bk", "t5bn"):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.bind((name, 0))
            s.setblocking(False)
            self.sockets.append(s)
            self.selector.register(s, selectors.EVENT_READ)
        self.events = []
        self.error = None
        self.fault = "none"
        self.fault_direction = None
        self.fault_count = 0
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.bytes = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def configure(self, fault, direction):
        with self.lock:
            self.fault, self.fault_direction, self.fault_count = fault, direction, 0
            return len(self.events)

    def snapshot(self, start):
        with self.lock:
            if self.error:
                raise RuntimeError(self.error)
            return list(self.events[start:]), self.fault_count

    def run(self):
        try:
            while not self.stop.is_set():
                for key, _ in self.selector.select(0.1):
                    s = key.fileobj
                    frame, addr = s.recvfrom(65536)
                    if addr[2] == socket.PACKET_OUTGOING:
                        continue
                    direction = "kernel-to-native" if s is self.sockets[0] else "native-to-kernel"
                    decoded = decode(frame, self.icmp)
                    if decoded is None:
                        continue  # only configured TCP (and ICMP) needs forwarding; static neighbors
                    if isinstance(decoded, dict):
                        with self.lock:
                            self.bytes += len(frame)
                            assert len(self.events) < 20000 and self.bytes < 32 * 1024 * 1024, "capture limit"
                            decoded.update(direction=direction, time_ns=time.monotonic_ns(), action="forward")
                            self.events.append(decoded)
                        target = self.sockets[1] if s is self.sockets[0] else self.sockets[0]
                        assert target.send(frame) == len(frame), "short forwarding send"
                        continue
                    event, options, tcp, end, pseudo = decoded
                    with self.lock:
                        self.bytes += len(frame)
                        assert len(self.events) < 20000 and self.bytes < 32 * 1024 * 1024, "capture limit"
                        event.update(direction=direction, time_ns=time.monotonic_ns(), action="forward")
                        if event["flags"] & 2:
                            event["raw"] = frame.hex()
                        # Match an actually received, submitted first data SYN.
                        if (self.fault_count == 0 and direction == self.fault_direction
                                and event["flags"] & 0x12 == 2 and event["payload"] > 0
                                and self.fault != "none"):
                            if self.fault == "drop":
                                event["action"] = "drop"
                            elif self.fault == "strip":
                                targets = [(i, n) for kind, i, n in options if kind == 34]
                                assert targets, "no framed Kind34 in selected data SYN"
                                altered = bytearray(frame)
                                for i, n in targets:
                                    altered[i:i+n] = b"\x01" * n
                                altered[tcp + 16:tcp + 18] = b"\0\0"
                                struct.pack_into("!H", altered, tcp + 16, checksum(pseudo + altered[tcp:end]))
                                frame = bytes(altered)
                                outgoing = decode(frame)[0]
                                for field in ("payload", "length", "ethernet_length", "tcp_header_length", "seq", "ack", "window", "flags"):
                                    assert outgoing[field] == event[field], (field, event, outgoing)
                                assert not outgoing["cookie"], "Kind34 survived stripping"
                                event.update(action="strip", egress=outgoing, egress_raw=frame.hex())
                            else:
                                raise AssertionError("unknown fault")
                            self.fault_count += 1
                        self.events.append(event)
                        if event["action"] != "drop":
                            target = self.sockets[1] if s is self.sockets[0] else self.sockets[0]
                            assert target.send(frame) == len(frame), "short forwarding send"
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"

    def close(self):
        self.stop.set()
        self.thread.join(2)
        for s in self.sockets:
            s.close()
        self.selector.close()
