# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Bounded Ethernet fault network. It has no TCP endpoint or response state."""
import hashlib
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


def decode(frame):
    if len(frame) < 14:
        return None
    eth = struct.unpack_from("!H", frame, 12)[0]
    if eth == 0x800:
        assert len(frame) >= 34 and frame[14] == 0x45, "unsupported IPv4 framing"
        end = 14 + struct.unpack_from("!H", frame, 16)[0]
        assert end <= len(frame) and checksum(frame[14:34]) == 0, "IPv4 checksum/length"
        if frame[23] != 6:
            return None
        assert struct.unpack_from("!H", frame, 20)[0] & 0x3fff == 0, "unexpected fragments"
        start = 34
        pseudo = frame[26:34] + b"\0\x06" + struct.pack("!H", end - start)
        family = 4
        ip = dict(df=bool(struct.unpack_from("!H", frame, 20)[0] & 0x4000),
                  ip_id=struct.unpack_from("!H", frame, 18)[0])
    elif eth == 0x86dd:
        assert len(frame) >= 54 and frame[14] >> 4 == 6, "IPv6 framing"
        end = 54 + struct.unpack_from("!H", frame, 18)[0]
        assert end <= len(frame), "IPv6 length"
        if frame[20] != 6:
            return None
        start = 54
        pseudo = frame[22:54] + struct.pack("!I", end - start) + b"\0\0\0\x06"
        family = 6
        ip = dict(df=None, ip_id=None)
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
    def __init__(self):
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
                    decoded = decode(frame)
                    if decoded is None:
                        continue  # only configured TCP needs forwarding; static neighbors
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
