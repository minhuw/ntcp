#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Plain kernel UDP/TCP peer for the ICMP scenario, in its own network namespace."""
import hashlib
import json
import os
import socket
import struct
import sys
import time

from linux_peer import fnv, pattern

UDP_PORT = 18090
# The fragmentation-enabled sender's own port, so its requests and replies
# are distinct from the never-fragmenting socket's.
FRAGMENT_UDP_PORT = 18091
IP_MTU_DISCOVER = 10  # Linux values absent from the socket module
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_DO = 2
IPV6_MTU_DISCOVER = 23
IPV6_PMTUDISC_DONT = 0
IPV6_DONTFRAG = 62


def fragmenting(s, family):
    """Let the kernel source-fragment datagrams larger than the link MTU."""
    if family == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
    else:
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DONT)
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 0)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def ping(family, remote, size, salt, wait):
    """One ICMP Echo Request with SIZE data octets through a raw socket the
    kernel fragments; the reply must echo identifier, sequence and data."""
    v4 = family == socket.AF_INET
    s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_ICMP if v4 else socket.IPPROTO_ICMPV6)
    with s:
        fragmenting(s, family)
        identifier, sequence = (0x5100 + salt) & 0xffff, salt & 0xffff
        data = pattern(size, salt)
        message = bytearray(struct.pack("!BBHHH", 8 if v4 else 128, 0, 0, identifier, sequence) + data)
        if v4:  # the kernel computes the ICMPv6 checksum of raw ICMPv6 sockets
            struct.pack_into("!H", message, 2, checksum(bytes(message)))
        assert s.sendto(bytes(message), (remote, 0)) == len(message)
        deadline = time.monotonic() + wait
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return dict(event="ping", sent=size, salt=salt, reply=None)
            s.settimeout(left)
            try:
                packet, source = s.recvfrom(65575)
            except socket.timeout:
                continue
            # IPv4 raw sockets deliver the reassembled IP header too.
            body = packet[(packet[0] & 15) * 4:] if v4 else packet
            if source[0] != remote or len(body) < 8 or body[0] != (0 if v4 else 129):
                continue
            if struct.unpack_from("!HH", body, 4) != (identifier, sequence):
                continue
            valid = not v4 or checksum(bytes(body)) == 0
            return dict(event="ping", sent=size, salt=salt, reply=len(body) - 8, match=body[8:] == data,
                        checksum_valid=valid, identifier=identifier, sequence=sequence,
                        sha256=hashlib.sha256(body[8:]).hexdigest())


def ext_ping(remote, optname, header, size, salt, wait, source=None):
    """One ICMPv6 Echo Request carrying the Linux-originated extension
    header HEADER (RFC 3542 sticky IPV6_HOPOPTS or IPV6_DSTOPTS; the kernel
    sets its Next Header), from SOURCE when given. Returns the Echo Reply, or the first ICMPv6 error
    from REMOTE quoting this request (type, code, pointer), or neither."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, optname, header)
        if source:
            s.bind((source, 0))
        identifier, sequence = (0x5100 + salt) & 0xffff, salt & 0xffff
        data = pattern(size, salt)
        message = struct.pack("!BBHHH", 128, 0, 0, identifier, sequence) + data
        assert s.sendto(message, (remote, 0)) == len(message)
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                body, source = s.recvfrom(65575)
            except socket.timeout:
                break
            if source[0] != remote or len(body) < 8:
                continue
            if body[0] == 129 and struct.unpack_from("!HH", body, 4) == (identifier, sequence):
                return dict(event="xping", reply=len(body) - 8, match=body[8:] == data, error=None)
            # An error quotes the invoking request: its Echo identifier and
            # sequence follow the quoted base and extension headers.
            if body[0] < 128 and len(body) >= 8 + 40 + len(header) + 8:
                inner = body[8 + 40 + len(header):]
                if inner[0] == 128 and struct.unpack_from("!HH", inner, 4) == (identifier, sequence):
                    return dict(event="xping", reply=None, error=dict(
                        type=body[0], code=body[1], pointer=struct.unpack_from("!I", body, 4)[0],
                        quoted_next_header=body[8 + 6], quoted_option=body[8 + 40:8 + 40 + len(header)].hex()))
        return dict(event="xping", reply=None, error=None)


def emit(**data):
    print(json.dumps(data, sort_keys=True), flush=True)


def main():
    local, remote, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    family = socket.AF_INET6 if ":" in local else socket.AF_INET
    emit(event="ready", namespace=os.stat("/proc/self/ns/net").st_ino,
         preload=os.environ.get("LD_PRELOAD", ""))
    udp = fudp = sink = listener = None
    streams = {}
    for line in sys.stdin:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "quit":
            break
        if fields[0] == "udp":
            # One datagram, never fragmented by this sender, with a distinct
            # payload per request so every echo has a distinct quote.
            size, salt, wait = int(fields[1]), int(fields[2]), float(fields[3])
            if udp is None:
                udp = socket.socket(family, socket.SOCK_DGRAM)
                if family == socket.AF_INET:
                    udp.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
                else:
                    udp.setsockopt(socket.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
                udp.bind((local, UDP_PORT))
            request = pattern(size, salt)
            assert udp.sendto(request, (remote, port)) == size
            udp.settimeout(wait)
            try:
                reply, source = udp.recvfrom(65536)
            except socket.timeout:
                emit(event="udp", sent=size, salt=salt, reply=None)
                continue
            assert source[:2] == (remote, port), source
            emit(event="udp", sent=size, salt=salt, reply=len(reply), match=reply == request,
                 sha256=hashlib.sha256(reply).hexdigest())
        elif fields[0] == "fudp":
            # One datagram from a fragmentation-enabled socket: the kernel
            # source-fragments it when it exceeds the 1500-octet link.
            size, salt, wait = int(fields[1]), int(fields[2]), float(fields[3])
            if fudp is None:
                fudp = socket.socket(family, socket.SOCK_DGRAM)
                fragmenting(fudp, family)
                fudp.bind((local, FRAGMENT_UDP_PORT))
            request = pattern(size, salt)
            assert fudp.sendto(request, (remote, port)) == size
            fudp.settimeout(wait)
            try:
                reply, source = fudp.recvfrom(65536)
            except socket.timeout:
                emit(event="fudp", sent=size, salt=salt, reply=None)
                continue
            assert source[:2] == (remote, port), source
            emit(event="fudp", sent=size, salt=salt, reply=len(reply), match=reply == request,
                 sha256=hashlib.sha256(reply).hexdigest(), request_sha256=hashlib.sha256(request).hexdigest())
        elif fields[0] == "sink":
            # A receive-only socket for the harness datagram driver: the
            # kernel reassembles fragmented datagrams before delivering them.
            sink = socket.socket(family, socket.SOCK_DGRAM)
            sink.bind((local, int(fields[1])))
            emit(event="sinking", port=int(fields[1]))
        elif fields[0] == "drain":
            # Every complete datagram that arrives within WAIT seconds.
            deadline, received = time.monotonic() + float(fields[1]), []
            while (left := deadline - time.monotonic()) > 0:
                sink.settimeout(left)
                try:
                    data, source = sink.recvfrom(65536)
                except socket.timeout:
                    break
                received.append(dict(size=len(data), source=source[0], port=source[1],
                                     sha256=hashlib.sha256(data).hexdigest()))
            emit(event="drain", datagrams=received)
        elif fields[0] == "ping":
            emit(**ping(family, remote, int(fields[1]), int(fields[2]), float(fields[3])))
        elif fields[0] == "xping":
            # OPTNAME (54 Hop-by-Hop, 59 Destination Options) and its header.
            emit(**ext_ping(remote, int(fields[1]), bytes.fromhex(fields[2]), int(fields[3]), int(fields[4]),
                            float(fields[5])))
        elif fields[0] in ("tcp", "tcpfrom"):
            # tcpfrom: the same echo stream from another local address.
            source = fields.pop(1) if fields[0] == "tcpfrom" else local
            size, salt = int(fields[1]), int(fields[2])
            data = pattern(size, salt)
            with socket.create_connection((remote, port), timeout=25, source_address=(source, 0)) as s:
                local_port = s.getsockname()[1]
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
                received = bytearray()
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                assert received == data, f"echo mismatch {len(received)}/{size}"
            emit(event="tcp", tx=size, rx=len(received), local_port=local_port, hash=fnv(received))
        elif fields[0] == "open":
            # An established stream kept open (quiescent) after one small
            # echo, so it has real state on the ntcp side but sends nothing.
            name, size, salt = fields[1], int(fields[2]), int(fields[3])
            s = socket.create_connection((remote, port), timeout=25, source_address=(local, 0))
            streams[name] = s
            data = pattern(size, salt)
            s.sendall(data)
            received = bytearray()
            while len(received) < size:
                chunk = s.recv(size - len(received))
                assert chunk, f"echo closed {len(received)}/{size}"
                received.extend(chunk)
            assert received == data, "echo mismatch"
            emit(event="open", name=name, rx=len(received), local_port=s.getsockname()[1])
        elif fields[0] == "finish":
            name, size, salt = fields[1], int(fields[2]), int(fields[3])
            with streams.pop(name) as s:
                local_port = s.getsockname()[1]
                data = pattern(size, salt)
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
                received = bytearray()
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                assert received == data, f"echo mismatch {len(received)}/{size}"
            emit(event="finish", name=name, tx=size, rx=len(received), local_port=local_port, hash=fnv(received))
        elif fields[0] == "listen":
            # A plain receiver for the staged ntcp sender; the kernel completes
            # the handshake and receives into the backlog before accept.
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((local, int(fields[1])))
            listener.listen(1)
            listener.settimeout(25)
            emit(event="listening", port=int(fields[1]))
        elif fields[0] == "origin":
            # The destination of ntcp's originated options: a raw TCP receiver
            # (opened first) sees each segment as delivered after the kernel's
            # IP option processing, and a listener accepts ntcp's active open.
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((local, int(fields[1])))
            listener.listen(1)
            listener.settimeout(25)
            emit(event="listening", port=int(fields[1]))
        elif fields[0] == "serve":
            # Application byte progress over the accepted connection: tun_echo
            # echoes every byte and closes after this side's FIN.
            size, salt = int(fields[1]), int(fields[2])
            data = pattern(size, salt)
            s, address = listener.accept()
            with s:
                s.settimeout(25)
                s.sendall(data)
                s.shutdown(socket.SHUT_WR)
                received = bytearray()
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            listener.close()
            # Segments still in flight (the last ACK) reach the raw receiver
            # within the settle time; ntcp's are those from its address.
            packets, deadline = [], time.monotonic() + 0.5
            while (left := deadline - time.monotonic()) > 0 and len(packets) < 256:
                raw.settimeout(left)
                try:
                    packet, _ = raw.recvfrom(65535)
                except socket.timeout:
                    break
                if socket.inet_ntoa(packet[12:16]) == remote:
                    packets.append(packet.hex())
            raw.close()
            emit(event="serve", tx=size, rx=len(received), match=received == data, hash=fnv(received),
                 remote=list(address), delivered=packets)
        elif fields[0] == "collect":
            size = int(fields[1])
            s, _ = listener.accept()
            with s:
                s.settimeout(25)
                received = bytearray()
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            listener.close()
            emit(event="collect", rx=len(received), expected=size, hash=fnv(received))
        else:
            raise ValueError(fields[0])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit(event="error", errno=getattr(e, "errno", None), message=str(e))
        raise
