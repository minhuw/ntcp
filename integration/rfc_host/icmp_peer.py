#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Plain kernel UDP/TCP peer for the ICMP scenario, in its own network namespace."""
import hashlib
import json
import os
import socket
import sys

from linux_peer import fnv, pattern

UDP_PORT = 18090
IP_MTU_DISCOVER = 10  # Linux values absent from the socket module
IP_PMTUDISC_DO = 2
IPV6_DONTFRAG = 62


def emit(**data):
    print(json.dumps(data, sort_keys=True), flush=True)


def main():
    local, remote, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    family = socket.AF_INET6 if ":" in local else socket.AF_INET
    emit(event="ready", namespace=os.stat("/proc/self/ns/net").st_ino,
         preload=os.environ.get("LD_PRELOAD", ""))
    udp = None
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
        elif fields[0] == "tcp":
            size, salt = int(fields[1]), int(fields[2])
            data = pattern(size, salt)
            with socket.create_connection((remote, port), timeout=25, source_address=(local, 0)) as s:
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
        else:
            raise ValueError(fields[0])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit(event="error", errno=getattr(e, "errno", None), message=str(e))
        raise
