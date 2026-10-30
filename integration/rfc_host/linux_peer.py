#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Plain kernel peer: no preload, managed library, or synthetic TCP replies."""
import errno
import json
import os
import socket
import sys


def pattern(n, salt):
    return bytes((i * 31 + salt) % 251 for i in range(n))


def fnv(data):
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & ((1 << 64) - 1)
    return f"{h:016x}"


def emit(**data):
    print(json.dumps(data, sort_keys=True), flush=True)


def read_exact(s, n, salt):
    data = bytearray()
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise RuntimeError(f"short stream {len(data)}/{n}")
        data.extend(chunk)
    assert data == pattern(n, salt), "stream mismatch"
    return fnv(data)


def main():
    role, local, peer, disabled = sys.argv[1:]
    disabled = disabled == "1"
    family = socket.AF_INET6 if ":" in local else socket.AF_INET
    listener = None
    if role == "server":
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.settimeout(25)
        if not disabled:
            listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 16)
        listener.bind((local, 18080))
        listener.listen(16)
    emit(event="ready", role=role, backend="Linux", preload=os.environ.get("LD_PRELOAD", ""))
    for line in sys.stdin:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "quit":
            break
        if fields[0] == "rotate":
            assert listener is not None
            listener.setsockopt(socket.IPPROTO_TCP, 33, os.urandom(16))  # TCP_FASTOPEN_KEY
            emit(event="rotated", mechanism="TCP_FASTOPEN_KEY", secret_logged=False)
            continue
        if listener:
            s, _ = listener.accept()
            with s:
                s.settimeout(25)
                info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                first = read_exact(s, 8192, 7)
                s.sendall(pattern(6144, 11))
                second = read_exact(s, 3072, 19)
                assert s.recv(1) == b"", "duplicate/unexpected request bytes"
                s.sendall(pattern(1024, 23))
                s.shutdown(socket.SHUT_WR)
                emit(event="stream", rx=11264, tx=7168, first_hash=first,
                     second_hash=second, accept_state=info[0], tcp_options=info[5], eof=True)
        else:
            mode = fields[0]
            nonblock = fields[1] == "nonblock"
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(25)
                if nonblock:
                    s.setblocking(False)
                sent, initial_errno, option_errno, result, stage = 0, 0, 0, 0, mode
                try:
                    if mode == "msg":
                        sent = s.sendto(pattern(8192, 7), socket.MSG_FASTOPEN, (peer, 18080))
                        result = sent
                    else:
                        if mode == "deferred":
                            try:
                                s.setsockopt(socket.IPPROTO_TCP, 30, 1)
                            except OSError as e:
                                if e.errno != errno.EOPNOTSUPP:
                                    raise
                                option_errno = e.errno
                                stage = "TCP_FASTOPEN_CONNECT-disabled-then-connect"
                        s.connect((peer, 18080))
                except OSError as e:
                    initial_errno, result = e.errno, -1
                    if e.errno == errno.EOPNOTSUPP and mode == "msg":
                        stage = "MSG_FASTOPEN-disabled-then-connect"
                        s.settimeout(25)
                        s.connect((peer, 18080))
                    elif e.errno not in (errno.EINPROGRESS, errno.EAGAIN):
                        raise
                s.settimeout(25)
                # The first write triggers a cached deferred open, and resumes
                # a nonblocking cold MSG_FASTOPEN that returned EINPROGRESS.
                s.sendall(pattern(8192, 7)[sent:])
                first = read_exact(s, 6144, 11)
                s.sendall(pattern(3072, 19))
                s.shutdown(socket.SHUT_WR)
                second = read_exact(s, 1024, 23)
                assert s.recv(1) == b"", "duplicate/unexpected response bytes"
                info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                emit(event="stream", tx=11264, rx=7168, first_hash=first, second_hash=second,
                     initial_result=result, initial_errno=initial_errno, option_errno=option_errno, stage=stage,
                     tcp_state=info[0], tcp_options=info[5], eof=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit(event="error", errno=getattr(e, "errno", None), message=str(e))
        raise
