#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Plain kernel peer of the scoped link-local cases (T18).

Every socket names its link: a link-local address is bound and connected
with the interface index of INTERFACES as its scope (sin6_scope_id), and the
names it reports carry the scope the kernel returns. Run as
scoped_peer.py LOCAL INTERFACE..., then on stdin:
  listen PORT                    on every interface bind [LOCAL%if]:PORT, listen
  serve N M SALT...              accept one connection per listener (each in
                                 its own thread), read N bytes of that link's
                                 SALT pattern, answer M (SALT + 100), close
                                 after EOF
  pair LPORT REMOTE RPORT N M SALT...
                                 on every interface connect from
                                 [LOCAL%if]:LPORT to [REMOTE%if]:RPORT, all
                                 established before any data, then (one
                                 thread each) send N, read M, shut down, EOF
  echo REMOTE PORT N SALT        a TCP stream to a TCP echo on the first
                                 interface: send N, shut down, read the echo
  udp REMOTE PORT N SALT         one datagram to a UDP echo on the first
                                 interface and its reply
  originate N SALT               accept the active open on the first
                                 listener, send N, shut down, read the echo
  quit
Run as scoped_peer.py inject INTERFACE HEX, it sends one Ethernet frame on
INTERFACE instead (beside a peer busy serving).
"""
import hashlib
import json
import os
import socket
import sys
import threading

from linux_peer import fnv, pattern

TIMEOUT = 25


def emit(**data):
    print(json.dumps(data, sort_keys=True), flush=True)


def name(address):
    """A scoped socket address as (address, port, scope_id)."""
    return dict(address=address[0].split("%")[0], port=address[1], scope_id=address[3])


def describe(s, index):
    info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    return dict(index=index, local=name(s.getsockname()), peer=name(s.getpeername()), tcp_state=info[0],
                snd_mss=int.from_bytes(info[16:20], sys.byteorder), pmtu=int.from_bytes(info[60:64], sys.byteorder))


def receive(s, n):
    data = bytearray()
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise RuntimeError(f"short stream {len(data)}/{n}")
        data.extend(chunk)
    return bytes(data)


def to_eof(s):
    data = bytearray()
    while chunk := s.recv(65536):
        data.extend(chunk)
    return bytes(data)


def threaded(work, items):
    """WORK(item) for every item concurrently; results in item order."""
    results, errors = [None] * len(items), []

    def run(i, item):
        try:
            results[i] = work(item)
        except Exception as e:
            errors.append(f"{type(e).__name__}: {e}")
    threads = [threading.Thread(target=run, args=(i, item)) for i, item in enumerate(items)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(TIMEOUT + 5)
    assert not errors and all(t is not None for t in results), errors
    return results


def inject(interface, frame):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind((interface, 0))
        assert s.send(frame) == len(frame)
    emit(event="injected", interface=interface, length=len(frame), sha256=hashlib.sha256(frame).hexdigest(),
         namespace=os.stat("/proc/self/ns/net").st_ino)


def main():
    if sys.argv[1] == "inject":
        return inject(sys.argv[2], bytes.fromhex(sys.argv[3]))
    local, interfaces = sys.argv[1], sys.argv[2:]
    emit(event="ready", namespace=os.stat("/proc/self/ns/net").st_ino, preload=os.environ.get("LD_PRELOAD", ""))
    listeners = []
    for line in sys.stdin:
        fields = line.split()
        if not fields:
            continue
        indexes = [socket.if_nametoindex(i) for i in interfaces]
        if fields[0] == "quit":
            break
        if fields[0] == "listen":
            port = int(fields[1])
            for index in indexes:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.bind((local, port, 0, index))
                s.listen(4)
                s.settimeout(TIMEOUT)
                listeners.append((s, index))
            emit(event="listening", sockets=[dict(index=i, local=name(s.getsockname())) for s, i in listeners])
        elif fields[0] == "serve":
            n, m, salts = int(fields[1]), int(fields[2]), list(map(int, fields[3:]))
            assert len(salts) == len(listeners), "one salt per listener"

            def serve(item):
                (listener, index), salt = item
                s, _ = listener.accept()
                with s:
                    s.settimeout(TIMEOUT)
                    accepted = describe(s, index)
                    request = receive(s, n)
                    assert request == pattern(n, salt), "request mismatch"
                    s.sendall(pattern(m, salt + 100))
                    assert s.recv(1) == b"", "unexpected request bytes"
                    done = describe(s, index)
                return dict(accepted=accepted, done=done, rx=n, tx=m, request_hash=fnv(request), salt=salt)
            emit(event="served", connections=threaded(serve, list(zip(listeners, salts))))
        elif fields[0] == "pair":
            lport, remote, rport = int(fields[1]), fields[2], int(fields[3])
            n, m, salts = int(fields[4]), int(fields[5]), list(map(int, fields[6:]))
            assert len(salts) == len(indexes), "one salt per interface"
            sockets = []
            try:
                for index in indexes:
                    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sockets.append(s)
                    s.settimeout(TIMEOUT)
                    s.bind((local, lport, 0, index))
                    s.connect((remote, rport, 0, index))
                established = [describe(s, i) for s, i in zip(sockets, indexes)]

                def run(item):
                    s, index, salt = item
                    s.sendall(pattern(n, salt))
                    response = receive(s, m)
                    assert response == pattern(m, salt + 100), "response mismatch"
                    # Described while connected: the closed socket has no peer.
                    done = describe(s, index)
                    s.shutdown(socket.SHUT_WR)
                    assert s.recv(1) == b"", "unexpected response bytes"
                    return dict(done=done, response_hash=fnv(response))
                done = threaded(run, list(zip(sockets, indexes, salts)))
            finally:
                for s in sockets:
                    s.close()
            emit(event="paired", connections=[dict(established=e, tx=n, rx=m, salt=salt, **d)
                                              for e, d, salt in zip(established, done, salts)])
        elif fields[0] == "echo":
            remote, port, n, salt = fields[1], int(fields[2]), int(fields[3]), int(fields[4])
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.bind((local, 0, 0, indexes[0]))
                s.connect((remote, port, 0, indexes[0]))
                established = describe(s, indexes[0])
                s.sendall(pattern(n, salt))
                s.shutdown(socket.SHUT_WR)
                received = to_eof(s)
            assert received == pattern(n, salt), f"echo mismatch {len(received)}/{n}"
            emit(event="echo", established=established, tx=n, rx=len(received), hash=fnv(received))
        elif fields[0] == "udp":
            remote, port, n, salt = fields[1], int(fields[2]), int(fields[3]), int(fields[4])
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                s.bind((local, 0, 0, indexes[0]))
                request = pattern(n, salt)
                assert s.sendto(request, (remote, port, 0, indexes[0])) == n
                reply, source = s.recvfrom(65536)
                sent_from = name(s.getsockname())
            assert reply == request, "UDP echo mismatch"
            emit(event="udp", local=sent_from, source=name(source), tx=n, rx=len(reply),
                 sha256=hashlib.sha256(reply).hexdigest())
        elif fields[0] == "originate":
            n, salt = int(fields[1]), int(fields[2])
            listener, index = listeners[0]
            s, _ = listener.accept()
            with s:
                s.settimeout(TIMEOUT)
                accepted = describe(s, index)
                s.sendall(pattern(n, salt))
                s.shutdown(socket.SHUT_WR)
                received = to_eof(s)
            assert received == pattern(n, salt), f"echo mismatch {len(received)}/{n}"
            emit(event="originated", accepted=accepted, tx=n, rx=len(received), hash=fnv(received))
        else:
            raise ValueError(fields[0])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit(event="error", errno=getattr(e, "errno", None), message=str(e))
        raise
