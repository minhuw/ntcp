#!/usr/bin/env python3
"""Exercise native ARP against Linux over a veth pair in a private net namespace.

Neither side has a static neighbour: Linux resolves the native port's MAC and
the native port resolves Linux's, each by ARP."""
import concurrent.futures
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[4]
KERNEL, NATIVE, PREFIX = '10.74.0.1', '10.74.0.2', '24'


def cmd(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def counters(line):
    if not line.startswith('COUNTERS '):
        raise AssertionError('no counters: ' + line)
    return {k: int(v) for k, v in (item.split('=') for item in line.split()[1:])}


def neighbours():
    out = subprocess.run(['ip', '-j', '-4', 'neigh', 'show', 'dev', 'k0'], check=True,
                         stdout=subprocess.PIPE, text=True).stdout
    return json.loads(out or '[]')


def inside(binary, parent_namespace):
    if os.readlink('/proc/self/ns/net') == parent_namespace:
        raise RuntimeError('independent network namespace required before setup')
    cmd('ip', 'link', 'set', 'lo', 'up')
    cmd('ip', 'link', 'add', 'k0', 'type', 'veth', 'peer', 'name', 'n0')
    # Complete checksums on the wire, as the other veth cases in this tree
    # arrange: the native port does not take partially checksummed frames.
    for name in ('k0', 'n0'):
        cmd('ethtool', '-K', name, 'tx', 'off', 'rx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')
    cmd('ip', 'link', 'set', 'k0', 'up')
    cmd('ip', 'link', 'set', 'n0', 'up')
    cmd('ip', 'addr', 'add', KERNEL + '/' + PREFIX, 'dev', 'k0')
    link = json.loads(subprocess.run(['ip', '-j', 'link', 'show', 'n0'], check=True,
                                     stdout=subprocess.PIPE, text=True).stdout)
    mac = link[0]['address']
    # No permanent neighbour anywhere.
    permanent = subprocess.run(['ip', 'neigh', 'show', 'nud', 'permanent'], check=True,
                               stdout=subprocess.PIPE, text=True).stdout.strip()
    assert not permanent, permanent
    process = subprocess.Popen([binary, 'n0', mac, NATIVE + '/' + PREFIX, 'server', '9000', '8'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError('native ARP example did not become ready')
            line = process.stdout.readline()
        if not line.startswith('READY '):
            raise RuntimeError('native startup failed: ' + line + process.stderr.read())

        def exchange(seed):
            payload = bytes((i + seed) % 251 for i in range(131072))
            with socket.create_connection((NATIVE, 9000), timeout=10) as client:
                errors = []

                def send():
                    try:
                        client.sendall(payload)
                        client.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        errors.append(error)
                sender = threading.Thread(target=send)
                sender.start()
                received = bytearray()
                while data := client.recv(32768):
                    received.extend(data)
                sender.join(10)
                if errors:
                    raise errors[0]
                assert received == payload, f'{len(received)}/{len(payload)} bytes'
                return len(received)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as clients:
            verified = sum(clients.map(exchange, range(4)))
        entries = [e for e in neighbours() if e.get('dst') == NATIVE]
        stdout, stderr = process.communicate(timeout=20)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    if process.returncode != 0:
        raise RuntimeError('native server failed: ' + stderr)
    server = counters(stdout.strip().splitlines()[-1])
    # Linux resolved the native MAC dynamically.
    assert len(entries) == 1 and entries[0].get('lladdr') == mac, entries
    states = entries[0].get('state', [])
    assert 'PERMANENT' not in states and set(states) & {'REACHABLE', 'STALE', 'DELAY', 'PROBE'}, states
    # Linux's request was received and answered.
    assert server['arp_received'] >= 1 and server['arp_sent'] >= 1, server
    print(json.dumps({'native_role': 'server', 'connections': 4, 'verified_bytes': verified,
                      'kernel_neighbour': {'lladdr': mac, 'state': states}, 'native_counters': server,
                      'result': 'passed'}), flush=True)

    # The native client resolves Linux's address itself; Linux forgets the
    # native port first, so it learns it again from the native request.
    cmd('ip', 'neigh', 'flush', 'dev', 'k0')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(15)
        listener.bind((KERNEL, 9001))
        listener.listen(1)

        def echo():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(15)
                count = 0
                while data := connection.recv(32768):
                    connection.sendall(data)
                    count += len(data)
                connection.shutdown(socket.SHUT_WR)
                return count
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as servers:
            pending = servers.submit(echo)
            completed = subprocess.run([binary, 'n0', mac, NATIVE + '/' + PREFIX, 'client', KERNEL, '9001'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            if completed.returncode:
                raise RuntimeError('native client failed: ' + completed.stderr)
            lines = completed.stdout.strip().splitlines()
            assert lines[0] == 'ROUNDTRIP 65536', lines
            verified = pending.result(timeout=15)
    client = counters(lines[1])
    # The native request for Linux's address was sent and its reply received.
    assert client['arp_sent'] >= 1 and client['arp_received'] >= 1, client
    entries = [e for e in neighbours() if e.get('dst') == NATIVE]
    assert len(entries) == 1 and entries[0].get('lladdr') == mac, entries
    assert 'PERMANENT' not in entries[0].get('state', []), entries
    print(json.dumps({'native_role': 'client', 'verified_bytes': verified, 'native_counters': client,
                      'kernel_neighbour': {'lladdr': mac, 'state': entries[0].get('state')},
                      'result': 'passed'}), flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside(*sys.argv[2:])
    else:
        build = subprocess.run(['cargo', 'build', '--manifest-path', str(ROOT / 'Cargo.toml'), '-p', 'ntcp-native',
                                '--example', 'arp_echo', '--message-format=json'],
                               cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True)
        artifacts = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = {a.get('target', {}).get('name'): a['executable'] for a in artifacts
                    if a.get('reason') == 'compiler-artifact' and a.get('executable')}
        assert 'arp_echo' in binaries, binaries
        parent = os.readlink('/proc/self/ns/net')
        # An unprivileged user namespace grants CAP_NET_ADMIN and CAP_NET_RAW
        # over its own network namespace: veth setup and AF_PACKET need no more.
        subprocess.run([shutil.which('unshare'), '--user', '--map-root-user', '--net', sys.executable,
                        str(Path(__file__).resolve()), '--inside', binaries['arp_echo'], parent],
                       check=True, timeout=90)
