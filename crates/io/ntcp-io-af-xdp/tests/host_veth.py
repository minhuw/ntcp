#!/usr/bin/env python3
"""Exercise the AF_XDP host against Linux over a veth pair in private namespaces.

The xdp_echo example attaches the host's program to x0 in generic mode and
runs a closed-loop echo client from an ntcp address on x0; the peer namespace
holds k0 and a kernel TCP echo server. x0 also has a kernel address, which the
peer pings during the run: the program passes the kernel's traffic on. Neither
side has a static neighbour, and the peer forgets ntcp's address during the
run, so ntcp both resolves the peer and answers the peer's ARP request. A
killed client leaves no program attached.

Run inside `nix develop` (it builds the example) with passwordless sudo: the
test itself needs CAP_BPF and CAP_NET_ADMIN, which an unprivileged user
namespace does not grant for BPF."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[4]
PEER, KERNEL, NATIVE, PREFIX, PORT = '10.75.0.1', '10.75.0.2', '10.75.0.12', '24', 9999


def cmd(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def output(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True).stdout


def in_peer(pid, *args):
    return subprocess.run(['nsenter', f'--net=/proc/{pid}/ns/net', *args], check=True,
                          stdout=subprocess.PIPE, text=True).stdout


def no_offloads(name):
    # Complete checksums and MTU-sized frames on the wire, as the other veth
    # cases in this tree arrange: the native port does not take partially
    # checksummed frames, and generic XDP sees what the peer transmits.
    cmd('ethtool', '-K', name, 'tx', 'off', 'rx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def peer():
    """The kernel side: waits for k0, then serves TCP echo until stdin closes."""
    # unshare has entered this namespace before running us: k0 may move here.
    print('STARTED', flush=True)
    deadline = time.monotonic() + 10
    while subprocess.run(['ip', 'link', 'show', 'k0'], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode:
        if time.monotonic() > deadline:
            raise RuntimeError('k0 did not appear')
        time.sleep(0.05)
    cmd('ip', 'link', 'set', 'lo', 'up')
    no_offloads('k0')
    cmd('ip', 'addr', 'add', PEER + '/' + PREFIX, 'dev', 'k0')
    cmd('ip', 'link', 'set', 'k0', 'up')
    server = Server((PEER, PORT), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print('READY', flush=True)
    sys.stdin.read()


def metrics(text):
    values = {}
    for line in text.splitlines():
        if line.startswith('METRIC '):
            name, value = line.split()[1].split('=')
            values[name] = float(value)
    return values


def xdp_attached(name):
    link = json.loads(output('ip', '-j', '-d', 'link', 'show', name))[0]
    return 'xdp' in link


def inside(binary, parent_namespace):
    if os.readlink('/proc/self/ns/net') == parent_namespace:
        raise RuntimeError('independent network namespace required before setup')
    cmd('ip', 'link', 'set', 'lo', 'up')
    peer_process = subprocess.Popen([shutil.which('unshare'), '--net', sys.executable, __file__, '--peer'],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        if peer_process.stdout.readline().strip() != 'STARTED':
            raise RuntimeError('peer did not start')
        cmd('ip', 'link', 'add', 'x0', 'type', 'veth', 'peer', 'name', 'k0', 'netns', str(peer_process.pid))
        no_offloads('x0')
        cmd('ip', 'addr', 'add', KERNEL + '/' + PREFIX, 'dev', 'x0')
        cmd('ip', 'link', 'set', 'x0', 'up')
        if peer_process.stdout.readline().strip() != 'READY':
            raise RuntimeError('peer did not configure k0')
        mac = json.loads(output('ip', '-j', 'link', 'show', 'x0'))[0]['address']
        permanent = output('ip', 'neigh', 'show', 'nud', 'permanent').strip()
        assert not permanent, permanent
        assert not xdp_attached('x0')

        client = subprocess.Popen([binary, '--dev', 'x0', '--mode', 'generic', '--ip', NATIVE, '--prefix', PREFIX,
                                   '--server', f'{PEER}:{PORT}', '--connections', '4', '--duration', '4'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(1.5)
            # The kernel's own address on the same interface keeps working.
            pings = in_peer(peer_process.pid, 'ping', '-c', '3', '-i', '0.2', '-W', '1', KERNEL)
            assert xdp_attached('x0')
            # The peer forgets ntcp's address and must resolve it again: ntcp
            # answers its request, or the echo loop stalls.
            in_peer(peer_process.pid, 'ip', 'neigh', 'flush', 'dev', 'k0')
            stdout, stderr = client.communicate(timeout=30)
        finally:
            if client.poll() is None:
                client.kill()
                client.communicate()
        values = metrics(stdout)
        if client.returncode != 0:
            raise RuntimeError(f'xdp_echo failed ({client.returncode}): {stderr}\n{stdout}')
        assert values['errors'] == 0 and values['requests'] > 0, stdout
        # ntcp resolved the peer, and answered the peer's request after the flush.
        assert values['arp_requests_sent'] >= 1 and values['arp_received'] >= 1, stdout
        assert values['arp_replies_sent'] >= 1, stdout
        assert values['arp_resolution_failures'] == 0 and values['unsteered'] == 0, stdout
        entries = [e for e in json.loads(in_peer(peer_process.pid, 'ip', '-j', '-4', 'neigh', 'show', 'dev', 'k0')
                                         or '[]') if e.get('dst') == NATIVE]
        assert len(entries) == 1 and entries[0].get('lladdr') == mac, entries
        assert 'PERMANENT' not in entries[0].get('state', []), entries
        assert not xdp_attached('x0'), 'program still attached after exit'
        print(json.dumps({'requests': values['requests'], 'requests_per_second': values['requests_per_second'],
                          'arp': {k: values[k] for k in values if k.startswith('arp_')},
                          'kernel_pings': pings.strip().splitlines()[-2],
                          'peer_neighbour': {'lladdr': mac, 'state': entries[0].get('state')},
                          'result': 'passed'}), flush=True)

        # A killed client leaves no program behind: the BPF link dies with it.
        client = subprocess.Popen([binary, '--dev', 'x0', '--mode', 'generic', '--ip', NATIVE, '--prefix', PREFIX,
                                   '--server', f'{PEER}:{PORT}', '--duration', '30'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            line = client.stderr.readline()
            assert line.startswith('PORT '), line
            assert xdp_attached('x0')
            client.send_signal(signal.SIGKILL)
            client.wait(timeout=10)
        finally:
            if client.poll() is None:
                client.kill()
                client.wait()
        deadline = time.monotonic() + 5
        while xdp_attached('x0'):
            assert time.monotonic() < deadline, 'program still attached after SIGKILL'
            time.sleep(0.05)
        print(json.dumps({'killed_client': 'program detached', 'result': 'passed'}), flush=True)
    finally:
        peer_process.stdin.close()
        peer_process.wait(timeout=10)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--peer':
        peer()
    elif len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside(*sys.argv[2:])
    else:
        build = subprocess.run(['cargo', 'build', '--manifest-path', str(ROOT / 'Cargo.toml'), '-p', 'ntcp-io-af-xdp',
                                '--features', 'host', '--example', 'xdp_echo', '--message-format=json'],
                               cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True)
        artifacts = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = {a.get('target', {}).get('name'): a['executable'] for a in artifacts
                    if a.get('reason') == 'compiler-artifact' and a.get('executable')}
        assert 'xdp_echo' in binaries, binaries
        parent = os.readlink('/proc/self/ns/net')
        privilege = [] if os.geteuid() == 0 else ['sudo', '-n']
        subprocess.run([*privilege, shutil.which('unshare'), '--net', sys.executable, str(Path(__file__).resolve()),
                        '--inside', binaries['xdp_echo'], parent], check=True, timeout=120)
