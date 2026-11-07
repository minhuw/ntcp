#!/usr/bin/env python3
"""Exercise the native Rust group against Linux TCP in isolated net namespaces."""
import concurrent.futures
import hashlib
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
# The native address is created in a fresh namespace for this run: nothing
# was ever emitted from it, so only the boot floor of the TCP quiet time applies.
FRESH_ADDRESS = dict(os.environ, NTCP_SOURCE_QUIET='never')

def cmd(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

def inside(binary, client_binary, family, parent_namespace):
    if os.readlink('/proc/self/ns/net') == parent_namespace:
        raise RuntimeError('independent network namespace required before setup')
    cmd('ip', 'link', 'set', 'lo', 'up')
    cmd('ip', 'tuntap', 'add', 'dev', 'native0', 'mode', 'tun')
    cmd('ip', 'link', 'set', 'native0', 'mtu', '1500', 'up')
    if family == '4':
        kernel, native, prefix, af = '10.73.0.1', '10.73.0.2', '24', socket.AF_INET
        cmd('ip', 'addr', 'add', kernel + '/' + prefix, 'dev', 'native0')
    else:
        kernel, native, prefix, af = 'fd73::1', 'fd73::2', '64', socket.AF_INET6
        cmd('ip', '-6', 'addr', 'add', kernel + '/' + prefix, 'dev', 'native0', 'nodad')
    process = subprocess.Popen([binary, 'native0', native, '9000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=FRESH_ADDRESS)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError('native TUN example did not become ready')
            line = process.stdout.readline()
        if not line.startswith('READY '):
            raise RuntimeError('native startup failed: ' + line + process.stderr.read())
        def exchange(seed):
            payload = bytes((i + seed) % 251 for i in range(262144))
            errors = []
            with socket.socket(af, socket.SOCK_STREAM) as client:
                client.settimeout(15)
                client.connect((native, 9000))
                def send():
                    try:
                        client.sendall(payload)
                        client.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        errors.append(error)
                sender = threading.Thread(target=send)
                sender.start()
                received = bytearray()
                while True:
                    data = client.recv(32768)
                    if not data:
                        break
                    received.extend(data)
                sender.join(15)
                if sender.is_alive():
                    raise RuntimeError('sender did not finish')
                if errors:
                    raise errors[0]
                if received != payload:
                    raise AssertionError(f'IPv{family} payload differs: {len(received)}/{len(payload)} bytes; sha256={hashlib.sha256(received).hexdigest()}')
                return len(received)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as clients:
            verified = sum(clients.map(exchange, range(4)))
        print(json.dumps({'family': 'IPv' + family, 'native_role': 'server', 'connections': 4, 'verified_bytes': verified, 'half_close_and_eof': True, 'result': 'passed'}), flush=True)
    finally:
        process.terminate()
        try:
            _, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate()
        if process.returncode not in [-15, 0]:
            print(stderr, file=sys.stderr)
    with socket.socket(af, socket.SOCK_STREAM) as listener:
        listener.settimeout(15)
        listener.bind((kernel, 9001))
        listener.listen(4)
        def echo():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(15)
                count = 0
                while True:
                    data = connection.recv(32768)
                    if not data:
                        break
                    connection.sendall(data)
                    count += len(data)
                connection.shutdown(socket.SHUT_WR)
                return count
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as servers:
            pending = [servers.submit(echo) for _ in range(4)]
            completed = subprocess.run([client_binary, 'native0', native, kernel, '9001'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25, env=FRESH_ADDRESS)
            if completed.returncode:
                raise RuntimeError('native client failed: ' + completed.stderr)
            if completed.stdout.strip() != 'ROUNDTRIP 4 1048576':
                raise AssertionError('unexpected native client result: ' + completed.stdout)
            verified = sum(result.result(timeout=15) for result in pending)
            assert verified == 1048576, verified
        print(json.dumps({'family': 'IPv' + family, 'native_role': 'client', 'connections': 4, 'verified_bytes': verified, 'half_close_and_eof': True, 'result': 'passed'}), flush=True)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside(*sys.argv[2:])
    else:
        build = subprocess.run(['cargo', 'build', '--manifest-path', str(ROOT / 'Cargo.toml'), '-p', 'ntcp-native', '--examples', '--message-format=json'], cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True)
        artifacts = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = {a.get('target', {}).get('name'): a['executable'] for a in artifacts if a.get('reason') == 'compiler-artifact' and a.get('executable')}
        assert 'tun_echo' in binaries and 'tun_roundtrip' in binaries, binaries
        privilege = [] if os.geteuid() == 0 else ['sudo', '-n']
        parent = os.readlink('/proc/self/ns/net')
        for family in ['4', '6']:
            subprocess.run(privilege + [shutil.which('unshare'), '--net', sys.executable, str(Path(__file__).resolve()), '--inside', binaries['tun_echo'], binaries['tun_roundtrip'], family, parent], check=True, timeout=60)
