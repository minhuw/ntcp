#!/usr/bin/env python3
"""Native Linux differential checks; --native-only needs no core build or TUN."""
import concurrent.futures
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[4]
LIBRARY = ROOT / 'target/debug/libntcp_socket.so'


def clean_env():
    return {k: v for k, v in os.environ.items()
            if k != 'LD_PRELOAD' and not k.startswith('NTCP_SOCKET_')}


def run(executable, virtual=False, preload=False):
    env = clean_env()
    host = '10.73.0.1' if virtual else '127.0.0.1'
    if virtual or preload:
        env['LD_PRELOAD'] = str(LIBRARY)
    if virtual:
        env.update(NTCP_SOCKET_TUN='ntcp0', NTCP_SOCKET_ADDR='10.73.0.2')

    def peer(listener):
        listener.settimeout(15)
        with listener.accept()[0] as client:
            client.settimeout(15)
            for command, response in [(b'A', b'abcdef'), (b'B', b'xyz'),
                                      (b'C', b'c'), (b'D', b'd'), (b'E', b'e'), (b'F', b'fin')]:
                assert client.recv(1) == command
                client.sendall(response)
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b''

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        listener.bind((host, 0))
        listener.listen()
        task = pool.submit(peer, listener)
        subprocess.run([str(executable), host, str(listener.getsockname()[1]),
                        'managed' if virtual else 'native'], env=env, check=True, timeout=25)
        task.result(timeout=5)

    done = threading.Event()
    def blocked_peer(listener):
        listener.settimeout(15)
        with listener.accept()[0]:
            assert done.wait(20)
    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        listener.bind((host, 0))
        listener.listen()
        task = pool.submit(blocked_peer, listener)
        try:
            subprocess.run([str(executable), host, str(listener.getsockname()[1]),
                            'managed-lowwater' if virtual else 'native-lowwater'],
                           env=env, check=True, timeout=25)
        finally:
            done.set()
        task.result(timeout=5)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        for args in (['ip', 'link', 'set', 'lo', 'up'],
                     ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                     ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                     ['ip', 'link', 'set', 'ntcp0', 'up']):
            subprocess.run(args, env=clean_env(), check=True, timeout=10)
        run(sys.argv[2], virtual=True)
        return
    native_only = sys.argv[1:] == ['--native-only']
    if not native_only:
        subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                       env=clean_env(), check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-socket-features-') as directory:
        executable = Path(directory) / 'socket_features'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', str(executable)],
                       env=clean_env(), check=True, timeout=30)
        run(executable)
        if not native_only:
            run(executable, preload=True)
            subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                            sys.executable, str(Path(__file__).resolve()), '--isolated', str(executable)],
                           env=clean_env(), check=True, timeout=35)


if __name__ == '__main__':
    main()
