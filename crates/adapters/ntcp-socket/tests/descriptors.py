#!/usr/bin/env python3
import concurrent.futures
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
LIBRARY = ROOT / 'target/debug/libntcp_socket.so'


def clean_env():
    return {k: v for k, v in os.environ.items()
            if k != 'LD_PRELOAD' and not k.startswith('NTCP_SOCKET_')}


def isolated(executable):
    env = clean_env()
    for args in (['ip', 'link', 'set', 'lo', 'up'],
                 ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                 ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                 ['ip', 'link', 'set', 'ntcp0', 'up']):
        subprocess.run(args, env=env, check=True, timeout=10)

    def echo(client):
        with client:
            client.settimeout(20)
            while True:
                try:
                    data = client.recv(1024)
                except ConnectionResetError:
                    return 'reset'
                if not data:
                    return 'fin'
                client.sendall(data)

    for extra, args in (({}, []), ({'LD_PRELOAD': str(LIBRARY)}, []),
                        ({'LD_PRELOAD': str(LIBRARY), 'NTCP_SOCKET_TUN': 'ntcp0',
                          'NTCP_SOCKET_ADDR': '10.73.0.2'}, ['--virtual'])):
        with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('10.73.0.1', 16382))
            listener.listen()
            listener.settimeout(20)

            def accept():
                tasks = [pool.submit(echo, listener.accept()[0]) for _ in range(3)]
                # Every last-close/replacement must actually end its TCP stream.
                return [task.result(timeout=20) for task in tasks]

            accepted = pool.submit(accept)
            subprocess.run([executable, *args], env=env | extra, check=True, timeout=30)
            assert len(accepted.result(timeout=20)) == 3
    print('PASS: native/TUN descriptor aliases, replacement, epoll lifetime and ONESHOT')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2])
        return
    env = clean_env()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-descriptors-') as directory:
        executable = Path(directory) / 'descriptors'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', str(executable)],
                       env=env, check=True, timeout=30)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                        sys.executable, str(Path(__file__).resolve()), '--isolated', str(executable)],
                       env=env, check=True, timeout=100)


if __name__ == '__main__':
    main()
