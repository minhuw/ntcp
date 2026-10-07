#!/usr/bin/env python3
"""Differential cancellation and socket stdio, including configured coexistence."""
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


def run(args, env=None, timeout=30):
    subprocess.run(args, env=env or clean_env(), cwd=ROOT, check=True, timeout=timeout)


def isolated(directory):
    env = clean_env()
    for args in (['ip', 'link', 'set', 'lo', 'up'],
                 ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                 ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                 ['ip', 'link', 'set', 'ntcp0', 'up']):
        run(args)
    preload = env | {'LD_PRELOAD': str(LIBRARY), 'NTCP_SOCKET_TUN': 'ntcp0',
                     'NTCP_SOCKET_ADDR': '10.73.0.2'}
    run([str(directory / 'cancellation'), '--coexist'], env=preload)

    def serve(listener, loaded):
        for _ in range(3 if loaded else 2):
            with listener.accept()[0] as client:
                client.settimeout(15)
                line = bytearray()
                while not line.endswith(b'\r\n'):
                    byte = client.recv(1)
                    if not byte:
                        break  # second connection is closed without payload
                    line.extend(byte)
                if not line:
                    continue
                assert line == b'PING\r\n', line
                client.sendall(b'+PONG\r\n')
                count = 0
                while count < 256 * 1024:
                    data = client.recv(min(16384, 256 * 1024 - count))
                    assert data
                    client.sendall(data)
                    count += len(data)

    for mode in ('r+', 'w+', 'a+'):
        for loaded in (False, True):
            with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(1) as pool:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('10.73.0.1', 16380))
                listener.listen()
                listener.settimeout(20)
                task = pool.submit(serve, listener, loaded)
                run([str(directory / 'stdio'), mode] + (['--managed'] if loaded else []),
                    env=preload if loaded else env)
                task.result(timeout=25)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        isolated(Path(sys.argv[2]))
        return
    run(['cargo', 'build', '-p', 'ntcp-socket'], timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-boundary-') as directory:
        directory = Path(directory)
        for name in ('cancellation', 'stdio'):
            run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread',
                 str(Path(__file__).with_name(name + '.c')), '-o', str(directory / name)])
        early = directory / 'early.so'
        run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread', '-fPIC', '-shared',
             '-DNTCP_EARLY', str(Path(__file__).with_name('cancellation.c')), '-o', str(early)])
        # Loader runs the second preload's constructor before our constructor.
        run(['/bin/true'], env=clean_env() | {'LD_PRELOAD': f'{LIBRARY}:{early}'})
        for env in (clean_env(), clean_env() | {'LD_PRELOAD': str(LIBRARY)}):
            run([str(directory / 'cancellation')], env=env)
        run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
             str(Path(__file__).resolve()), '--isolated', str(directory)], timeout=150)
    print('PASS Linux C cancellation boundary and managed socket stdio')


if __name__ == '__main__':
    main()
