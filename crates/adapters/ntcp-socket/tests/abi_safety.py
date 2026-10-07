#!/usr/bin/env python3
import concurrent.futures
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

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
    done = threading.Event()

    def server(listener):
        listener.settimeout(10)
        with listener.accept()[0] as client:
            client.sendall(b'abcdef')
            assert done.wait(20)

    def accepted_fault():
        deadline = time.monotonic() + 10
        while True:
            try:
                client = socket.create_connection(('10.73.0.2', 16381), timeout=1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
        with client:
            client.settimeout(10)
            assert client.recv(1) == b'', 'faulted accept must close its engine child'

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('10.73.0.1', 16380))
        listener.listen()
        server_task = pool.submit(server, listener)
        fault_task = pool.submit(accepted_fault)
        try:
            subprocess.run([executable, '--virtual'], env=env | {
                'LD_PRELOAD': str(LIBRARY), 'NTCP_SOCKET_TUN': 'ntcp0',
                'NTCP_SOCKET_ADDR': '10.73.0.2'}, check=True, timeout=25)
        finally:
            done.set()
        server_task.result(timeout=5)
        fault_task.result(timeout=12)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2])
        return
    env = clean_env()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    # Includes the deterministic TOKENS-held signal regression, under a watchdog.
    subprocess.run(['cargo', 'test', '-p', 'ntcp-socket', '--', '--test-threads=1'],
                   cwd=ROOT, env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-abi-') as directory:
        executable = Path(directory) / 'abi_safety'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-D_FORTIFY_SOURCE=2',
                        str(Path(__file__).with_suffix('.c')), '-o', str(executable)],
                       env=env, check=True, timeout=30)
        symbols = subprocess.check_output(['nm', '-u', executable], env=env, text=True)
        for symbol in ('__read_chk', '__recv_chk', '__recvfrom_chk', '__poll_chk', '__ppoll_chk'):
            assert symbol + '@' in symbols, (symbol, symbols)
        subprocess.run([executable], env=env, check=True, timeout=20)
        subprocess.run([executable], env=env | {'LD_PRELOAD': str(LIBRARY)},
                       check=True, timeout=20)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                        sys.executable, str(Path(__file__).resolve()), '--isolated', str(executable)],
                       env=env, check=True, timeout=45)
    print('PASS: native errno, fault-reporting ABI, fortified symbols, preserved reads and accept cleanup')


if __name__ == '__main__':
    main()
