#!/usr/bin/env python3
import concurrent.futures
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import timestamping


def run(binary, managed=False, preload=False):
    env = timestamping.environment()
    host = '10.73.0.1' if managed else '127.0.0.1'
    if preload or managed:
        env['LD_PRELOAD'] = str(timestamping.LIBRARY)
    if managed:
        env.update(NTCP_SOCKET_ADDR='10.73.0.2', NTCP_SOCKET_TUN='ntcp0')
    pattern = bytes(n % 251 for n in range(150000))

    def peer(listener):
        for case in range(15):
            with listener.accept()[0] as conn:
                conn.settimeout(8)
                if case in (6, 7, 10):
                    time.sleep(.4)
                if case in (8, 10, 13, 14):
                    conn.sendall(pattern if case == 8 else pattern[:5])
                received = bytearray()
                while chunk := conn.recv(65536):
                    received.extend(chunk)
                expected = (pattern[:5] if case in (0, 1, 4, 9, 12) else
                            pattern if case in (2, 3, 5, 6, 7) else b'')
                assert received == expected, (case, len(received), len(expected))

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor() as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, 16406))
        listener.listen()
        listener.settimeout(10)
        task = pool.submit(peer, listener)
        subprocess.run([binary, host], env=env, check=True, timeout=35)
        task.result(timeout=10)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                        ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                        ['ip', 'link', 'set', 'ntcp0', 'up']):
            subprocess.run(command, check=True, timeout=10)
        run(sys.argv[2], managed=True)
        return
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=timestamping.ROOT,
                   check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-file-transfer-') as directory:
        binary = str(Path(directory) / 'file-transfer')
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(Path(__file__).with_suffix('.c')), '-o', binary], check=True)
        run(binary)
        run(binary, preload=True)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
                        str(Path(__file__).resolve()), '--isolated', binary], check=True, timeout=45)


if __name__ == '__main__':
    main()
