#!/usr/bin/env python3
import concurrent.futures
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from socket_config import config_env
import timestamping


def run(binary, managed=False, preload=False):
    env = timestamping.environment()
    host = '10.73.0.1' if managed else '127.0.0.1'
    if preload or managed:
        env['LD_PRELOAD'] = str(timestamping.LIBRARY)
    if managed:
        env.update(config_env(Path(binary).parent, io_interface='ntcp0', io_address='10.73.0.2'))

    def peer(listener):
        for case in range(16):
            with listener.accept()[0] as conn:
                conn.settimeout(5)
                if case >= 12:
                    time.sleep(.65)
                    continue
                data = bytearray()
                while chunk := conn.recv(65536):
                    data.extend(chunk)
                if case < 5:
                    assert data == bytes(n % 251 for n in range(150000)), (case, len(data))
                elif case < 7:
                    assert data and all(n == 19 for n in data), (case, len(data))
                else:
                    assert not data, (case, len(data))
                if 5 <= case < 12:
                    conn.sendall(len(data).to_bytes(4, 'big'))

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor() as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        listener.bind((host, 16405))
        listener.listen()
        listener.settimeout(8)
        task = pool.submit(peer, listener)
        subprocess.run([binary, host], env=env, check=True, timeout=25)
        task.result(timeout=10)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                        ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                        ['ip', 'link', 'set', 'ntcp0', 'up']):
            subprocess.run(command, env=timestamping.environment(), check=True, timeout=10)
        run(sys.argv[2], managed=True)
        return
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=timestamping.ROOT,
                   env=timestamping.environment(), check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-large-write-') as directory:
        binary = str(Path(directory) / 'large-write')
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=timestamping.environment(), check=True)
        run(binary)
        run(binary, preload=True)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
                        str(Path(__file__).resolve()), '--isolated', binary],
                       env=timestamping.environment(), check=True, timeout=35)


if __name__ == '__main__':
    main()
