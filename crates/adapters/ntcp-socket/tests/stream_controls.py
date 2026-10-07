#!/usr/bin/env python3
import concurrent.futures
import os
from pathlib import Path
import socket
import struct
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


def run_case(executable, virtual=False, preload=False):
    kernel = '10.73.0.1' if virtual else '127.0.0.1'
    local = '10.73.0.2' if virtual else kernel
    env = clean_env()
    if virtual or preload:
        env['LD_PRELOAD'] = str(LIBRARY)
    if virtual:
        env.update(NTCP_SOCKET_TUN='ntcp0', NTCP_SOCKET_ADDR=local)
    done = threading.Event()

    def listener(port):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.bind((kernel, port))
        s.listen()
        s.settimeout(15)
        return s

    def stream_peer(s):
        with s.accept()[0] as client:
            client.settimeout(12)
            client.sendall(b'abcdef')
            assert client.recv(1) == b'P'
            time.sleep(.03)
            client.sendall(b'xyz')
            client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b''
        with s.accept()[0]:
            # No application drain: send timeout must bound real backpressure.
            assert done.wait(15)

    def reset_peer(s):
        client = s.accept()[0]
        client.sendall(b'rst')
        time.sleep(.1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        client.close()

    with listener(16400) as stream, listener(16402) as reset:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            streams = pool.submit(stream_peer, stream)
            resets = pool.submit(reset_peer, reset)
            process = subprocess.Popen([str(executable), kernel, local,
                                        'virtual' if virtual else 'native'],
                                       env=env, stdout=subprocess.PIPE, text=True)
            try:
                # The C watchdog also bounds this pipe read.
                assert process.stdout.readline().strip() == 'ACCEPT'
                with socket.create_connection((local, 16401), timeout=3):
                    output, _ = process.communicate(timeout=15)
                assert process.returncode == 0, process.returncode
                assert 'PASS: stream controls' in output, output
            finally:
                done.set()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
            streams.result(timeout=3)
            resets.result(timeout=3)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        for args in (['ip', 'link', 'set', 'lo', 'up'],
                     ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                     ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                     ['ip', 'link', 'set', 'ntcp0', 'up']):
            subprocess.run(args, env=clean_env(), check=True, timeout=10)
        run_case(sys.argv[2], virtual=True)
        return
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=clean_env(), check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-controls-') as directory:
        executable = Path(directory) / 'stream_controls'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread',
                        str(Path(__file__).with_suffix('.c')), '-o', str(executable)],
                       env=clean_env(), check=True, timeout=30)
        run_case(executable)
        run_case(executable, preload=True)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                        sys.executable, str(Path(__file__).resolve()), '--isolated', str(executable)],
                       env=clean_env(), check=True, timeout=30)
    print('PASS: native TCP vs TUN peek, faults, vectors, EOF/reset, timeout options, '
          'receive/mutex/accept/connect/send deadlines and inheritance')


if __name__ == '__main__':
    main()
