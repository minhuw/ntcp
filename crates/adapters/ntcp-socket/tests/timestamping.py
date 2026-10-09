#!/usr/bin/env python3
import concurrent.futures
import os
import select
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from socket_config import config_env

ROOT = Path(__file__).resolve().parents[4]
LIBRARY = ROOT / 'target/debug/libntcp_socket.so'


def environment():
    return {k: v for k, v in os.environ.items()
            if k not in ('LD_PRELOAD', 'NTCP_SOCKET_CONFIG')}


def isolated(binary, backend):
    env = environment()
    commands = [ ['ip', 'link', 'set', 'lo', 'up'] ]
    settings = {'io_address': '10.73.0.2'}
    if backend == 'tun':
        commands += [ ['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                      ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                      ['ip', 'link', 'set', 'ntcp0', 'up'] ]
        settings['io_interface'] = 'ntcp0'
    else:
        commands += [ ['ip', 'link', 'add', 'engine0', 'type', 'veth', 'peer', 'name', 'peer0'],
                      ['ip', 'link', 'set', 'engine0', 'address', '02:00:00:00:00:02'],
                      ['ip', 'link', 'set', 'peer0', 'address', '02:00:00:00:00:01'],
                      ['ip', 'addr', 'add', '10.73.0.254/24', 'dev', 'engine0', 'noprefixroute'],
                      ['ip', 'addr', 'add', '10.73.0.253/24', 'dev', 'peer0'],
                      ['ip', 'link', 'set', 'engine0', 'up'],
                      ['ip', 'link', 'set', 'peer0', 'up'] ]
        settings |= {'io_backend': 'af-packet', 'io_interface': 'engine0',
                     'io_next_hop_mac': '02:00:00:00:00:01'}
    for args in commands:
        subprocess.run(args, env=env, check=True, timeout=10)

    def echo(listener):
        listener.settimeout(10)
        with listener.accept()[0] as conn:
            conn.settimeout(10)
            data = b''
            while len(data) < 9:
                chunk = conn.recv(9 - len(data))
                assert chunk, 'unexpected EOF'
                data += chunk
            conn.sendall(data)
            assert conn.recv(1) == b''

    if backend == 'af-packet':
        # Two userspace endpoints avoid veth's kernel CHECKSUM_PARTIAL frames;
        # no offload/NIC configuration or checksum bypass is needed.
        server_env = env | {'LD_PRELOAD': str(LIBRARY)} | config_env(
            Path(binary).parent, **(settings | {'io_address': '10.73.0.1',
                'io_interface': 'peer0', 'io_next_hop_mac': '02:00:00:00:00:02'}))
        with subprocess.Popen([binary, '--server'], env=server_env,
                              stdout=subprocess.PIPE, text=True) as server:
            try:
                assert select.select([server.stdout], [], [], 10)[0], 'server startup timeout'
                assert server.stdout.readline().strip() == 'READY'
                subprocess.run([binary], env=env | {'LD_PRELOAD': str(LIBRARY)} | config_env(
                                   Path(binary).parent, **settings),
                               check=True, timeout=20)
                assert server.wait(timeout=10) == 0
            finally:
                if server.poll() is None:
                    server.kill()
        return

    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor() as pool:
        listener.bind(('10.73.0.1', 16380))
        listener.listen()
        task = pool.submit(echo, listener)
        subprocess.run([binary], env=env | {
            'LD_PRELOAD': str(LIBRARY), **config_env(Path(binary).parent, **settings)}, check=True, timeout=20)
        task.result(timeout=10)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2], sys.argv[3])
        return
    env = environment()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-timestamp-') as directory:
        binary = str(Path(directory) / 'timestamping')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        subprocess.run([binary, '--invalid'], env=env | {
            'LD_PRELOAD': str(LIBRARY), **config_env(directory, io_backend='af-packet')},
            check=True, timeout=10)
        for backend in ['tun', 'af-packet']:
            subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                            sys.executable, str(Path(__file__).resolve()), '--isolated', binary, backend],
                           env=env, check=True, timeout=40)
            print(f'PASS {backend}: actual RX software and core ACK; no physical HW claim')


if __name__ == '__main__':
    main()
