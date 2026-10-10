#!/usr/bin/env python3
import select
import subprocess
import sys
import tempfile
from pathlib import Path

from socket_config import config_env
from timestamping import ROOT, LIBRARY, environment


def isolated(binary, backend, pacing, egress_capacity=32):
    env = environment()
    commands = [['ip', 'link', 'set', 'lo', 'up']]
    settings = {'io_address': '10.73.0.2', 'io_egress_capacity': egress_capacity}
    if pacing != 'unset':
        settings['tcp_pacing'] = pacing
    if backend == 'tun':
        commands += [['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                     ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                     ['ip', 'link', 'set', 'ntcp0', 'up']]
        settings['io_interface'] = 'ntcp0'
        server_env = env
    else:
        commands += [['ip', 'link', 'add', 'engine0', 'type', 'veth', 'peer', 'name', 'peer0'],
                     ['ip', 'link', 'set', 'engine0', 'address', '02:00:00:00:00:02'],
                     ['ip', 'link', 'set', 'peer0', 'address', '02:00:00:00:00:01'],
                     ['ip', 'addr', 'add', '10.73.0.254/24', 'dev', 'engine0', 'noprefixroute'],
                     ['ip', 'addr', 'add', '10.73.0.253/24', 'dev', 'peer0'],
                     ['ip', 'link', 'set', 'engine0', 'up'],
                     ['ip', 'link', 'set', 'peer0', 'up']]
        settings |= {'io_backend': 'af-packet', 'io_interface': 'engine0',
                     'io_next_hop_mac': '02:00:00:00:00:01'}
        # Two userspace endpoints avoid kernel CHECKSUM_PARTIAL frames on veth.
        server_env = env | {'LD_PRELOAD': str(LIBRARY)} | config_env(
            Path(binary).parent, **(settings | {'io_address': '10.73.0.1',
                'io_interface': 'peer0', 'io_next_hop_mac': '02:00:00:00:00:02'}))
    for command in commands:
        subprocess.run(command, env=env, check=True, timeout=10)
    with subprocess.Popen([binary, '--server'], env=server_env,
                          stdout=subprocess.PIPE, text=True) as server:
        try:
            assert select.select([server.stdout], [], [], 10)[0], 'server startup timeout'
            assert server.stdout.readline().strip() == 'READY'
            subprocess.run([binary], env=env | {'LD_PRELOAD': str(LIBRARY)} | config_env(
                               Path(binary).parent, **settings), check=True, timeout=30)
            assert server.wait(timeout=10) == 0
        finally:
            if server.poll() is None:
                server.kill()


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--isolated':
        isolated(*sys.argv[2:])
        return
    env = environment()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-pacing-') as directory:
        binary = str(Path(directory) / 'pacing')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        for value in ['', 'TRUE', '01', '2']:
            subprocess.run([binary, '--invalid'], env=env | {
                'LD_PRELOAD': str(LIBRARY), **config_env(
                    directory, io_interface='ntcp0', io_address='10.73.0.2', tcp_pacing=value)}, check=True, timeout=10)
        for backend in ['tun', 'af-packet']:
            for pacing in ['unset', 'false', 'true']:
                subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                                sys.executable, str(Path(__file__).resolve()),
                                '--isolated', binary, backend, pacing],
                               env=env, check=True, timeout=50)
                print(f'PASS {backend} pacing={pacing}: bidirectional transfer, idle, half-close')


if __name__ == '__main__':
    main()
