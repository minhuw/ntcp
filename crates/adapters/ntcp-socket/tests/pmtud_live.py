#!/usr/bin/env python3
"""Isolated native MTU-drop regression; never changes host interfaces."""
import select
import subprocess
import sys
import tempfile
from pathlib import Path

from socket_config import config_env
from timestamping import ROOT, LIBRARY, environment


def line(process, expected):
    assert select.select([process.stdout], [], [], 10)[0], expected
    assert process.stdout.readline().strip() == expected


def isolated(binary, backend):
    env = environment()
    commands = [['ip', 'link', 'set', 'lo', 'up']]
    settings = {'io_address': '10.73.0.2', 'io_output_reservation_timeout_ms': '1000'}
    if backend == 'tun':
        commands += [['ip', 'tuntap', 'add', 'dev', 'ntcp0', 'mode', 'tun'],
                     ['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp0'],
                     ['ip', 'link', 'set', 'ntcp0', 'up']]
        settings['io_interface'] = 'ntcp0'
        server_env, interfaces = env, ['ntcp0']
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
        server_env = env | {'LD_PRELOAD': str(LIBRARY)} | config_env(
            Path(binary).parent, **(settings | {'io_address': '10.73.0.1',
                'io_interface': 'peer0', 'io_next_hop_mac': '02:00:00:00:00:02'}))
        interfaces = ['engine0', 'peer0']
    for command in commands:
        subprocess.run(command, env=env, check=True, timeout=10)
    with subprocess.Popen([binary, 'server', backend], env=server_env,
                          stdout=subprocess.PIPE, text=True) as server:
        client = None
        try:
            line(server, 'READY')
            client = subprocess.Popen([binary, 'client', backend], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, text=True, env=env | {'LD_PRELOAD': str(LIBRARY)} |
                config_env(Path(binary).parent, **settings))
            line(client, 'CONNECTED')
            for interface in interfaces:
                subprocess.run(['ip', 'link', 'set', interface, 'mtu', '600'],
                               env=env, check=True, timeout=10)
            output, _ = client.communicate('x', timeout=30)
            assert client.returncode == 0
            assert server.wait(timeout=10) == 0
            print(output + server.stdout.read(), end='')
        finally:
            for process in [client, server]:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--isolated':
        isolated(*sys.argv[2:])
        return
    env = environment()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT, env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-pmtud-') as directory:
        binary = str(Path(directory) / 'pmtud-live')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        for backend in ['tun', 'af-packet']:
            subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                            sys.executable, str(Path(__file__).resolve()),
                            '--isolated', binary, backend], env=env, check=True, timeout=50)
            print(f'PASS {backend}: live 1500->600, data integrity, future connection')


if __name__ == '__main__':
    main()
