#!/usr/bin/env python3
"""Live software phases, never injected completions or a hardware claim."""
import argparse
import platform
from pathlib import Path
import subprocess
import sys
import tempfile

import timestamping


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--isolated':
        timestamping.isolated(sys.argv[2], sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['tun', 'af-packet', 'both'], default='both')
    args = parser.parse_args()
    backends = ['tun', 'af-packet'] if args.backend == 'both' else [args.backend]
    if 'af-packet' in backends:
        version = tuple(map(int, platform.release().split('.')[:2]))
        if version < (6, 13):
            parser.error('AF_PACKET explicit TX IDs require Linux >=6.13; run in the modern-kernel VM')
    env = timestamping.environment()
    subprocess.run(['cargo', 'build', '--locked', '-p', 'ntcp-socket'],
                   cwd=timestamping.ROOT, env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-timestamp-phases-') as directory:
        binary = str(Path(directory) / 'timestamping-phases')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        for backend in backends:
            subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                            sys.executable, str(Path(__file__).resolve()),
                            '--isolated', binary, backend], env=env, check=True, timeout=40)
            print(f'PASS {backend}: live software SCHED/SND/ACK, no physical HW claim')


if __name__ == '__main__':
    main()
