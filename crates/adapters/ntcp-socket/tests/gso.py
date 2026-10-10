#!/usr/bin/env python3
"""Scalar/software-range native transfer differential; no hardware offload."""
import subprocess
import sys
import tempfile
from pathlib import Path

from pacing import isolated
from timestamping import ROOT, environment


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2], sys.argv[3], 'false', int(sys.argv[4]), sys.argv[5] == 'range')
        return
    env = environment()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-gso-') as directory:
        binary = str(Path(directory) / 'egress')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread',
                        str(Path(__file__).with_name('egress.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        for backend in ['tun', 'af-packet']:
            for capacity in [1, 32]:
                for mode in ['scalar', 'range']:
                    subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                                    sys.executable, str(Path(__file__).resolve()),
                                    '--isolated', binary, backend, str(capacity), mode],
                                   env=env, check=True, timeout=50)
                    print(f'PASS {backend} capacity={capacity} {mode}: identical checked bidirectional payloads')


if __name__ == '__main__':
    main()
