#!/usr/bin/env python3
"""Serial native paced multiflow smoke; copying backends, not GSO/wire timing."""
import subprocess
import sys
import tempfile
from pathlib import Path

from pacing import isolated
from timestamping import ROOT, environment


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2], sys.argv[3], 'true', int(sys.argv[4]))
        return
    env = environment()
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    with tempfile.TemporaryDirectory(prefix='ntcp-egress-') as directory:
        binary = str(Path(directory) / 'egress')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread',
                        str(Path(__file__).with_suffix('.c')), '-o', binary],
                       env=env, check=True, timeout=30)
        for backend in ['tun', 'af-packet']:
            for capacity in [1, 32]:
                subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                                sys.executable, str(Path(__file__).resolve()),
                                '--isolated', binary, backend, str(capacity)],
                               env=env, check=True, timeout=50)
                print(f'PASS {backend} capacity={capacity}: 4 paced bidirectional flows, idle, half-close')


if __name__ == '__main__':
    main()
