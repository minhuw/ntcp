#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]


def main():
    env = {k: v for k, v in os.environ.items()
           if k != 'LD_PRELOAD' and not k.startswith('NTCP_SOCKET_')}
    subprocess.run(['cargo', 'build', '-p', 'ntcp-socket'], cwd=ROOT,
                   env=env, check=True, timeout=180)
    library = ROOT / 'target/debug/libntcp_socket.so'
    assert library.is_file(), library
    with tempfile.TemporaryDirectory(prefix='ntcp-preload-') as directory:
        executable = Path(directory) / 'preload'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-D_FORTIFY_SOURCE=2',
                        str(Path(__file__).with_suffix('.c')), '-o', str(executable)],
                       env=env, check=True, timeout=30)
        subprocess.run([executable], env=env, check=True, timeout=15)
        subprocess.run([executable], env=env | {'LD_PRELOAD': str(library)},
                       check=True, timeout=15)
    print('PASS: native file/socket/UDP, vectored I/O, readiness, fcntl, dup, and fork passthrough')


if __name__ == '__main__':
    main()
