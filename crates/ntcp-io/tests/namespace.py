#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]

# Build before entering the namespace: no network/download access is needed there.
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(ROOT / 'workbench' / 'ntcp-io-target')
subprocess.run(['cargo', 'test', '-p', 'ntcp-io', '--test', 'namespace', '--no-run'],
               cwd=ROOT, env=env, check=True)
if '--in-namespace' in sys.argv:
    # Caller must supply the original host inode, never infer safety from uid.
    parent = int(env['NTCP_IO_PARENT_NETNS'])
    if os.stat('/proc/self/ns/net').st_ino == parent:
        raise RuntimeError('refusing to run in the parent network namespace')
    command = ['cargo', 'test', '-p', 'ntcp-io', '--test', 'namespace', '--',
               '--ignored', '--nocapture']
else:
    env['NTCP_IO_PARENT_NETNS'] = str(os.stat('/proc/self/ns/net').st_ino)
    command = ['unshare', '--user', '--map-root-user', '--net',
               sys.executable, str(pathlib.Path(__file__).resolve()), '--in-namespace']
subprocess.run(command, cwd=ROOT, env=env, check=True)
