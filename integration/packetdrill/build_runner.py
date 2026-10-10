#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the pinned runner plus the bounded code_sockopt repair in workbench."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from run import HERE, PIN, ROOT, check_checkout, runner_provenance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkout', required=True, type=Path)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    revision = check_checkout(checkout)
    patch = HERE / 'code-sockopt.patch'
    patch_bytes = patch.read_bytes()
    recipe_bytes = Path(__file__).read_bytes()
    parent = ROOT / 'workbench/packetdrill-builds'
    parent.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix='code-sockopt-', dir=parent))
    # Export committed bytes, never copy untracked/generated files from checkout.
    with tempfile.TemporaryFile() as archive:
        subprocess.run(['git', '-C', str(checkout), 'archive', revision],
                       stdout=archive, check=True)
        archive.seek(0)
        subprocess.run(['tar', '-xf', '-', '-C', str(build)], stdin=archive, check=True)
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=build, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=build, check=True)
    runner = build / PIN['runner']
    # Ignore caller compiler/make flags; this recipe has no configurable patch set.
    env = {key: value for key, value in os.environ.items()
           if key not in {'MAKEFLAGS', 'MFLAGS', 'MAKEFILES', 'CC', 'CFLAGS',
                          'CPPFLAGS', 'LDFLAGS', 'LDLIBS'}}
    subprocess.run(['make', '-j2', 'CC=cc', 'packetdrill'],
                   cwd=runner.parent, env=env, check=True)
    check_checkout(checkout)
    if patch.read_bytes() != patch_bytes or Path(__file__).read_bytes() != recipe_bytes:
        raise ValueError('runner patch or build recipe changed during build')
    provenance = {
        'source_revision': revision,
        'patch_sha256': hashlib.sha256(patch_bytes).hexdigest(),
        'build_helper_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'executable_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
    }
    runner.with_suffix('.provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    runner_provenance(runner)
    print(runner)


if __name__ == '__main__':
    main()
