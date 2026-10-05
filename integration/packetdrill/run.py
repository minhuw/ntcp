#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PIN = json.loads((HERE / 'upstream.json').read_text())


def preflight(text):
    # Conservative safety/capability screening, NOT a second packetdrill parser.
    # Upstream --dry_run remains the authority for script syntax.
    # Inspect raw text conservatively, including comments: do not accidentally
    # strip a command concealed by comment-like characters inside a string.
    reasons = []
    if '`' in text:
        reasons.append('shell setup/assertions target Linux, not the ntcp backend')
    if '%{' in text or '}%' in text:
        reasons.append('embedded code is outside the supported adapter profile')
    allowed = {'local_ip', 'remote_ip', 'tolerance_usecs', 'tcp_ts_tick_usecs',
               'strict_segments', 'ip_version', 'mss', 'tcp_ts_ecr_scaled'}
    for option in re.findall(r'^\s*--([\w_-]+)', text, re.M):
        if option not in allowed:
            reasons.append(f'script option --{option} is outside the supported profile')
    if re.search(r'^\s*[^\n]*>[^\n]*\bsackOK\b', text, re.M):
        reasons.append('expects SACK negotiation, which ntcp does not implement')
    return sorted(set(reasons))


def invoke(argv, cwd, timeout):
    # Kill the whole process group on timeout; packetdrill has worker threads and
    # may spawn helper processes. Never leave an external test running behind CI.
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            return None, False, str(error)
        expired = False
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
        output.seek(0, os.SEEK_END)
        size = output.tell()
        output.seek(max(0, size - 16384))
        log = output.read().decode(errors='replace')
        return code, expired, log


def outcome(code, expired, log):
    if expired:
        return 'timeout'
    if 'NTCP_PACKETDRILL_FAILURE:' in log or code is not None and code < 0:
        return 'failed'
    if 'NTCP_PACKETDRILL_UNSUPPORTED:' in log:
        return 'unsupported'
    if code is None:
        return 'environment_error'
    if code == 0:
        return 'passed'
    if any(message in log for message in (
        'unshare: unshare failed', 'mlockall:', 'mlockall failed',
        'error while loading shared libraries', 'cannot open shared object file',
    )):
        return 'environment_error'
    return 'failed'


def check_checkout(checkout):
    actual = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'],
                                     text=True).strip()
    if actual != PIN['revision']:
        raise ValueError(f'packetdrill revision {actual} differs from pin {PIN["revision"]}')
    if subprocess.run(['git', '-C', str(checkout), 'diff', '--quiet', 'HEAD', '--',
                       'gtests/net'], check=False).returncode != 0:
        raise ValueError('packetdrill checkout has modified tracked runner/tests')
    return actual


def variants(script, upstream):
    if not upstream:
        return [('native-ipv4', [])]
    # Match the filename selection and argument sets of the pinned run_all.py.
    return [(name, args) for name, args in PIN['variants'].items()
            if not (script.name.endswith('v6.pkt') and name != 'ipv6')
            and not (script.name.endswith('v4.pkt') and name == 'ipv6')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--plugin', type=Path,
                        default=ROOT / 'target/debug/libntcp_packetdrill.so')
    parser.add_argument('--suite', choices=['smoke', 'upstream'], default='smoke')
    parser.add_argument('--report', type=Path,
                        default=ROOT / 'workbench/packetdrill/report.json')
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--so-flags')
    args = parser.parse_args()
    if args.so_flags is None:
        args.so_flags = ('baseline,local=192.168.0.1' if args.suite == 'upstream'
                         else 'baseline,local=192.0.2.1')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be finite and positive')
    checkout = args.checkout.resolve()
    plugin = args.plugin.resolve()
    try:
        revision = check_checkout(checkout)
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        parser.error(str(error))
    runner = checkout / PIN['runner']
    if not runner.is_file() or not os.access(runner, os.X_OK):
        parser.error(f'build the pinned external runner first: {runner}')
    if not plugin.is_file():
        parser.error(f'build ntcp-packetdrill first: {plugin}')
    directory = checkout / PIN['tcp_tests'] if args.suite == 'upstream' else HERE / 'tests'
    if args.suite == 'upstream':
        tracked = subprocess.check_output(
            ['git', '-C', str(checkout), 'ls-files', '-z', '--', PIN['tcp_tests']],
            text=True,
        ).split('\0')
        scripts = sorted(checkout / path for path in tracked if path.endswith('.pkt'))
    else:
        scripts = sorted(directory.rglob('*.pkt'))
    if not scripts:
        parser.error(f'no .pkt tests found in {directory}')
    results = []
    cases = [(script, variant, flags) for script in scripts
             for variant, flags in variants(script, args.suite == 'upstream')]
    for script, variant, flags in cases:
        text = script.read_text()
        row = {'script': str(script.relative_to(directory)), 'variant': variant,
               'sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
               'behavior_executed': False}
        code, expired, log = invoke([str(runner), '--dry_run', *flags, str(script)],
                                    script.parent, args.timeout)
        row['syntax_returncode'] = code
        if code != 0 or expired:
            row.update(status='syntax_error' if code is not None and not expired
                       else 'environment_error', log=log)
        else:
            reasons = preflight(text)
            if variant not in ('native-ipv4', 'ipv4'):
                reasons.append('the adapter implements IPv4 only')
            if reasons:
                row.update(status='unsupported', reasons=reasons,
                           behavior_executed=False)
            else:
                # Namespace isolation is required, never silently fall back to host.
                argv = ['unshare', '--user', '--map-root-user', '--net',
                        str(runner), f'--so_filename={plugin}',
                        f'--so_flags={args.so_flags}', *flags, str(script)]
                code, expired, log = invoke(argv, script.parent, args.timeout)
                row.update(status=outcome(code, expired, log), returncode=code,
                           behavior_executed=True, log=log)
        results.append(row)
        print(f'{row["status"]}: {row["script"]} ({variant})', flush=True)
    counts = dict(collections.Counter(row['status'] for row in results))
    report = {'upstream_revision': revision, 'suite': args.suite,
              'adapter_flags': args.so_flags, 'script_files': len(scripts),
              'syntax_valid': sum(row['syntax_returncode'] == 0 for row in results),
              'behavior_executed': sum(row['behavior_executed'] for row in results),
              'runner_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
              'plugin_sha256': hashlib.sha256(plugin.read_bytes()).hexdigest(),
              'counts': counts, 'total': len(results), 'results': results,
              'all_passed': all(row['status'] == 'passed' for row in results)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(counts, sort_keys=True))
    # Unsupported/syntax-only checks are NEVER reported as a passing suite.
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
