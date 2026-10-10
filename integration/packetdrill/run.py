#!/usr/bin/env python3
import argparse
import ast
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


SENDFILE_FIXTURE = 'sendfile-five-zero-bytes'
SENDFILE_SETUP = (b'`../../common/defaults.sh\n'
                  b'/bin/rm -f /tmp/testfile\n'
                  b'/bin/dd bs=1 count=5 if=/dev/zero of=/tmp/testfile status=none\n`\n')
FIXTURE_UNSUPPORTED = 'NTCP_PACKETDRILL_FIXTURE_UNSUPPORTED:'
# Executed only in the child, before LD_PRELOAD. No upstream shell is evaluated.
FIXTURE_CHILD = r"""
import ctypes, os, pathlib, sys
try:
    if os.readlink('/proc/self/ns/mnt') == sys.argv[1]:
        raise OSError('private mount namespace unavailable')
    argv = sys.argv[2:]
    script = pathlib.Path(argv[-1])
    if (not script.is_relative_to('/tmp') or '..' in script.parts
            or script == pathlib.Path('/tmp/testfile')):
        raise ValueError('generated script must be a separate path under /tmp')
    source = script.read_bytes()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    def mount(source, target, kind, flags, data):
        if libc.mount(source, target, kind, flags, data) != 0:
            raise OSError(ctypes.get_errno(), 'fixture mount failed')
    mount(None, b'/', None, (1 << 18) | (1 << 14), None)  # recursive private
    mount(b'tmpfs', b'/tmp', b'tmpfs', 2 | 4, b'size=16m,mode=1777')
    # All writes happen after both isolation operations succeeded.
    pathlib.Path('/tmp/testfile').write_bytes(b'\0' * 5)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(source)
    os.chdir(script.parent)
    os.execvp(argv[0], argv)
except (OSError, ValueError) as error:
    print('NTCP_PACKETDRILL_FIXTURE_UNSUPPORTED:', error, flush=True)
    sys.exit(125)
"""


def fixture_command(argv, runner, plugin):
    # /tmp is deliberately hidden. Do not silently run a different executable.
    for path in (runner, plugin, Path(sys.executable)):
        if Path(path).resolve().is_relative_to('/tmp'):
            raise ValueError('isolated fixture cannot access runtime artifacts under /tmp')
    return [*argv[:4], '--mount', '--propagation', 'private',
            sys.executable, '-I', '-c', FIXTURE_CHILD,
            os.readlink('/proc/self/ns/mnt'), *argv[4:]]


TCP_INFO_FIELDS = {'tcpi_ca_state', 'tcpi_unacked', 'tcpi_sacked',
                   'tcpi_lost', 'tcpi_retrans', 'tcpi_reordering',
                   'tcpi_snd_cwnd', 'tcpi_snd_ssthresh', 'tcpi_rtt',
                   'tcpi_notsent_bytes', 'tcpi_last_data_recv', 'tcpi_busy_time',
                   'tcpi_rwnd_limited', 'tcpi_sndbuf_limited'}


TCP_INFO_SYMBOLS = {'TCP_CA_Open', 'TCP_CA_Disorder', 'TCP_CA_CWR',
                    'TCP_CA_Recovery', 'TCP_CA_Loss'}


def tcp_info_only(text):
    # Fail closed: only simple assertions over audited fields/constants. No
    # calls, imports, assignments, dynamic lookup or exception suppression.
    snippets = re.findall(r'%\{(.*?)\}%', text, re.S)
    if not snippets or text.count('%{') != len(snippets) or text.count('}%') != len(snippets):
        return False
    allowed = (ast.Module, ast.Assert, ast.Compare, ast.Name, ast.Load,
               ast.Constant, ast.BinOp, ast.UnaryOp, ast.BoolOp,
               ast.cmpop, ast.operator, ast.unaryop, ast.boolop)
    for snippet in snippets:
        try:
            tree = ast.parse(snippet.strip() + "\n\n")
        except SyntaxError:
            return False
        if not tree.body or any(not isinstance(node, ast.Assert) for node in tree.body):
            return False
        for node in ast.walk(tree):
            if not isinstance(node, allowed):
                return False
            if isinstance(node, ast.Name) and node.id not in TCP_INFO_FIELDS | TCP_INFO_SYMBOLS:
                return False
    return True


def runner_provenance(runner):
    provenance = json.loads(runner.with_suffix('.provenance.json').read_bytes())
    expected = {
        'source_revision': PIN['revision'],
        'patch_sha256': hashlib.sha256((HERE / 'code-sockopt.patch').read_bytes()).hexdigest(),
        'build_helper_sha256': hashlib.sha256((HERE / 'build_runner.py').read_bytes()).hexdigest(),
        'executable_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
    }
    if provenance != expected:
        raise ValueError('patched runner provenance differs from audited build')
    return provenance


def preflight(text, embedded_tcp_info=False):
    # Conservative safety/capability screening, NOT a second packetdrill parser.
    # Upstream --dry_run remains the authority for script syntax.
    # Inspect raw text conservatively, including comments: do not accidentally
    # strip a command concealed by comment-like characters inside a string.
    reasons = []
    if '`' in text:
        reasons.append('shell setup/assertions target Linux, not the ntcp backend')
    if '%{' in text or '}%' in text:
        if embedded_tcp_info:
            if not tcp_info_only(text):
                reasons.append('embedded code is not limited to audited TCP_INFO assertions')
            unknown = set(re.findall(r'\btcpi_\w+\b', text)) - TCP_INFO_FIELDS
            if unknown:
                reasons.append('embedded code requires unsupported TCP_INFO fields: '
                               + ', '.join(sorted(unknown)))
        else:
            reasons.append('embedded code requires a hash-audited TCP_INFO mapping')
    allowed = {'local_ip', 'remote_ip', 'tolerance_usecs', 'tcp_ts_tick_usecs',
               'strict_segments', 'ip_version', 'mss', 'tcp_ts_ecr_scaled'}
    for option in re.findall(r'^\s*--([\w_-]+)', text, re.M):
        if option not in allowed:
            reasons.append(f'script option --{option} is outside the supported profile')
    return sorted(set(reasons))


def adapt_source(directory, relative, manifest, so_flags):
    """Replace only audited setup; never rewrite assertions or fixture paths."""
    if manifest['upstream_revision'] != PIN['revision']:
        raise ValueError('adaptation revision differs from upstream pin')
    if relative not in manifest['scripts']:
        raise ValueError('script is not adaptation-allowlisted')
    entry = manifest['scripts'][relative]
    if so_flags != entry['adapter_flags']:
        raise ValueError('adapter flags differ from audited mapping')
    source = (directory / relative).read_bytes()
    setup = (directory / entry['setup_path']).read_bytes()
    for label, data, expected in (
        ('source', source, entry['source_sha256']),
        ('setup', setup, entry['setup_sha256']),
    ):
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'{label} hash differs from audited adaptation')
    for extra in entry.get('additional_setup_files', []):
        data = (directory / extra['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != extra['sha256']:
            raise ValueError(f"setup {extra['path']} hash differs from audited adaptation")
    if entry.get('blocked_reasons'):
        # Keep unavailable shell/configuration and embedded assertions untouched.
        # The caller reports the audit but must never execute this source.
        return source, dict(entry)
    command = entry['command_line'].encode()
    replacement = entry['replacement_line'].encode()
    ecn_command = (b'`../common/defaults.sh\n'
                   b'sysctl -q net.ipv4.tcp_ecn=1  # fully enabled\n`\n')
    ecn_mapped = (command == ecn_command
                  and so_flags == 'upstream-ecn,local=192.168.0.1'
                  and entry['mapping']['ntcp_settings'].get('ecn') is True
                  and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    passive_ecn_command = (b'`../common/defaults.sh\n'
                           b'sysctl -q net.ipv4.tcp_ecn=2    # server agrees to ECN if client proposes it\n`\n')
    passive_ecn_mapped = (
        relative == 'cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt'
        and command == passive_ecn_command
        and so_flags == 'upstream-cubic-ecn,local=192.168.0.1'
        and entry['mapping']['ntcp_settings'].get('ecn') is True
        and entry['mapping'].get('ecn_scope') == 'passive listener in this exact script only'
        and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    fixture_mapped = (relative == 'sendfile/sendfile-simple.pkt'
                      and command == SENDFILE_SETUP
                      and entry.get('fixture') == SENDFILE_FIXTURE
                      and so_flags == 'upstream-basic,local=192.168.0.1'
                      and entry.get('command_sha256') == hashlib.sha256(command).hexdigest())
    if entry.get('fixture') is not None and not fixture_mapped:
        raise ValueError('fixture is not the exact audited sendfile setup')
    # Only exact defaults, ECN enablement or the bounded fixture, not a shell scrubber.
    if (entry['variant'] != 'ipv4' or entry['setup_path'] != 'common/defaults.sh'
            or not (command in (b'`../common/defaults.sh`\n',
                                b'`../common/defaults.sh\n`\n',
                                b'`../../common/defaults.sh`\n',
                                b'`../../common/defaults.sh\n`\n') or ecn_mapped or passive_ecn_mapped or fixture_mapped)
            or replacement != b'// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
            or entry['expected_command_count'] != 1
            or source.count(command) != 1
            or not (source.startswith(command) or b'\n' + command in source)
            or source.count(b'`') != 2):
        raise ValueError('expected exactly one audited setup command and replacement')
    generated = source.replace(command, replacement, 1)
    reasons = preflight(generated.decode(), entry.get('embedded_tcp_info') is True)
    if reasons:
        raise ValueError('; '.join(reasons))
    return generated, {**entry, 'generated_sha256': hashlib.sha256(generated).hexdigest()}


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
        # Preserve complete diagnostic output; report consumers retain raw logs.
        output.seek(0)
        log = output.read().decode(errors='replace')
        return code, expired, log


def check_plugin_hash(plugin, expected):
    if hashlib.sha256(plugin.read_bytes()).hexdigest() != expected:
        raise ValueError('packetdrill plugin changed after backend verification')


def verify_backend(plugin, timeout):
    # An interposer must never be loaded into this runner's own Python process.
    digest = hashlib.sha256(plugin.read_bytes()).hexdigest()
    helper = ('import ctypes, sys; '
              'library = ctypes.CDLL(sys.argv[1]); '
              'identity = library.ntcp_packetdrill_backend; '
              'identity.argtypes = []; identity.restype = ctypes.c_char_p; '
              'print(identity().decode("ascii"))')
    code, expired, log = invoke([sys.executable, '-I', '-c', helper, str(plugin)],
                                plugin.parent, min(timeout, 5))
    if expired or code != 0 or log.strip() != 'ntcp-socket':
        raise ValueError('packetdrill plugin backend verification failed '
                         f'(expected ntcp-socket, returncode={code}, timeout={expired}): '
                         + log.strip())
    check_plugin_hash(plugin, digest)
    return 'ntcp-socket', digest


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


def select_cases(scripts, directory, suite, selected_variants=None, selected_scripts=None):
    known_variants = set(PIN['variants']) if suite in ('upstream', 'adapted') else {'native-ipv4'}
    for variant in selected_variants or []:
        if variant not in known_variants:
            raise ValueError(f'--variant {variant!r} is invalid for suite {suite}')
    names = {str(script.relative_to(directory)) for script in scripts}
    for script in selected_scripts or []:
        if script not in names:
            raise ValueError(f'--script {script!r} is not an exact eligible relative path')
    selected, excluded = [], []
    for script in scripts:
        relative = str(script.relative_to(directory))
        for variant, flags in variants(script, suite in ('upstream', 'adapted')):
            reasons = []
            if selected_scripts is not None and relative not in selected_scripts:
                reasons.append('excluded by --script selection')
            if selected_variants is not None and variant not in selected_variants:
                reasons.append('excluded by --variant selection')
            if reasons:
                excluded.append({'script': relative, 'variant': variant,
                                 'suite': suite, 'reasons': reasons})
            else:
                selected.append((script, variant, flags))
    if not selected:
        raise ValueError('selection matches no eligible packetdrill cases')
    return selected, excluded


def profile_metadata(so_flags):
    profiles = [flag for flag in so_flags.split(',') if not flag.startswith('local=')]
    profile = profiles[0] if len(profiles) == 1 else None
    known = profile in {
        'baseline', 'sack', 'upstream-window8', 'upstream-sack', 'upstream-ecn',
        'upstream-basic', 'upstream-cubic', 'upstream-cubic-ecn',
        'pipeline', 'pipeline-paced', 'pipeline-gso', 'pipeline-paced-gso'}
    # Configuration/capture boundary only: not measured timing or Linux fq/TSO equivalence.
    return {
        'profile': profile,
        'transport_clock': 'monotonic Instant elapsed microseconds' if known else None,
        'prr_pacing': profile not in {'upstream-cubic', 'upstream-cubic-ecn'} if known else None,
        'transmit_batch_clock': 'monotonic sample per selection/accept' if known else None,
        'egress_pipeline': 'shared production scheduler' if known else None,
        'general_pacing': profile in {'pipeline-paced', 'pipeline-paced-gso'} if known else None,
        'software_gso': profile in {'pipeline-gso', 'pipeline-paced-gso'} if known else None,
        'capture_boundary': 'individual raw IPv4 TCP wire segments' if known else None,
        'capture_clock': 'realtime epoch microseconds at backend submission' if known else None,
        'hardware_tso': False if known else None,
        'gro': False if known else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--runner', type=Path,
                        help='explicit patched executable produced by build_runner.py')
    parser.add_argument('--plugin', type=Path,
                        default=ROOT / 'target/debug/libntcp_packetdrill.so')
    parser.add_argument('--suite', choices=['smoke', 'sack', 'upstream', 'adapted'], default='smoke')
    parser.add_argument('--variant', action='append',
                        choices=['native-ipv4', *PIN['variants']],
                        help='select a suite variant (repeatable; default: all eligible variants)')
    parser.add_argument('--script', action='append',
                        help='select an exact suite-relative script path (repeatable)')
    parser.add_argument('--report', type=Path,
                        default=ROOT / 'workbench/packetdrill/report.json')
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--so-flags')
    args = parser.parse_args()
    if args.so_flags is None and args.suite != 'adapted':
        args.so_flags = ('sack,local=192.0.2.1' if args.suite == 'sack' else
                         'baseline,local=192.0.2.1' if args.suite == 'smoke' else
                         'baseline,local=192.168.0.1')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be finite and positive')
    checkout = args.checkout.resolve()
    plugin = args.plugin.resolve()
    try:
        revision = check_checkout(checkout)
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        parser.error(str(error))
    runner = args.runner.resolve() if args.runner else checkout / PIN['runner']
    try:
        provenance = runner_provenance(runner) if args.runner else None
    except (ValueError, OSError) as error:
        parser.error(str(error))

    def check_runner():
        try:
            if provenance is not None and runner_provenance(runner) != provenance:
                raise ValueError('patched runner changed during execution')
        except (ValueError, OSError) as error:
            parser.error(str(error))

    def invoke_runner(argv, cwd, timeout):
        check_runner()
        result = invoke(argv, cwd, timeout)
        check_runner()
        return result
    if not runner.is_file() or not os.access(runner, os.X_OK):
        parser.error(f'build the pinned external runner first: {runner}')
    if not plugin.is_file():
        parser.error(f'build ntcp-packetdrill first: {plugin}')
    try:
        socket_backend, plugin_sha256 = verify_backend(plugin, args.timeout)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    manifest_bytes = (HERE / 'adaptations.json').read_bytes() if args.suite == 'adapted' else None
    manifest = json.loads(manifest_bytes) if manifest_bytes is not None else None
    upstream = args.suite in ('upstream', 'adapted')
    directory = (checkout / PIN['tcp_tests'] if upstream else
                 HERE / ('sack-tests' if args.suite == 'sack' else 'tests'))
    upstream_scripts = []
    if upstream:
        tracked = subprocess.check_output(
            ['git', '-C', str(checkout), 'ls-files', '-z', '--', PIN['tcp_tests']],
            text=True,
        ).split('\0')
        upstream_scripts = sorted(checkout / path for path in tracked if path.endswith('.pkt'))
        scripts = (sorted(directory / path for path in manifest['scripts'])
                   if manifest is not None else upstream_scripts)
        if any(script not in upstream_scripts for script in scripts):
            parser.error('adaptation allowlist contains an untracked upstream script')
    else:
        scripts = sorted(directory.rglob('*.pkt'))
    if not scripts:
        parser.error(f'no .pkt tests found in {directory}')
    results = []
    try:
        cases, excluded = select_cases(scripts, directory, args.suite,
                                       args.variant, args.script)
    except ValueError as error:
        parser.error(str(error))
    selected_script_files = len({script for script, _, _ in cases})
    with tempfile.TemporaryDirectory(prefix='ntcp-packetdrill-') as temporary:
        for script, variant, flags in cases:
            source = script.read_bytes()
            text = source.decode()
            row = {'script': str(script.relative_to(directory)), 'variant': variant,
                   'suite': args.suite, 'adapted': False,
                   'sha256': hashlib.sha256(source).hexdigest(),
                   'effective_flags': {'adapter': args.so_flags, 'packetdrill': flags},
                   'syntax_returncode': None, 'behavior_executed': False,
                   'stage': 'adaptation' if manifest is not None else 'syntax'}
            so_flags = args.so_flags
            if manifest is not None and so_flags is None:
                so_flags = manifest['scripts'][row['script']]['adapter_flags']
            row['effective_flags']['adapter'] = so_flags
            row['effective_flags'].update(profile_metadata(so_flags))
            execution_script = script
            if manifest is not None:
                try:
                    generated, audit = adapt_source(directory, row['script'], manifest,
                                                    so_flags)
                    row['adaptation'] = audit
                    if audit.get('blocked_reasons'):
                        row.update(status='unsupported', reasons=audit['blocked_reasons'])
                    elif variant != 'ipv4':
                        row.update(status='unsupported', reasons=['adaptation supports IPv4 only'])
                    else:
                        execution_script = Path(temporary) / script.name
                        execution_script.write_bytes(generated)
                        text = generated.decode()
                        row['adapted'] = True
                except (ValueError, OSError) as error:
                    row.update(status='adaptation_rejected', reasons=[str(error)])
            if 'status' not in row:
                row['stage'] = 'syntax'
                code, expired, log = invoke_runner(
                    [str(runner), '--dry_run', *flags, str(execution_script)],
                    execution_script.parent, args.timeout)
                row['syntax_returncode'] = code
                row['syntax_log'] = log
                if code != 0 or expired:
                    row.update(status='syntax_error' if code is not None and not expired
                               else 'environment_error', log=log)
                else:
                    row['stage'] = 'preflight'
                    embedded_tcp_info = (row['adapted'] and
                                         row['adaptation'].get('embedded_tcp_info') is True)
                    reasons = preflight(text, embedded_tcp_info)
                    if variant not in ('native-ipv4', 'ipv4'):
                        reasons.append('the adapter implements IPv4 only')
                    if reasons:
                        row.update(status='unsupported', reasons=reasons)
                    else:
                        # Namespace isolation is required, never fall back to host.
                        # Teardown and direct libc calls must share the plugin's socket registry.
                        preload = ['env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}']
                        row['effective_flags']['preload'] = str(plugin)
                        code_flags = (['--code_sockopt=TCP_INFO']
                                      if provenance is not None and embedded_tcp_info
                                      and tcp_info_only(text) else [])
                        row['effective_flags']['packetdrill'] = [*flags, *code_flags]
                        argv = ['unshare', '--user', '--map-root-user', '--net',
                                *preload, str(runner), f'--so_filename={plugin}',
                                f'--so_flags={so_flags}', *flags, *code_flags, str(execution_script)]
                        fixture = row.get('adaptation', {}).get('fixture')
                        if fixture:
                            try:
                                argv = fixture_command(argv, runner, plugin)
                            except (ValueError, OSError) as error:
                                row.update(status='unsupported', stage='environment',
                                           reasons=[str(error)])
                                results.append(row)
                                print(f'unsupported: {row["script"]} ({variant}, {args.suite})', flush=True)
                                continue
                            row['effective_flags']['fixture'] = fixture
                        try:
                            check_plugin_hash(plugin, plugin_sha256)
                            code, expired, log = invoke_runner(argv, execution_script.parent, args.timeout)
                            check_plugin_hash(plugin, plugin_sha256)
                        except (ValueError, OSError) as error:
                            parser.error(str(error))
                        status = outcome(code, expired, log)
                        fixture_unavailable = fixture and (
                            FIXTURE_UNSUPPORTED in log or log.startswith('unshare:')
                            or status == 'environment_error')
                        if fixture_unavailable:
                            status = 'unsupported'
                            row['reasons'] = ['isolated fixture unavailable: ' + log.strip()]
                        row.update(status=status, returncode=code,
                                   stage='environment' if status == 'environment_error' or fixture_unavailable else 'behavior',
                                   behavior_executed=status != 'environment_error' and not fixture_unavailable, log=log)
            results.append(row)
            print(f'{row["status"]}: {row["script"]} ({variant}, {args.suite})', flush=True)
    try:
        check_plugin_hash(plugin, plugin_sha256)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    check_runner()
    counts = dict(collections.Counter(row['status'] for row in results))
    report = {'upstream_revision': revision, 'suite': args.suite,
              'adapter_flags': args.so_flags, 'script_files': selected_script_files,
              'eligible_script_files': len(scripts),
              'eligible_total': len(cases) + len(excluded),
              'selected_total': len(cases), 'excluded_total': len(excluded),
              'selection': {'variants': args.variant, 'scripts': args.script},
              'excluded_cases': excluded,
              'syntax_valid': sum(row['syntax_returncode'] == 0 for row in results),
              'behavior_executed': sum(row['behavior_executed'] for row in results),
              'runner_path': str(runner),
              'runner_provenance': provenance,
              'runner_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
              'plugin_path': str(plugin),
              'plugin_sha256': plugin_sha256,
              'socket_backend': socket_backend,
              'counts': counts, 'total': len(results), 'results': results,
              'all_passed': bool(results) and len(results) == len(cases) and all(
                  row['status'] == 'passed' and row['behavior_executed']
                  for row in results)}
    if upstream:
        report['coverage'] = {'selected_script_files': selected_script_files,
                              'upstream_script_files': len(upstream_scripts),
                              'selection': 'adaptation_allowlist' if manifest is not None
                              else 'all_tracked_upstream_scripts'}
    if manifest is not None:
        report['adaptation_manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(counts, sort_keys=True))
    # Unsupported/syntax-only checks are NEVER reported as a passing suite.
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
