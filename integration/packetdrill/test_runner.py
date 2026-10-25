import copy
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from expectations import PORTED_SCRIPTS

from run import (CACHE_FLUSH_SCRIPT, SYN_DATA_ACK_SCRIPTS, TIMESTAMP_SOURCES, RESOURCE_SCRIPT, RESOURCE_EVENT, RESOURCE_CONTROL, SLOW_START_ACK_SCRIPTS, FASTOPEN_CLIENT_SCRIPTS, NON_TFO_SETUP_COMMANDS, ADAPTIVE_ACK_SCRIPTS, FASTOPEN_PMTUD_SCRIPTS, LINUX_COOKIE_SCRIPTS, FIXTURE_CHILD, FIXTURE_UNSUPPORTED, SENDFILE_FIXTURE, SENDFILE_SETUP,
                 fixture_command, HERE, PIN, adapt_source, check_plugin_hash, invoke, main, outcome,
                 preflight, profile_metadata, select_cases, variants, verify_backend)


def mock_backend(test):
    # Main-flow fixtures mock executable boundaries, not behavioral passes.
    patcher = patch('run.verify_backend', side_effect=lambda plugin, timeout:
                    ('ntcp-socket', hashlib.sha256(plugin.read_bytes()).hexdigest()))
    patcher.start()
    test.addCleanup(patcher.stop)


BASIC17 = (
    'blocking/blocking-accept.pkt',
    'blocking/blocking-connect.pkt',
    'blocking/blocking-read.pkt',
    'blocking/blocking-write.pkt',
    'close/close-local-close-then-remote-fin.pkt',
    'close/close-on-syn-sent.pkt',
    'close/close-remote-fin-then-close.pkt',
    'ioctl/ioctl-siocinq-fin.pkt',
    'shutdown/shutdown-rd-close.pkt',
    'shutdown/shutdown-rd-wr-close.pkt',
    'shutdown/shutdown-rdwr-close.pkt',
    'shutdown/shutdown-rdwr-send-queue-ack-close.pkt',
    'shutdown/shutdown-rdwr-write-queue-close.pkt',
    'shutdown/shutdown-wr-close.pkt',
    'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt',
    'syscall_bad_arg/sendmsg-empty-iov.pkt',
    'syscall_bad_arg/syscall-invalid-buf-ptr.pkt',
)
CONGESTION18 = (
    'cubic/cubic-bulk-166k-idle-restart.pkt',
    'cubic/cubic-bulk-166k.pkt',
    'cubic/cubic-hystart-delay-min-rtt-jumps-downward.pkt',
    'cubic/cubic-hystart-delay-rtt-jumps-upward.pkt',
    'cubic/cubic-rack-reo-timeout-retrans-failed-incoming-data.pkt',
    'cubic/cubic-rto-ss-ca-cwnd-bump.pkt',
    'cwnd_moderation/cwnd-moderation-disorder-no-moderation.pkt',
    'cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt',
    'slow_start/slow-start-ack-per-1pkt.pkt',
    'slow_start/slow-start-ack-per-2pkt-send-5pkt.pkt',
    'slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt',
    'slow_start/slow-start-ack-per-2pkt.pkt',
    'slow_start/slow-start-ack-per-4pkt.pkt',
    'slow_start/slow-start-after-idle.pkt',
    'slow_start/slow-start-after-win-update.pkt',
    'slow_start/slow-start-app-limited-9-packets-out.pkt',
    'slow_start/slow-start-app-limited.pkt',
    'slow_start/slow-start-fq-ack-per-2pkt.pkt',
)
PASSIVE_CUBIC_ECN = 'cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt'
DEFAULTS_ONLY_CUBIC = {
    'cubic/cubic-rto-ss-ca-cwnd-bump.pkt',
    'cwnd_moderation/cwnd-moderation-disorder-no-moderation.pkt',
    'slow_start/slow-start-ack-per-2pkt-send-5pkt.pkt',
    'slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt',
    'slow_start/slow-start-app-limited-9-packets-out.pkt',
    'slow_start/slow-start-app-limited.pkt',
}

SOCKET_FEATURE19 = (
    'epoll/epoll_in_edge.pkt',
    'epoll/epoll_out_edge.pkt',
    'epoll/epoll_out_edge_default_notsent_lowat.pkt',
    'epoll/epoll_out_edge_notsent_lowat.pkt',
    'inq/client.pkt', 'inq/server.pkt',
    'notsent_lowat/notsent-lowat-default.pkt',
    'notsent_lowat/notsent-lowat-setsockopt.pkt',
    'notsent_lowat/notsent-lowat-sysctl.pkt',
    'eor/no-coalesce-large.pkt', 'eor/no-coalesce-retrans.pkt',
    'eor/no-coalesce-small.pkt', 'eor/no-coalesce-subsequent.pkt',
    'nagle/https_client.pkt', 'nagle/sendmsg_msg_more.pkt',
    'nagle/sockopt_cork_nodelay.pkt',
    'tcp_info/tcp-info-last_data_recv.pkt',
    'tcp_info/tcp-info-rwnd-limited.pkt',
    'tcp_info/tcp-info-sndbuf-limited.pkt',
)
SOCKET43 = BASIC17 + SOCKET_FEATURE19 + (
    'sendfile/sendfile-simple.pkt', 'splice/tcp_splice_loop_test.pkt',
    'timestamping/client-only-last-byte.pkt', 'timestamping/partial.pkt',
    'timestamping/server.pkt', 'user_timeout/user-timeout-probe.pkt',
    'user_timeout/user_timeout.pkt',
)


class RunnerChecks(unittest.TestCase):
    def test_preflight_does_not_ignore_kernel_setup_or_change_packet_expectations(self):
        self.assertEqual(preflight('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3'), [])
        self.assertTrue(preflight('`../common/defaults.sh`'))
        self.assertTrue(preflight('0 %{ assert tcpi_snd_cwnd == 10 }%'))
        self.assertTrue(preflight('--init_scripts=/tmp/script'))
        self.assertTrue(preflight('--so_filename=other.so'))
        self.assertTrue(preflight('--wire_server'))
        self.assertEqual(preflight('0 > S. 0:0(0) ack 1 <mss 1460,sackOK>'), [])
        self.assertEqual(preflight('0 < S 0:0(0) win 1000 <sackOK>'), [])
        self.assertEqual(preflight('--tolerance_usecs=10000\n0 > . 1:1(0) ack 1'), [])

    def test_embedded_code_requires_audited_capability_and_known_fields(self):
        text = '0 %{ assert tcpi_lost == 0 }%'
        self.assertTrue(preflight(text))
        self.assertEqual(preflight(text, embedded_tcp_info=True), [])
        self.assertEqual(preflight('0 %{ assert tcpi_snd_cwnd == 7\n'
                                   'assert tcpi_snd_ssthresh == 7 }%', True), [])
        self.assertEqual(preflight('0 %{ assert tcpi_rtt > 0 }%', True), [])
        for field in ('tcpi_notsent_bytes', 'tcpi_last_data_recv', 'tcpi_busy_time',
                      'tcpi_rwnd_limited', 'tcpi_sndbuf_limited'):
            text = f'0 %{{ assert {field} > 0 }}%'
            self.assertTrue(preflight(text))  # Still requires a hash-audited mapping.
            self.assertEqual(preflight(text, True), [])
        self.assertTrue(preflight('0 %{ assert tcpi_pacing_rate == 0 }%', True))
        self.assertTrue(preflight('`sysctl something`\n' + text, True))

    def test_options_only_audited_masks_and_delivery_fields(self):
        for expression in ('tcpi_delivered == 1', 'tcpi_snd_wscale == 3',
                           'tcpi_rcv_wscale == 14',
                           '(tcpi_options & TCPI_OPT_SYN_DATA) != 0',
                           '(TCPI_OPT_ECN & tcpi_options) == 0',
                           'tcpi_options & (TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK | TCPI_OPT_WSCALE)',
                           '(tcpi_options & 47) == 15'):
            text = '0 %{ assert ' + expression + ' }%'
            self.assertEqual(preflight(text, True), [], expression)
            self.assertTrue(preflight(text), expression)
        for expression in ('tcpi_options == 0', 'tcpi_options',
                           '(tcpi_options & 255) == 0', '(tcpi_options & -1) == 0',
                           'tcpi_options & (1 << 4)', 'tcpi_options & tcpi_lost',
                           '(tcpi_options >> 4) & 1', '(tcpi_options | 16) == 16',
                           '(tcpi_options & (47 | 16)) == 0',
                           'tcpi_options & TCPI_OPT_ECN_SEEN',
                           'tcpi_options & TCPI_OPT_USEC_TS',
                           'tcpi_options & TCPI_OPT_TFO_CHILD',
                           'tcpi_delivered_ce == 0', 'tcpi_delivered_ce_bytes == 0',
                           'tcpi_bytes_acked == 0', 'tcpi_total_retrans == 0'):
            self.assertTrue(preflight('0 %{ assert ' + expression + ' }%', True), expression)

    def test_upstream_variants_preserve_wrapper_parameters(self):
        both = dict(variants(Path('basic.pkt'), True))
        self.assertEqual(set(both), {'ipv4', 'ipv6', 'ipv4-mapped-v6'})
        self.assertIn('TFO_COOKIE=3021b9d889017eeb', both['ipv4'])
        self.assertEqual([name for name, _ in variants(Path('basic-v6.pkt'), True)],
                         ['ipv6'])
        self.assertEqual([name for name, _ in variants(Path('basic-v4.pkt'), True)],
                         ['ipv4', 'ipv4-mapped-v6'])
        self.assertEqual(variants(Path('basic.pkt'), False), [('native-ipv4', [])])

    def test_nonpasses_are_not_silently_promoted(self):
        self.assertEqual(outcome(0, False, ''), 'passed')
        self.assertEqual(outcome(1, False, 'packet mismatch'), 'failed')
        self.assertEqual(outcome(0, False, 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO'),
                         'unsupported')
        self.assertEqual(outcome(-signal.SIGSEGV, False, ''), 'failed')
        self.assertEqual(outcome(-signal.SIGSEGV, False,
                                 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO'), 'failed')
        self.assertEqual(outcome(0, False,
                                 'NTCP_PACKETDRILL_FAILURE: callback panicked'), 'failed')
        self.assertEqual(outcome(1, False,
                                 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO\n'
                                 'NTCP_PACKETDRILL_FAILURE: owner panicked'), 'failed')
        self.assertEqual(outcome(None, False, 'not found'), 'environment_error')
        self.assertEqual(outcome(1, False, 'unshare: unshare failed'), 'environment_error')
        self.assertEqual(outcome(-9, True, ''), 'timeout')

    def test_invoke_preserves_full_raw_output(self):
        with tempfile.TemporaryDirectory() as cwd:
            code, expired, log = invoke(
                [sys.executable, '-c', 'print("a" * 20000)'], cwd, 5)
            self.assertEqual((code, expired, log), (0, False, 'a' * 20000 + '\n'))

    def test_process_exit_timeout_and_missing_executable(self):
        with tempfile.TemporaryDirectory() as cwd:
            code, expired, log = invoke([sys.executable, '-c', 'print("ok")'], cwd, 5)
            self.assertEqual((code, expired, log.strip()), (0, False, 'ok'))
            code, expired, _ = invoke([sys.executable, '-c', 'import time; time.sleep(10)'],
                                      cwd, 0.1)
            self.assertTrue(expired)
            self.assertEqual(code, -signal.SIGKILL)
            code, expired, _ = invoke([str(Path(cwd) / 'missing')], cwd, 1)
            self.assertIsNone(code)
            self.assertFalse(expired)


class BackendChecks(unittest.TestCase):
    def test_isolated_identity_rejects_stale_wrong_null_and_absent_libraries(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('C compiler unavailable for identity-only shared-library fixtures')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plugin = directory / 'plugin.so'
            with self.assertRaises(OSError):
                verify_backend(plugin, 5)
            for source, valid in (
                ('int legacy_backend(void) { return 0; }', False),
                ('const char *ntcp_packetdrill_backend(void) { return "legacy"; }', False),
                ('const char *ntcp_packetdrill_backend(void) { return 0; }', False),
                ('const char *ntcp_packetdrill_backend(void) { return "ntcp-socket"; }', True),
            ):
                with self.subTest(source=source):
                    subprocess.run([compiler, '-shared', '-fPIC', '-x', 'c', '-',
                                    '-o', str(plugin)], input=source, text=True, check=True,
                                   capture_output=True)
                    if valid:
                        backend, digest = verify_backend(plugin, 5)
                        self.assertEqual(backend, 'ntcp-socket')
                        self.assertEqual(digest, hashlib.sha256(plugin.read_bytes()).hexdigest())
                        check_plugin_hash(plugin, digest)
                        plugin.write_bytes(b'changed')
                        with self.assertRaisesRegex(ValueError, 'changed after backend verification'):
                            check_plugin_hash(plugin, digest)
                    else:
                        with self.assertRaisesRegex(ValueError, 'backend verification failed'):
                            verify_backend(plugin, 5)

    def test_identity_helper_is_bounded_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            plugin = Path(temporary) / 'plugin.so'
            plugin.write_bytes(b'identity fixture')
            with patch('run.invoke', return_value=(0, False, 'ntcp-socket\n')) as execute:
                verify_backend(plugin, 30)
            argv, cwd, timeout = execute.call_args.args
            self.assertEqual(argv[:3], [sys.executable, '-I', '-c'])
            self.assertEqual(argv[-1], str(plugin))
            self.assertEqual((cwd, timeout), (plugin.parent, 5))
            for result in ((-9, True, ''), (-11, False, ''),
                           (0, False, 'ntcp-socket\nNTCP_PACKETDRILL_FAILURE: error')):
                with patch('run.invoke', return_value=result):
                    with self.assertRaisesRegex(ValueError, 'backend verification failed'):
                        verify_backend(plugin, 0.1)

            def replace_library(*args):
                plugin.write_bytes(b'replacement')
                return 0, False, 'ntcp-socket\n'

            with patch('run.invoke', side_effect=replace_library):
                with self.assertRaisesRegex(ValueError, 'changed after backend verification'):
                    verify_backend(plugin, 5)


class SelectionChecks(unittest.TestCase):
    def setUp(self):
        mock_backend(self)

    def test_main_rejects_unverified_and_replaced_plugins_without_passing_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('runner')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            tests = checkout / 'tests'
            tests.mkdir()
            (tests / 'basic.pkt').write_text('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3')
            report = checkout / 'report.json'
            argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                    '--report', str(report)]
            with patch('run.HERE', checkout), \
                    patch('run.check_checkout', return_value=PIN['revision']), \
                    patch.object(sys, 'argv', argv):
                plugin.write_bytes(b'plugin')
                with patch('run.verify_backend', side_effect=ValueError('wrong backend')), \
                        patch('run.invoke') as execute:
                    with self.assertRaises(SystemExit) as error:
                        main()
                    self.assertEqual(error.exception.code, 2)
                    execute.assert_not_called()
                    self.assertFalse(report.exists())
                for replace_on_call in (1, 2):
                    plugin.write_bytes(b'plugin')
                    calls = []

                    def execute(*args):
                        calls.append(args)
                        if len(calls) == replace_on_call:
                            plugin.write_bytes(b'replaced')
                        return 0, False, ''

                    with patch('run.invoke', side_effect=execute):
                        with self.assertRaises(SystemExit) as error:
                            main()
                    self.assertEqual(error.exception.code, 2)
                    self.assertEqual(len(calls), replace_on_call)
                    self.assertFalse(report.exists())

    def test_selection_combinations_and_exclusion_reasons(self):
        directory = Path('/tests')
        scripts = [directory / name for name in ('basic.pkt', 'only-v4.pkt', 'only-v6.pkt')]
        for suite in ('upstream-raw', 'upstream'):
            for variant_filter, script_filter, expected in (
                (None, None, 6),
                (['ipv4'], None, 2),
                (['ipv4', 'ipv6'], None, 4),
                (None, ['basic.pkt'], 3),
                (['ipv4'], ['basic.pkt', 'only-v4.pkt'], 2),
                (['ipv4', 'ipv4'], ['basic.pkt', 'basic.pkt'], 1),
            ):
                with self.subTest(suite=suite, variants=variant_filter, scripts=script_filter):
                    selected, excluded = select_cases(scripts, directory, suite,
                                                      variant_filter, script_filter)
                    self.assertEqual(len(selected), expected)
                    self.assertEqual(len(selected) + len(excluded), 6)
                    for row in excluded:
                        reasons = []
                        if script_filter is not None and row['script'] not in script_filter:
                            reasons.append('excluded by --script selection')
                        if variant_filter is not None and row['variant'] not in variant_filter:
                            reasons.append('excluded by --variant selection')
                        self.assertEqual(row['reasons'], reasons)
                        self.assertTrue(reasons)
        selected, excluded = select_cases(scripts, directory, 'smoke',
                                          ['native-ipv4'], ['basic.pkt'])
        self.assertEqual(selected, [(scripts[0], 'native-ipv4', [])])
        self.assertEqual(len(excluded), 2)

    def test_invalid_and_empty_selections(self):
        directory = Path('/tests')
        scripts = [directory / 'only-v6.pkt']
        for suite, variant_filter, script_filter in (
            ('smoke', ['ipv4'], None),
            ('upstream-raw', ['native-ipv4'], None),
            ('upstream', ['unknown'], None),
            ('upstream-raw', [''], None),
            ('upstream-raw', [], None),
            ('upstream-raw', ['ipv4'], ['only-v6.pkt']),
            ('upstream-raw', None, []),
            *[('upstream-raw', None, [name]) for name in
              ('', 'missing.pkt', '*.pkt', '/tests/only-v6.pkt',
               './only-v6.pkt', '../tests/only-v6.pkt', 'only-v6.pkt/')],
        ):
            with self.subTest(suite=suite, variants=variant_filter, scripts=script_filter):
                with self.assertRaises(ValueError):
                    select_cases(scripts, directory, suite, variant_filter, script_filter)
        with self.assertRaises(ValueError):
            select_cases([], directory, 'smoke')

    def test_old_adapted_suite_is_rejected(self):
        with patch.object(sys, 'argv', ['run.py', '--checkout', '/unused',
                                        '--suite', 'adapted']), \
                patch('run.check_checkout') as check:
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            check.assert_not_called()

    def test_main_smoke_and_upstream_raw_reporting_status_and_argument_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('runner')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('plugin')
            report = checkout / 'report.json'
            for suite in ('smoke', 'sack', 'upstream-raw'):
                native = suite in ('smoke', 'sack')
                directory = checkout / ('sack-tests' if suite == 'sack' else
                                        'tests' if suite == 'smoke' else PIN['tcp_tests'])
                directory.mkdir(parents=True, exist_ok=True)
                for name in ('basic.pkt', 'other.pkt'):
                    (directory / name).write_text('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3')
                tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                                    for name in ('basic.pkt', 'other.pkt'))
                argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                        '--suite', suite, '--report', str(report)]
                variant = 'native-ipv4' if native else 'ipv4'
                filters = ['--variant', variant, '--script', 'basic.pkt']
                with patch('run.HERE', checkout), \
                        patch('run.check_checkout', return_value=PIN['revision']), \
                        patch('run.subprocess.check_output', return_value=tracked):
                    for code, expired, log, status in (
                        (0, False, '', 'passed'),
                        (1, False, 'packet mismatch', 'failed'),
                        (0, False, 'NTCP_PACKETDRILL_UNSUPPORTED: test', 'unsupported'),
                        (1, False, 'unshare: unshare failed', 'environment_error'),
                        (-9, True, '', 'timeout'),
                    ):
                        with patch.object(sys, 'argv', argv + filters), patch('run.invoke',
                                side_effect=[(0, False, ''), (code, expired, log)]) as execute:
                            self.assertEqual(main(), 0 if status == 'passed' else 1)
                        data = json.loads(report.read_text())
                        self.assertEqual(data['suite'], suite)
                        self.assertEqual(data['results'][0]['suite'], suite)
                        self.assertFalse(data['results'][0]['adapted'])
                        self.assertNotIn('adaptation', data['results'][0])
                        self.assertNotIn('adaptation_manifest_sha256', data)
                        self.assertEqual(data['socket_backend'], 'ntcp-socket')
                        self.assertEqual(data['plugin_sha256'], hashlib.sha256(plugin.read_bytes()).hexdigest())
                        self.assertEqual(data['results'][0]['effective_flags']['profile'],
                                         'sack' if suite == 'sack' else 'baseline')
                        self.assertEqual(data['all_passed'], status == 'passed')
                        self.assertEqual(data['counts'], {status: 1})
                        self.assertEqual(data['eligible_script_files'], 2)
                        self.assertEqual(data['script_files'], 1)
                        self.assertEqual(data['eligible_total'], 2 if native else 6)
                        self.assertEqual(data['results'][0]['effective_flags']['adapter'],
                                         'sack,local=192.0.2.1' if suite == 'sack' else
                                         'baseline,local=192.0.2.1' if suite == 'smoke' else
                                         'baseline,local=192.168.0.1')
                        self.assertEqual(data['selected_total'], 1)
                        self.assertEqual(data['excluded_total'], data['eligible_total'] - 1)
                        self.assertEqual(len(data['excluded_cases']), data['excluded_total'])
                        self.assertEqual(data['selection'], {'variants': [variant],
                                                            'scripts': ['basic.pkt']})
                        self.assertEqual(data['results'][0]['behavior_executed'],
                                         status != 'environment_error')
                        self.assertEqual(data['results'][0]['stage'],
                                         'environment' if status == 'environment_error' else 'behavior')
                        self.assertEqual(execute.call_args_list[0].args[0],
                                         [str(runner), '--dry_run',
                                          *data['results'][0]['effective_flags']['packetdrill'],
                                          str(directory / 'basic.pkt')])
                        self.assertEqual(execute.call_args_list[1].args[0],
                                         ['unshare', '--user', '--map-root-user', '--net',
                                          'env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}',
                                          str(runner), f'--so_filename={plugin}',
                                          f"--so_flags={data['results'][0]['effective_flags']['adapter']}",
                                          *data['results'][0]['effective_flags']['packetdrill'],
                                          str(directory / 'basic.pkt')])
                        self.assertEqual(data['results'][0]['effective_flags']['preload'],
                                         str(plugin))
                    with patch.object(sys, 'argv', argv), \
                            patch('run.invoke', return_value=(0, False, '')) as execute:
                        self.assertEqual(main(), 0 if native else 1)
                    data = json.loads(report.read_text())
                    for call in execute.call_args_list:
                        invocation = call.args[0]
                        if '--dry_run' in invocation:
                            self.assertEqual(invocation[:2], [str(runner), '--dry_run'])
                        else:
                            self.assertEqual(invocation[:9],
                                             ['unshare', '--user', '--map-root-user', '--net',
                                              'env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}',
                                              str(runner), f'--so_filename={plugin}'])
                    for row in data['results']:
                        if row['behavior_executed']:
                            self.assertEqual(row['effective_flags']['preload'], str(plugin))
                    self.assertEqual(data['selected_total'], data['eligible_total'])
                    self.assertEqual(data['excluded_cases'], [])
                    self.assertEqual(data['selection'], {'variants': None, 'scripts': None})
                    if suite == 'upstream-raw':
                        self.assertEqual(data['coverage'], {
                            'selected_script_files': 2, 'upstream_script_files': 2,
                            'selection': 'all_tracked_upstream_scripts'})
                        self.assertTrue(all(not row['adapted'] for row in data['results']))
                        self.assertEqual(data['counts'], {'passed': 2, 'unsupported': 4})
                        self.assertEqual(data['behavior_executed'], 2)
                    with patch.object(sys, 'argv', argv + filters), \
                            patch('run.invoke', return_value=(1, False, 'bad syntax')) as execute:
                        self.assertEqual(main(), 1)
                    self.assertEqual(execute.call_count, 1)
                    data = json.loads(report.read_text())
                    self.assertFalse(data['all_passed'])
                    self.assertEqual(data['behavior_executed'], 0)
                    for invalid in (['--variant', 'unknown'], ['--variant', ''],
                                    ['--variant', 'ipv4' if native else 'native-ipv4'],
                                    ['--script', ''], ['--script', 'missing.pkt']):
                        with patch.object(sys, 'argv', argv + invalid), \
                                patch('run.invoke') as execute:
                            with self.assertRaises(SystemExit) as error:
                                main()
                            self.assertEqual(error.exception.code, 2)
                            execute.assert_not_called()


TFO26 = [
    'fastopen/client/' + name + '.pkt' for name in (
        'blocking-connect-bypass-errno', 'blocking-connect-bypass',
        'blocking-sendmsg-multi-iov', 'blocking-sendto-errnos', 'blocking-sendto',
        'cookie-req-timeout', 'fastopen-connect-keepalive', 'nonblocking-connect-bypass',
        'nonblocking-sendmsg-multi-iov', 'nonblocking-sendto-empty-buf',
        'nonblocking-sendto-over-mss', 'poll', 'sendto-af-unspec',
        'simultaneous-fast-open', 'syn-data-icmp-unreach-frag-needed',
        'syn-data-icmp-unreach-frag-needed-with-seq', 'syn-data-rtt-from-syn-data',
        'syn-data-timeout', 'valid-cookie-format')
] + ['fastopen/server/' + name + '.pkt' for name in (
    'basic-non-tfo-listener', 'icmp-baseline', 'opt34/basic-non-tfo-listener',
    'opt34/fin-close-socket', 'opt34/reset-after-accept', 'opt34/reset-before-accept')
] + ['syscall_bad_arg/fastopen-invalid-buf-ptr.pkt']


class AdaptationChecks(unittest.TestCase):
    def setUp(self):
        mock_backend(self)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / PIN['tcp_tests']
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        # Timed resource commands require the exact real source/hash and have
        # separate capability tests; generic synthetic sources cannot enable it.
        self.manifest['scripts'].pop(RESOURCE_SCRIPT)
        self.manifest['scripts'].pop(CACHE_FLUSH_SCRIPT)
        for name in TIMESTAMP_SOURCES:
            self.manifest['scripts'].pop(name)
        # Synthetic generic sources have no IPv6-only filename constraints.
        for name in list(self.manifest['scripts']):
            if name.endswith('v6.pkt'):
                self.manifest['scripts'].pop(name)
        self.source = (b'// assertions must survive exactly\n`../common/defaults.sh`\n'
                       b'0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3\n'
                       b'+0 > S 0:0(0) <...>\n+0 close(3) = 0\n')
        self.setup = b'#!/bin/sh\nsysctl -q net.ipv4.tcp_ecn=0\n'
        # Synthetic sources exercise runner behavior, independent of real scripts'
        # blocked capabilities and alternate defaults spellings.
        for name, entry in self.manifest['scripts'].items():
            if name in ('nagle/https_client.pkt', 'notsent_lowat/notsent-lowat-sysctl.pkt',
                        'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt') or name in (
                            LINUX_COOKIE_SCRIPTS | FASTOPEN_PMTUD_SCRIPTS | ADAPTIVE_ACK_SCRIPTS
                            | FASTOPEN_CLIENT_SCRIPTS | NON_TFO_SETUP_COMMANDS.keys() | SLOW_START_ACK_SCRIPTS | SYN_DATA_ACK_SCRIPTS):
                path = self.directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                source = self.source.replace(b'`../common/defaults.sh`\n', entry['command_line'].encode())
                source += entry.get('restore_line', '').encode()
                path.write_bytes(source)
                entry['source_sha256'] = hashlib.sha256(source).hexdigest()
                entry['setup_sha256'] = hashlib.sha256(self.setup).hexdigest()
                for extra in entry.get('additional_setup_files', []):
                    helper = self.directory / extra['path']
                    helper.parent.mkdir(parents=True, exist_ok=True)
                    helper.write_bytes(b'# synthetic helper\n')
                    extra['sha256'] = hashlib.sha256(helper.read_bytes()).hexdigest()
                continue
            entry.pop('blocked_reasons', None)
            entry.pop('additional_setup_files', None)
            entry.pop('fixture', None)
            entry['command_line'] = '`../common/defaults.sh`\n'
            entry['replacement_line'] = '// ntcp setup mapped by adaptations.json; Linux defaults not reproduced.\n'
            entry['expected_command_count'] = 1
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.source)
            entry['source_sha256'] = hashlib.sha256(self.source).hexdigest()
            entry['setup_sha256'] = hashlib.sha256(self.setup).hexdigest()
        setup = self.directory / 'common/defaults.sh'
        setup.parent.mkdir(parents=True, exist_ok=True)
        setup.write_bytes(self.setup)
        self.name = 'close/close-on-syn-sent.pkt'
        self.flags = self.manifest['scripts'][self.name]['adapter_flags']

    def test_exact_replacement_preserves_every_other_byte(self):
        for name, entry in self.manifest['scripts'].items():
            generated, audit = adapt_source(self.directory, name, self.manifest,
                                             entry['adapter_flags'])
            source = (self.directory / name).read_bytes()
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            if 'restore_line' in entry:
                expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertEqual((self.directory / name).read_bytes(), source)
            self.assertEqual(audit['source_sha256'], entry['source_sha256'])
            self.assertEqual(audit['setup_sha256'], entry['setup_sha256'])
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
            self.assertFalse(audit['mapping']['linux_defaults_reproduced'])
            self.assertTrue(preflight(self.source.decode()))  # upstream still refuses it
            self.assertEqual(preflight(generated.decode()), [])

    def test_alternate_defaults_spellings_preserve_every_other_byte(self):
        entry = self.manifest['scripts'][self.name]
        for command in ('`../common/defaults.sh\n`\n', '`../../common/defaults.sh`\n',
                        '`../../common/defaults.sh\n`\n'):
            original = self.source.replace(entry['command_line'].encode(), command.encode())
            (self.directory / self.name).write_bytes(original)
            entry['command_line'] = command
            entry['source_sha256'] = hashlib.sha256(original).hexdigest()
            generated, _ = adapt_source(self.directory, self.name, self.manifest, self.flags)
            self.assertEqual(generated, original.replace(command.encode(),
                                                       entry['replacement_line'].encode()))
            entry['command_line'] = '`../common/defaults.sh`\n'

    def test_inline_ecn_enablement_requires_exact_hash_and_profile(self):
        self.name = 'ecn/ecn-uses-ect0.pkt'
        entry = self.manifest['scripts'][self.name]
        command = ('`../common/defaults.sh\n'
                   'sysctl -q net.ipv4.tcp_ecn=1  # fully enabled\n`\n')
        original = self.source.replace(entry['command_line'].encode(), command.encode())
        (self.directory / self.name).write_bytes(original)
        entry.update(command_line=command,
                     source_sha256=hashlib.sha256(original).hexdigest(),
                     command_sha256=hashlib.sha256(command.encode()).hexdigest(),
                     adapter_flags='upstream,local=192.168.0.1,ecn')
        entry['mapping']['ntcp_settings'] = profile_metadata(entry['adapter_flags'])
        flags = entry['adapter_flags']
        generated, _ = adapt_source(self.directory, self.name, self.manifest, flags)
        self.assertEqual(generated, original.replace(command.encode(),
                                                   entry['replacement_line'].encode()))
        for field, value in (('command_sha256', '0' * 64),
                             ('adapter_flags', 'upstream-sack,local=192.168.0.1')):
            manifest = copy.deepcopy(self.manifest)
            manifest['scripts'][self.name][field] = value
            with self.assertRaises(ValueError):
                adapt_source(self.directory, self.name, manifest,
                             manifest['scripts'][self.name]['adapter_flags'])
        entry['mapping']['ntcp_settings']['ecn'] = False
        with self.assertRaises(ValueError):
            adapt_source(self.directory, self.name, self.manifest, flags)
        entry['mapping']['ntcp_settings']['ecn'] = True
        original = original.replace(b'tcp_ecn=1', b'tcp_ecn=2')
        (self.directory / self.name).write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        entry['command_line'] = command.replace('tcp_ecn=1', 'tcp_ecn=2')
        entry['command_sha256'] = hashlib.sha256(entry['command_line'].encode()).hexdigest()
        with self.assertRaises(ValueError):
            adapt_source(self.directory, self.name, self.manifest, flags)

    def test_blocked_setup_and_embedded_assertions_are_never_executed(self):
        entry = self.manifest['scripts'][self.name]
        original = self.source + b'+0 `tc qdisc add dev tun0 root pfifo limit 0`\n' \
                   + b'+0 %{ assert tcpi_probes == 6 }%\n'
        (self.directory / self.name).write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        entry['blocked_reasons'] = ['No ntcp resource-probe mapping']
        extra = self.directory / 'common/set_sysctls.py'
        extra.write_bytes(b'unavailable setup')
        entry['additional_setup_files'] = [{'path': 'common/set_sysctls.py',
                                           'sha256': hashlib.sha256(extra.read_bytes()).hexdigest()}]
        generated, audit = adapt_source(self.directory, self.name, self.manifest, self.flags)
        self.assertEqual(generated, original)
        self.assertNotIn('generated_sha256', audit)
        checkout = Path(self.temporary.name)
        runner = checkout / PIN['runner']
        runner.parent.mkdir(parents=True)
        runner.write_text('unused')
        runner.chmod(0o700)
        plugin = checkout / 'plugin.so'
        plugin.write_text('unused')
        manifest_dir = checkout / 'manifest'
        manifest_dir.mkdir()
        (manifest_dir / 'adaptations.json').write_text(json.dumps(self.manifest))
        report = checkout / 'report.json'
        tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                            for name in self.manifest['scripts'])
        with patch('run.HERE', manifest_dir), \
                patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke') as execute, patch.object(sys, 'argv',
                    ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                     '--suite', 'upstream', '--variant', 'ipv4', '--script', self.name,
                     '--report', str(report)]):
            self.assertEqual(main(), 1)
            execute.assert_not_called()
        row = json.loads(report.read_text())['results'][0]
        self.assertEqual(row['status'], 'unsupported')
        self.assertEqual(row['reasons'], entry['blocked_reasons'])
        self.assertFalse(row['behavior_executed'])
        self.assertFalse(row['adapted'])
        extra.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'setup common/set_sysctls.py hash differs'):
            adapt_source(self.directory, self.name, self.manifest, self.flags)
        extra.unlink()
        with self.assertRaises(OSError):
            adapt_source(self.directory, self.name, self.manifest, self.flags)

    def test_embedded_assertions_preserved_and_hash_bound(self):
        entry = self.manifest['scripts'][self.name]
        path = self.directory / self.name
        original = (self.source + b'0 %{ assert tcpi_lost == 0\n'
                    b'assert tcpi_snd_cwnd == 7\nassert tcpi_snd_ssthresh == 7 }%\n')
        path.write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        with self.assertRaises(ValueError):
            adapt_source(self.directory, self.name, self.manifest, self.flags)
        entry['embedded_tcp_info'] = True
        generated, audit = adapt_source(self.directory, self.name, self.manifest, self.flags)
        self.assertEqual(generated, original.replace(entry['command_line'].encode(),
                                                    entry['replacement_line'].encode()))
        self.assertTrue(audit['embedded_tcp_info'])
        path.write_bytes(original.replace(b'== 0', b'== 1'))
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            adapt_source(self.directory, self.name, self.manifest, self.flags)
        original = original.replace(b'tcpi_lost', b'tcpi_pacing_rate')
        path.write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        with self.assertRaisesRegex(ValueError, 'unsupported TCP_INFO'):
            adapt_source(self.directory, self.name, self.manifest, self.flags)

    def test_explicit_runner_selection_and_checks_around_execution(self):
        checkout = Path(self.temporary.name)
        runner = checkout / PIN['runner']
        runner.parent.mkdir(parents=True)
        runner.write_text('default runner')
        runner.chmod(0o700)
        patched = checkout / 'patched-runner'
        patched.write_text('audited runner')
        patched.chmod(0o700)
        plugin = checkout / 'plugin.so'
        plugin.write_text('plugin')
        manifest_dir = checkout / 'manifest'
        manifest_dir.mkdir()
        report = checkout / 'report.json'
        entry = self.manifest['scripts'][self.name]
        entry['embedded_tcp_info'] = True
        tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                            for name in self.manifest['scripts'])
        argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                '--suite', 'upstream', '--variant', 'ipv4', '--script', self.name,
                '--report', str(report)]
        provenance = {'audited': True}
        with patch('run.HERE', manifest_dir), \
                patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked):
            for override, snippet in ((False, b'assert tcpi_lost == 0'),
                                      (True, b'assert tcpi_lost == 0'),
                                      (True, b'assert SK_MEMINFO_RMEM_ALLOC == 0')):
                original = self.source + b'0 %{ ' + snippet + b' }%\n'
                (self.directory / self.name).write_bytes(original)
                entry['source_sha256'] = hashlib.sha256(original).hexdigest()
                (manifest_dir / 'adaptations.json').write_text(json.dumps(self.manifest))
                omitted = b'SK_MEMINFO' in snippet
                with patch.object(sys, 'argv', argv + (
                        ['--runner', str(patched)] if override else [])), \
                        patch('run.runner_provenance', return_value=provenance) as audit, \
                        patch('run.invoke', return_value=(0, False, '')) as execute:
                    self.assertEqual(main(), 1 if omitted else 0)
                data = json.loads(report.read_text())
                self.assertEqual(data['runner_path'], str(patched if override else runner))
                self.assertEqual(data['runner_provenance'], provenance if override else None)
                if omitted:
                    execute.assert_not_called()
                    self.assertFalse(data['all_passed'])
                else:
                    self.assertEqual('--code_sockopt=TCP_INFO_PREFIX' in execute.call_args.args[0], override)
                if not override:
                    audit.assert_not_called()
            # A changed artifact must abort before/after both dry-run and behavior.
            original = self.source + b'0 %{ assert tcpi_lost == 0 }%\n'
            (self.directory / self.name).write_bytes(original)
            entry['source_sha256'] = hashlib.sha256(original).hexdigest()
            (manifest_dir / 'adaptations.json').write_text(json.dumps(self.manifest))
            for changed_at, invocations in ((2, 0), (3, 1), (4, 1), (5, 2)):
                with patch.object(sys, 'argv', argv + ['--runner', str(patched)]), \
                        patch('run.runner_provenance', side_effect=(
                            [provenance] * (changed_at - 1) + [ValueError('artifact changed')])), \
                        patch('run.invoke', return_value=(0, False, '')) as execute:
                    with self.assertRaises(SystemExit) as error:
                        main()
                    self.assertEqual(error.exception.code, 2)
                    self.assertEqual(execute.call_count, invocations)

    def test_source_and_setup_changes_rejected_with_same_revision(self):
        for relative in (self.name, 'common/defaults.sh'):
            path = self.directory / relative
            original = path.read_bytes()
            path.write_bytes(original + b'// changed\n')
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                adapt_source(self.directory, self.name, self.manifest, self.flags)
            path.write_bytes(original)

    def test_unexpected_commands_and_code_rejected_even_with_updated_hash(self):
        for source in (
            self.source + b'`echo surprise`\n',
            self.source + b'`../common/defaults.sh`\n',
            self.source.replace(b'`../common/defaults.sh`', b'`true`'),
            self.source.replace(b'`../common/defaults.sh`', b'// `../common/defaults.sh`'),
            self.source.replace(b'`../common/defaults.sh`',
                                b'`../common/defaults.sh\nsysctl -q net.ipv4.tcp_ecn=1\n`'),
            self.source.replace(b'`../common/defaults.sh`\n', b''),
            self.source + b'0 %{ assert 1 }%\n',
        ):
            with self.subTest(source=source):
                (self.directory / self.name).write_bytes(source)
                self.manifest['scripts'][self.name]['source_sha256'] = hashlib.sha256(source).hexdigest()
                with self.assertRaises(ValueError):
                    adapt_source(self.directory, self.name, self.manifest, self.flags)

    def test_every_mapping_resolves_common_unpaced_cubic_and_rfc9937(self):
        from run import UPSTREAM_BASELINE_REASON, UPSTREAM_OPTION_AUDIT, upstream_flags
        for name, entry in self.manifest['scripts'].items():
            settings = profile_metadata(entry['adapter_flags'])
            self.assertEqual(entry['adapter_flags'], upstream_flags(name))
            self.assertEqual(entry['mapping']['ntcp_settings'], profile_metadata(entry['adapter_flags']))
            self.assertEqual(entry['mapping']['option_reasons'], UPSTREAM_OPTION_AUDIT.get(name, {}))
            self.assertEqual(entry['mapping']['reasons'][0], UPSTREAM_BASELINE_REASON)
            self.assertEqual(settings['adaptive_ack'], 'immediate-ack' not in settings['options'])
            self.assertEqual(settings['delayed_ack_us'], 0 if 'immediate-ack' in settings['options'] else 200000)
            self.assertEqual(settings['initial_ack_timeout_us'], 40000)
            self.assertTrue(settings['coalesce_read_window_updates'])
            self.assertEqual(settings['profile'], 'upstream')
            self.assertEqual(settings['congestion_control'], 'Cubic')
            self.assertEqual(settings['prr'], 'Rfc9937')
            self.assertFalse(settings['general_pacing'])
            self.assertFalse(settings['prr_pacing'])
            self.assertTrue(settings['cubic_hystart'])
            self.assertTrue(settings['cubic_fast_convergence'])
            self.assertIsNone(settings['pacing_config'])
            self.assertEqual(set(settings['options']), set(entry['mapping']['option_reasons']))
            self.assertTrue(entry['mapping']['assertions_preserved'])

    def test_consistent_manifest_cannot_smuggle_unaudited_options(self):
        name = 'tcp_info/tcp-info-sndbuf-limited.pkt'
        for token in ('reno', 'paced', 'linux-cookie', 'pmtud1500', 'adaptive-ack'):
            manifest = copy.deepcopy(self.manifest)
            entry = manifest['scripts'][name]
            entry['adapter_flags'] += ',' + token
            entry['mapping']['ntcp_settings'] = profile_metadata(entry['adapter_flags'])
            entry['mapping']['option_reasons'][token] = 'unaudited policy'
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, 'per-case audit'):
                adapt_source(self.directory, name, manifest, entry['adapter_flags'])

    def test_resource_options_are_independent_of_congestion(self):
        large = {'cubic/cubic-rto-ss-ca-cwnd-bump.pkt',
                 'slow_start/slow-start-app-limited-9-packets-out.pkt',
                 'slow_start/slow-start-app-limited.pkt'} | SLOW_START_ACK_SCRIPTS
        self.assertEqual({name for name, entry in self.manifest['scripts'].items()
                          if 'budget128m' in entry['adapter_flags'].split(',')}, large)
        for name, entry in self.manifest['scripts'].items():
            settings = entry['mapping']['ntcp_settings']
            self.assertEqual(settings['endpoint_max_buffer_bytes'],
                             (128 if 'budget128m' in settings['options'] else
                              224 if 'budget224m' in settings['options'] else 32) * 1024 * 1024)
            self.assertEqual(settings['preallocate_connections'],
                             4 if 'prealloc4' in settings['options'] else 3 if 'prealloc3' in settings['options'] else 1)

    def test_congestion_basic_selection_and_diagnostic_profiles(self):
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual(manifest['upstream_revision'], PIN['revision'])
        selection = BASIC17 + CONGESTION18
        self.assertEqual((len(BASIC17), len(CONGESTION18), len(set(selection))), (17, 18, 35))
        self.assertTrue(set(selection) <= manifest['scripts'].keys())
        cubic = {name for name, entry in manifest['scripts'].items()
                 if not name.startswith('fast_recovery/')
                 and (name.startswith(('cubic/', 'slow_start/')) or name == 'cwnd_moderation/cwnd-moderation-disorder-no-moderation.pkt')
                 and not entry.get('blocked_reasons')}
        self.assertEqual(cubic, DEFAULTS_ONLY_CUBIC | SLOW_START_ACK_SCRIPTS)
        for name in DEFAULTS_ONLY_CUBIC:
            entry = manifest['scripts'][name]
            self.assertEqual(entry['mapping']['ntcp_settings'], profile_metadata(entry['adapter_flags']))
            self.assertTrue(entry['embedded_tcp_info'])
            self.assertEqual(entry['expected_command_count'], 1)
            self.assertEqual(entry['command_line'], '`../common/defaults.sh`\n')
            self.assertTrue(entry['mapping']['assertions_preserved'])
            self.assertFalse(entry['mapping']['linux_defaults_reproduced'])
        blocked = {name for name in selection if manifest['scripts'][name].get('blocked_reasons')}
        self.assertEqual(blocked, (set(CONGESTION18) - DEFAULTS_ONLY_CUBIC - SLOW_START_ACK_SCRIPTS - {PASSIVE_CUBIC_ECN}) | {
            'blocking/blocking-write.pkt',
        })
        copied = manifest['scripts']['syscall_bad_arg/sendmsg-empty-iov.pkt']
        self.assertEqual(copied['adapter_flags'], 'upstream,local=192.168.0.1')
        self.assertNotIn('blocked_reasons', copied)
        self.assertIn('copied-fallback MSG_ZEROCOPY', copied['mapping']['claim'])
        self.assertTrue(copied['mapping']['assertions_preserved'])
        for name in blocked:
            entry = manifest['scripts'][name]
            self.assertTrue(entry['blocked_reasons'])
            self.assertEqual(len(entry['audited_shell_commands']), entry['expected_command_count'])
            for command in entry['audited_shell_commands']:
                self.assertEqual(hashlib.sha256(command['command'].encode()).hexdigest(),
                                 command['sha256'])
                self.assertIn('Unavailable:', command['semantic_mapping'])

    def test_explicit_resource_reasons_do_not_enable_blocked_setup(self):
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertNotIn('no SO_SNDBUF mapping', json.dumps(manifest))
        reasons = {name: entry['mapping']['option_reasons']['budget128m']
                   for name, entry in manifest['scripts'].items()
                   if 'budget128m' in entry['mapping']['option_reasons']}
        retained = reasons.pop('zerocopy/fastopen-client.pkt')
        self.assertIn('Two client connections retain', retained)
        self.assertEqual(len(reasons), 6)
        self.assertTrue(all('SO_SNDBUF=200000' in reason and 'staged' in reason for reason in reasons.values()))
        for entry in manifest['scripts'].values():
            if entry.get('blocked_reasons'):
                self.assertTrue(any('Unavailable:' in command['semantic_mapping']
                                    or 'Blocked:' in command['semantic_mapping']
                                    for command in entry['audited_shell_commands']))

    def test_mapping_requires_allowlist_exact_flags_count_and_replacement(self):
        with self.assertRaisesRegex(ValueError, 'allowlisted'):
            adapt_source(self.directory, 'other.pkt', self.manifest, self.flags)
        with self.assertRaisesRegex(ValueError, 'flags differ'):
            adapt_source(self.directory, self.name, self.manifest, 'baseline,local=192.0.2.1')
        for key, value in (('expected_command_count', 2), ('replacement_line', ''),
                           ('replacement_line', '0 close(3) = 0\n')):
            manifest = copy.deepcopy(self.manifest)
            manifest['scripts'][self.name][key] = value
            with self.assertRaises(ValueError):
                adapt_source(self.directory, self.name, manifest, self.flags)

    def test_main_runs_generated_parser_and_namespaced_plugin_and_reports_provenance(self):
        checkout = Path(self.temporary.name)
        runner = checkout / PIN['runner']
        runner.parent.mkdir(parents=True)
        runner.write_text('unused')
        runner.chmod(0o700)
        plugin = checkout / 'plugin.so'
        plugin.write_text('unused')
        manifest_dir = checkout / 'manifest'
        manifest_dir.mkdir()
        (manifest_dir / 'adaptations.json').write_text(json.dumps(self.manifest))
        report = checkout / 'report.json'
        calls = []
        tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                            for name in self.manifest['scripts'])

        def execute(argv, cwd, timeout):
            generated = Path(argv[-1])
            self.assertNotEqual(generated.parent, self.directory)
            self.assertNotIn(b'`', generated.read_bytes())
            calls.append(argv)
            if '--dry_run' in argv or generated.name == 'close-on-syn-sent.pkt':
                return 0, False, ''
            return 1, False, 'packet mismatch'

        argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                '--suite', 'upstream', '--report', str(report)]
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke', side_effect=execute), patch.object(sys, 'argv', argv):
            self.assertEqual(main(), 1)
        data = json.loads(report.read_text())
        self.assertEqual(data['suite'], 'upstream')
        inventory_count = len(self.manifest['scripts'])
        count = inventory_count - len(PORTED_SCRIPTS & self.manifest['scripts'].keys())
        self.assertEqual(data['coverage'], {'selected_script_files': count,
                                          'upstream_script_files': inventory_count,
                                          'selection': 'adaptation_allowlist'})
        self.assertEqual(data['counts'], {'failed': count - 1, 'passed': 1, 'unsupported': 2 * count - 1})
        self.assertFalse(data['all_passed'])
        self.assertEqual(len(calls), 2 * count)
        for row in data['results']:
            self.assertEqual(row['suite'], 'upstream')
            self.assertEqual(row['effective_flags']['adapter'],
                             self.manifest['scripts'][row['script']]['adapter_flags'])
            self.assertEqual(row['effective_flags']['profile'],
                             row['effective_flags']['adapter'].split(',')[0])
            self.assertIn('generated_sha256', row['adaptation'])
            self.assertFalse(row['effective_flags']['prr_pacing'])
            self.assertEqual(row['effective_flags']['transport_clock'],
                             'monotonic Instant elapsed microseconds')
            self.assertEqual(row['effective_flags']['transmit_batch_clock'],
                             'monotonic sample per selection/accept')
            self.assertEqual(row['behavior_executed'], row['variant'] == 'ipv4')
            self.assertEqual(row['adapted'], row['variant'] == 'ipv4')
            if row['behavior_executed']:
                self.assertEqual(row['effective_flags']['preload'], str(plugin))
        for invocation in calls[::2]:
            self.assertEqual(invocation[:2], [str(runner), '--dry_run'])
            self.assertFalse(any(arg.startswith('LD_PRELOAD=') for arg in invocation))
        for invocation in calls[1::2]:
            self.assertEqual(invocation[:9],
                             ['unshare', '--user', '--map-root-user', '--net',
                              'env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}',
                              str(runner), f'--so_filename={plugin}'])
            entry = next(entry for name, entry in self.manifest['scripts'].items()
                         if Path(name).name == Path(invocation[-1]).name)
            embedded = entry.get('embedded_tcp_info') is True
            self.assertEqual([arg for arg in invocation if arg.startswith('LD_PRELOAD=')],
                             [f'LD_PRELOAD={plugin}'])
            self.assertIn('PYTHONOPTIMIZE=0', invocation)
            if embedded:
                # Exercise the actual interpreter under the selected environment override.
                with patch.dict(os.environ, {'PYTHONOPTIMIZE': '1'}):
                    code, expired, log = invoke(
                        ['env', invocation[5], sys.executable, '-c', 'assert False'],
                        checkout, 5)
                self.assertEqual(code, 1)
                self.assertFalse(expired)
                self.assertIn('AssertionError', log)
        for filters, expected_counts, expected_calls in (
            (['--variant', 'ipv4', '--script', self.name], {'passed': 1}, 2),
            (['--variant', 'ipv4'], {'passed': 1, 'failed': count - 1}, 2 * count),
            (['--variant', 'ipv6', '--script', self.name], {'unsupported': 1}, 0),
            (['--variant', 'ipv4', '--variant', 'ipv6', '--script', self.name],
             {'passed': 1, 'unsupported': 1}, 2),
            (['--variant', 'ipv4', '--script', self.name,
              '--script', 'blocking/blocking-read.pkt'], {'passed': 1, 'failed': 1}, 4),
        ):
            calls.clear()
            with patch('run.HERE', manifest_dir), \
                    patch('run.check_checkout', return_value=PIN['revision']), \
                    patch('run.subprocess.check_output', return_value=tracked), \
                    patch('run.invoke', side_effect=execute), \
                    patch.object(sys, 'argv', argv + filters):
                self.assertEqual(main(), 0 if expected_counts == {'passed': 1} else 1)
            data = json.loads(report.read_text())
            self.assertEqual(data['counts'], expected_counts)
            self.assertEqual(data['all_passed'], expected_counts == {'passed': 1})
            self.assertEqual(data['eligible_total'], 3 * inventory_count - 1)
            self.assertEqual(data['eligible_script_files'], inventory_count)
            self.assertEqual(data['selected_total'], sum(expected_counts.values()))
            self.assertEqual(data['excluded_total'], 3 * inventory_count - 1 - data['selected_total'])
            self.assertEqual(len(calls), expected_calls)
            self.assertEqual(data['adaptation_manifest_sha256'],
                             hashlib.sha256((manifest_dir / 'adaptations.json').read_bytes()).hexdigest())
            self.assertEqual(data['runner_sha256'], hashlib.sha256(runner.read_bytes()).hexdigest())
            self.assertEqual(data['plugin_sha256'], hashlib.sha256(plugin.read_bytes()).hexdigest())
            self.assertEqual(data['plugin_path'], str(plugin.resolve()))
            self.assertEqual(data['runner_path'], str(runner.resolve()))
            for row in data['results']:
                self.assertEqual(row['adaptation']['source_sha256'],
                                 self.manifest['scripts'][row['script']]['source_sha256'])
                self.assertEqual(row['effective_flags']['packetdrill'], PIN['variants'][row['variant']])
        # A newly tracked source cannot disappear behind the old allowlist.
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked + '\0' + PIN['tcp_tests'] + '/unselected.pkt'), \
                patch('run.invoke') as execute, patch.object(sys, 'argv', argv):
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            execute.assert_not_called()
        # An override cannot execute with settings different from the audit claim.
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke') as execute, patch.object(sys, 'argv',
                    ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                     '--suite', 'upstream', '--report', str(report), '--so-flags', 'baseline']):
            self.assertEqual(main(), 1)
            execute.assert_not_called()
        self.assertEqual(json.loads(report.read_text())['counts'], {'adaptation_rejected': 3 * count - 1})


class FileFixtureChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.name = 'sendfile/sendfile-simple.pkt'
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][self.name]
        self.flags = self.entry['adapter_flags']
        self.source = (b'// preserved\n' + SENDFILE_SETUP +
                       b'+0 open("/tmp/testfile", O_RDONLY) = 5\n'
                       b'+0 sendfile(4, 5, [0], 5) = 5\n+0 > P. 1:6(5) ack 1\n')
        self.path = self.directory / self.name
        self.path.parent.mkdir()
        self.path.write_bytes(self.source)
        setup = self.directory / 'common/defaults.sh'
        setup.parent.mkdir()
        setup.write_bytes(b'audited defaults')
        self.entry.update(source_sha256=hashlib.sha256(self.source).hexdigest(),
                          setup_sha256=hashlib.sha256(setup.read_bytes()).hexdigest())
        self.entry.pop('blocked_reasons', None)  # Candidate mapping, not runtime evidence.

    def test_exact_fixture_mapping_hashes_and_unsafe_setup(self):
        generated, audit = adapt_source(self.directory, self.name, self.manifest, self.flags)
        self.assertEqual(generated.replace(self.entry['replacement_line'].encode(),
                                           SENDFILE_SETUP), self.source)
        self.assertEqual(audit['fixture'], SENDFILE_FIXTURE)
        self.assertEqual(audit['source_sha256'], hashlib.sha256(self.source).hexdigest())
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        for field in ('source_sha256', 'setup_sha256', 'command_sha256', 'fixture'):
            changed = copy.deepcopy(self.manifest)
            changed['scripts'][self.name][field] = 'invalid'
            with self.subTest(field=field), self.assertRaises(ValueError):
                adapt_source(self.directory, self.name, changed, self.flags)
        for old, new in ((b'count=5', b'count=6'), (b'/tmp/testfile', b'/tmp/other'),
                         (b'/bin/rm -f', b'/bin/rm -rf')):
            changed = copy.deepcopy(self.manifest)
            entry = changed['scripts'][self.name]
            source = self.source.replace(old, new)
            self.path.write_bytes(source)
            entry['source_sha256'] = hashlib.sha256(source).hexdigest()
            entry['command_line'] = SENDFILE_SETUP.replace(old, new).decode()
            entry['command_sha256'] = hashlib.sha256(entry['command_line'].encode()).hexdigest()
            with self.subTest(new=new), self.assertRaises(ValueError):
                adapt_source(self.directory, self.name, changed, self.flags)
        self.path.write_bytes(self.source)
        changed = copy.deepcopy(self.manifest)
        changed['scripts']['other.pkt'] = changed['scripts'].pop(self.name)
        (self.directory / 'other.pkt').write_bytes(self.source)
        with self.assertRaises(ValueError):
            adapt_source(self.directory, 'other.pkt', changed, self.flags)

    def test_main_fixture_invocation_and_isolation_failure_reporting(self):
        mock_backend(self)
        with tempfile.TemporaryDirectory(dir=HERE.parent.parent / 'workbench') as temporary:
            checkout = Path(temporary).resolve()
            (checkout / PIN['tcp_tests']).parent.mkdir(parents=True)
            (checkout / PIN['tcp_tests']).symlink_to(self.directory)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('mock runner')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('mock plugin')
            report = checkout / 'report.json'
            manifest_dir = checkout / 'manifest'
            manifest_dir.mkdir()
            self.manifest['scripts'] = {self.name: self.entry}
            (manifest_dir / 'adaptations.json').write_text(json.dumps(self.manifest))
            argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                    '--suite', 'upstream', '--variant', 'ipv4', '--script', self.name,
                    '--report', str(report)]
            for log, expected, executed in (
                    ('packet mismatch', 'failed', True),
                    ('unshare: unshare failed: Operation not permitted', 'unsupported', False),
                    ('unshare: mount / failed: Operation not permitted', 'unsupported', False),
                    (FIXTURE_UNSUPPORTED + ' fixture mount failed', 'unsupported', False)):
                calls = []

                def execute(command, cwd, timeout):
                    calls.append(command)
                    generated = Path(command[-1]).read_bytes()
                    self.assertEqual(generated.replace(self.entry['replacement_line'].encode(),
                                                       SENDFILE_SETUP), self.source)
                    return (0, False, '') if '--dry_run' in command else (1, False, log)

                with patch('run.HERE', manifest_dir), \
                        patch('run.check_checkout', return_value=PIN['revision']), \
                        patch('run.subprocess.check_output', return_value=str(Path(PIN['tcp_tests']) / self.name)), \
                        patch('run.invoke', side_effect=execute), patch.object(sys, 'argv', argv):
                    self.assertEqual(main(), 1)
                data = json.loads(report.read_text())
                row = data['results'][0]
                self.assertEqual(row['status'], expected)
                self.assertEqual(row['behavior_executed'], executed)
                self.assertEqual(row['sha256'], hashlib.sha256(self.source).hexdigest())
                self.assertEqual(row['adaptation']['source_sha256'], row['sha256'])
                self.assertFalse(data['all_passed'])
                self.assertEqual(len(calls), 2)
                self.assertNotIn('--mount', calls[0])  # syntax only, no fixture needed
                self.assertIn('--mount', calls[1])
                self.assertIn(FIXTURE_CHILD, calls[1])
                self.assertIn(f'LD_PRELOAD={plugin}', calls[1])
                self.assertIn(f'--so_filename={plugin}', calls[1])
                self.assertEqual(calls[0][-1], calls[1][-1])
                self.assertEqual(row['effective_flags']['fixture'], SENDFILE_FIXTURE)
                if not executed:
                    self.assertEqual(row['stage'], 'environment')
                    self.assertIn('isolated fixture unavailable', row['reasons'][0])

    def test_helper_refuses_parent_namespace_before_any_write(self):
        code, expired, log = invoke([sys.executable, '-I', '-c', FIXTURE_CHILD,
                                    os.readlink('/proc/self/ns/mnt'), 'unused', str(self.path)],
                                   self.directory, 5)
        self.assertEqual((code, expired), (125, False))
        self.assertIn(FIXTURE_UNSUPPORTED, log)
        self.assertEqual(self.path.read_bytes(), self.source)

    def test_fixture_namespace_content_identity_and_teardown(self):
        # Put the sentinel in an OUTER namespace, never write host /tmp/testfile.
        # Inner namespace must hide it; its teardown must reveal it unchanged.
        probe = r'''
import ctypes, os, pathlib, subprocess, sys
libc = ctypes.CDLL(None)
assert libc.mount(None, b'/', None, (1 << 18) | (1 << 14), None) == 0
assert libc.mount(b'tmpfs', b'/tmp', b'tmpfs', 0, b'size=16m') == 0
pathlib.Path('/tmp/testfile').write_bytes(b'outer sentinel')
script = pathlib.Path('/tmp/case/test.pkt')
script.parent.mkdir()
script.write_bytes(b'unchanged /tmp/testfile assertions')
check = "import os,pathlib,sys; assert pathlib.Path('/tmp/testfile').read_bytes() == b'\\0'*5; assert pathlib.Path(sys.argv[1]).read_bytes() == b'unchanged /tmp/testfile assertions'; print(os.readlink('/proc/self/ns/mnt'))"
argv = ['unshare', '--mount', '--propagation', 'private', sys.executable, '-I', '-c',
        sys.argv[1], os.readlink('/proc/self/ns/mnt'), sys.executable, '-I', '-c', check, str(script)]
p = subprocess.run(argv, capture_output=True, text=True)
assert p.returncode == 0, p.stdout + p.stderr
assert p.stdout.strip() != os.readlink('/proc/self/ns/mnt')
assert pathlib.Path('/tmp/testfile').read_bytes() == b'outer sentinel'
assert script.read_bytes() == b'unchanged /tmp/testfile assertions'
argv[-2] = 'raise SystemExit(7)'
p = subprocess.run(argv, capture_output=True, text=True)
assert p.returncode == 7, p.stdout + p.stderr
assert pathlib.Path('/tmp/testfile').read_bytes() == b'outer sentinel'
'''
        code, expired, log = invoke(['unshare', '--user', '--map-root-user', '--net',
                                    '--mount', '--propagation', 'private',
                                    sys.executable, '-I', '-c', probe, FIXTURE_CHILD],
                                   self.directory, 5)
        if 'unshare: unshare failed' in log:
            self.skipTest('mount/user namespace unavailable: ' + log.strip())
        self.assertEqual((code, expired, log), (0, False, ''))

    def test_behavior_wrapper_keeps_preload_plugin_and_script_identity(self):
        runner = HERE / 'fake-runner'
        plugin = HERE / 'fake-plugin.so'
        argv = ['unshare', '--user', '--map-root-user', '--net', 'env',
                'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}', str(runner),
                f'--so_filename={plugin}', f'--so_flags={self.flags}', str(self.path)]
        wrapped = fixture_command(argv, runner, plugin)
        self.assertEqual(wrapped[:7], argv[:4] + ['--mount', '--propagation', 'private'])
        self.assertEqual(wrapped[-len(argv[4:]):], argv[4:])
        self.assertEqual(wrapped[10:12], [FIXTURE_CHILD, os.readlink('/proc/self/ns/mnt')])
        with self.assertRaisesRegex(ValueError, 'under /tmp'):
            fixture_command(argv, Path('/tmp/runner'), plugin)


class PublishedSelectionChecks(unittest.TestCase):
    def setUp(self):
        mock_backend(self)
        # Optional pinned upstream checkout, as used by the runner itself.
        self.checkout = Path(os.environ.get('NTCP_PACKETDRILL_CHECKOUT',
                            HERE.parent.parent / 'workbench/packetdrill-upstream'))
        self.directory = self.checkout / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned packetdrill checkout unavailable; set NTCP_PACKETDRILL_CHECKOUT')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())

    def test_upstream_manifest_executes_all_tfo26_and_preserves_icmp_mismatch(self):
        self.assertEqual(len(set(TFO26)), 26)
        self.assertTrue(set(TFO26) <= self.manifest['scripts'].keys())
        profiles = [self.manifest['scripts'][name]['adapter_flags'].split(',')[0] for name in TFO26]
        self.assertEqual(set(profiles), {'upstream'})
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            (checkout / PIN['tcp_tests']).parent.mkdir(parents=True)
            (checkout / PIN['tcp_tests']).symlink_to(self.directory.resolve())
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('unused')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('unused')
            report = checkout / 'report.json'
            tracked = '\0'.join(str(Path(PIN['tcp_tests']) / n)
                                for n in self.manifest['scripts'])
            executed = []

            def execute(argv, cwd, timeout):
                generated = Path(argv[-1]).read_bytes()
                self.assertNotIn(b'`', generated)
                if '--dry_run' not in argv:
                    executed.append(generated)
                    if Path(argv[-1]).name == 'icmp-baseline.pkt':
                        return 1, False, 'expected RST, actual ACK after retained handshake'
                return 0, False, ''

            argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                    '--suite', 'upstream', '--variant', 'ipv4', '--report', str(report)]
            for name in TFO26:
                argv.extend(['--script', name])
            with patch('run.check_checkout', return_value=PIN['revision']), \
                    patch('run.subprocess.check_output', return_value=tracked), \
                    patch('run.invoke', side_effect=execute) as invoke_mock, \
                    patch.object(sys, 'argv', argv):
                self.assertEqual(main(), 1)  # An executed mismatch is not a pass.
            data = json.loads(report.read_text())
            self.assertEqual({r['script'] for r in data['results']}, set(TFO26))
            self.assertEqual(data['counts'], {'passed': 25, 'failed': 1})
            self.assertEqual(invoke_mock.call_count, 52)
            self.assertEqual(len(executed), 26)
            control = next(r for r in data['results'] if r['status'] == 'failed')
            self.assertEqual(control['script'], 'fastopen/server/icmp-baseline.pkt')
            self.assertTrue(control['behavior_executed'])
            self.assertEqual(control['syntax_returncode'], 0)
            self.assertIn('expected RST', control['log'])
            self.assertIn('generated_sha256', control['adaptation'])

    def test_original_file_transfer_sources_candidate_mapping_preserves_all_nonsetup_bytes(self):
        manifest = copy.deepcopy(self.manifest)
        for name in ('sendfile/sendfile-simple.pkt', 'splice/tcp_splice_loop_test.pkt'):
            entry = manifest['scripts'][name]
            entry.pop('blocked_reasons', None)  # Test adaptation, not runtime readiness.
            source = (self.directory / name).read_bytes()
            generated, audit = adapt_source(self.directory, name, manifest, entry['adapter_flags'])
            before, after = source.split(entry['command_line'].encode())
            self.assertEqual(generated, before + entry['replacement_line'].encode() + after)
            self.assertEqual(audit['source_sha256'], hashlib.sha256(source).hexdigest())
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
            self.assertEqual((self.directory / name).read_bytes(), source)
            if name.startswith('sendfile/'):
                self.assertIn(b'open("/tmp/testfile", O_RDONLY) = 5', generated)
                self.assertEqual(audit['fixture'], SENDFILE_FIXTURE)
            else:
                self.assertNotIn('fixture', audit)

    def test_passive_cubic_ecn_mapping_is_exact_and_not_global_mode2(self):
        entry = self.manifest['scripts'][PASSIVE_CUBIC_ECN]
        settings = copy.deepcopy(entry['mapping']['ntcp_settings'])
        self.assertTrue(settings.pop('ecn'))
        cubic = profile_metadata('upstream,local=192.168.0.1')
        self.assertEqual(settings.pop('options'), ['ecn'])
        self.assertEqual(cubic.pop('options'), [])
        self.assertFalse(cubic.pop('ecn'))
        self.assertEqual(settings, cubic)
        self.assertIn('mode2 active-open', entry['mapping']['option_reasons']['ecn'])
        self.assertEqual(entry['mapping']['ecn_scope'], 'passive listener in this exact script only')
        generated, _ = adapt_source(self.directory, PASSIVE_CUBIC_ECN, self.manifest, entry['adapter_flags'])
        source = (self.directory / PASSIVE_CUBIC_ECN).read_bytes()
        self.assertEqual(generated, source.replace(entry['command_line'].encode(),
                                                  entry['replacement_line'].encode(), 1))
        for key, value in [('command_sha256', 'bad'), ('command_line', entry['command_line'].replace('tcp_ecn=2', 'tcp_ecn=1'))]:
            manifest = copy.deepcopy(self.manifest)
            manifest['scripts'][PASSIVE_CUBIC_ECN][key] = value
            with self.assertRaises(ValueError):
                adapt_source(self.directory, PASSIVE_CUBIC_ECN, manifest, entry['adapter_flags'])
        for key, value in [('ecn_scope', 'global mode 2'), ('ntcp_settings', {**entry['mapping']['ntcp_settings'], 'ecn': False})]:
            manifest = copy.deepcopy(self.manifest)
            manifest['scripts'][PASSIVE_CUBIC_ECN]['mapping'][key] = value
            with self.assertRaises(ValueError):
                adapt_source(self.directory, PASSIVE_CUBIC_ECN, manifest, entry['adapter_flags'])

    def test_all_35_published_hashes_commands_and_nonsetup_bytes(self):
        for name in BASIC17 + CONGESTION18:
            with self.subTest(script=name):
                entry = self.manifest['scripts'][name]
                source = (self.directory / name).read_bytes()
                self.assertEqual(hashlib.sha256(source).hexdigest(), entry['source_sha256'])
                self.assertEqual(hashlib.sha256((self.directory / entry['setup_path']).read_bytes()).hexdigest(),
                                 entry['setup_sha256'])
                for extra in entry.get('additional_setup_files', []):
                    self.assertEqual(hashlib.sha256((self.directory / extra['path']).read_bytes()).hexdigest(),
                                     extra['sha256'])
                commands = re.findall(rb'`[^`]*`', source)
                self.assertEqual(len(commands), entry['expected_command_count'])
                generated, audit = adapt_source(self.directory, name, self.manifest, entry['adapter_flags'])
                if entry.get('blocked_reasons'):
                    self.assertEqual([c['command'].encode() for c in entry['audited_shell_commands']], commands)
                    self.assertEqual(generated, source)
                    self.assertNotIn('generated_sha256', audit)
                else:
                    command = entry['command_line'].encode()
                    self.assertEqual(source.count(command), 1)
                    before, after = source.split(command)
                    expected = before + entry['replacement_line'].encode() + after
                    if 'restore_line' in entry:
                        expected = expected.replace(entry['restore_line'].encode(),
                                                    entry['restore_replacement_line'].encode(), 1)
                    self.assertEqual(generated, expected)
                    self.assertEqual(preflight(generated.decode(), entry.get('embedded_tcp_info') is True, resource_control=entry.get('resource_control') is True), [])
                    self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
                self.assertEqual((self.directory / name).read_bytes(), source)
                if name in DEFAULTS_ONLY_CUBIC | SLOW_START_ACK_SCRIPTS and b'SO_SNDBUF' in source:
                    self.assertIn('budget128m', entry['mapping']['option_reasons'])
                    self.assertEqual(entry['mapping']['ntcp_settings']['endpoint_max_buffer_bytes'], 128 * 1024 * 1024)

    def test_socket43_inventory_hashes_and_assertions(self):
        counts = {'blocking': 4, 'close': 3, 'shutdown': 6, 'ioctl': 1,
                  'syscall_bad_arg': 3, 'epoll': 4, 'inq': 2, 'notsent_lowat': 3,
                  'eor': 4, 'sendfile': 1, 'splice': 1, 'tcp_info': 3,
                  'timestamping': 3, 'nagle': 3, 'user_timeout': 2}
        self.assertEqual(sum(counts.values()), 43)
        for directory, count in counts.items():
            scripts = sorted((self.directory / directory).glob('*.pkt'))
            self.assertEqual(len(scripts), count)
            for script in scripts:
                name = str(script.relative_to(self.directory))
                entry = self.manifest['scripts'][name]
                source = script.read_bytes()
                generated, audit = adapt_source(self.directory, name, self.manifest,
                                                entry['adapter_flags'])
                self.assertEqual(len(re.findall(rb'`[^`]*`', source)),
                                 entry['expected_command_count'])
                if entry.get('blocked_reasons'):
                    self.assertEqual(generated, source)
                else:
                    restored = generated.replace(entry['replacement_line'].encode(),
                                                 entry['command_line'].encode(), 1)
                    if 'restore_line' in entry:
                        restored = restored.replace(entry['restore_replacement_line'].encode(),
                                                    entry['restore_line'].encode(), 1)
                    if name == RESOURCE_SCRIPT:
                        restored = restored.replace(RESOURCE_CONTROL, RESOURCE_EVENT, 1)
                    self.assertEqual(restored, source)
                    self.assertIn('generated_sha256', audit)
                self.assertFalse(entry['mapping']['linux_defaults_reproduced'])

    def test_socket43_and_focused_selection_execute_only_genuine_mappings(self):
        self.assertEqual(len(set(SOCKET43)), 43)
        self.assertEqual(len(set(SOCKET_FEATURE19)), 19)
        stale = json.dumps(self.manifest)
        self.assertNotIn('TCP_NOTSENT_LOWAT and EPOLLET are also unavailable', stale)
        self.assertNotIn('TCP_NOTSENT_LOWAT is also unavailable', stale)
        for name in SOCKET_FEATURE19:
            entry = self.manifest['scripts'][name]
            from run import upstream_flags
            self.assertEqual(entry['adapter_flags'], upstream_flags(name))
            self.assertEqual(entry['mapping']['ntcp_settings']['prr'], 'Rfc9937')
            self.assertFalse(entry['mapping']['ntcp_settings']['general_pacing'])
            if name.startswith('tcp_info/'):
                self.assertTrue(entry['embedded_tcp_info'])
                self.assertNotIn('blocked_reasons', entry)
        with tempfile.TemporaryDirectory(dir=HERE.parent.parent / 'workbench') as temporary:
            checkout = Path(temporary)
            (checkout / PIN['tcp_tests']).parent.mkdir(parents=True)
            (checkout / PIN['tcp_tests']).symlink_to(self.directory.resolve(), target_is_directory=True)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('unused')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('unused')
            report = checkout / 'report.json'
            tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                                for name in self.manifest['scripts'])
            # The candidate fixture remains runtime-gated until integration is ready.
            sendfile_enabled = not self.manifest['scripts']['sendfile/sendfile-simple.pkt'].get('blocked_reasons')
            for selection, source_eligible in ((SOCKET43, 37 + int(sendfile_enabled)), (SOCKET_FEATURE19, 15)):
                ported = set(selection) & PORTED_SCRIPTS
                eligible = source_eligible - len(ported)
                executed = []

                def execute(argv, cwd, timeout):
                    path = Path(argv[-1])
                    name = next(n for n in selection
                                if not self.manifest['scripts'][n].get('blocked_reasons')
                                and adapt_source(self.directory, n, self.manifest,
                                    self.manifest['scripts'][n]['adapter_flags'])[0] == path.read_bytes())
                    entry = self.manifest['scripts'][name]
                    self.assertFalse(entry.get('blocked_reasons'), name)
                    self.assertEqual(preflight(path.read_text(), entry.get('embedded_tcp_info') is True, resource_control=entry.get('resource_control') is True), [])
                    if '--dry_run' not in argv:
                        executed.append(name)
                    return 1 if '--dry_run' not in argv else 0, False, 'diagnostic mismatch'

                argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                        '--suite', 'upstream', '--variant', 'ipv4', '--report', str(report)]
                for name in selection:
                    argv.extend(['--script', name])
                with patch('run.check_checkout', return_value=PIN['revision']), \
                        patch('run.subprocess.check_output', return_value=tracked), \
                        patch('run.invoke', side_effect=execute) as invoke_mock, \
                        patch.object(sys, 'argv', argv):
                    self.assertEqual(main(), 1)
                data = json.loads(report.read_text())
                self.assertEqual(data['counts'], {'failed': eligible, 'unsupported': len(selection) - source_eligible})
                self.assertFalse(set(executed) & PORTED_SCRIPTS)
                self.assertEqual({r['script'] for r in data['ported_exclusions']}, ported)
                self.assertEqual(invoke_mock.call_count, 2 * eligible)
                self.assertEqual(len(executed), eligible)
                self.assertFalse(data['all_passed'])
                for row in data['results']:
                    flags = row['effective_flags']
                    self.assertEqual(flags['profile'], self.manifest['scripts'][row['script']]['adapter_flags'].split(',')[0])
                    self.assertEqual(flags['prr_pacing'], flags['profile'] != 'upstream')
                    self.assertEqual(flags['transport_clock'], 'monotonic Instant elapsed microseconds')
                    self.assertEqual(flags['transmit_batch_clock'], 'monotonic sample per selection/accept')
                    if row['status'] == 'unsupported':
                        self.assertFalse(row['behavior_executed'])
                        self.assertIsNone(row['syntax_returncode'])

    def test_exact_35_selection_blocks_unmapped_setup_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            # Real sources and manifest; mock only the external executable boundary.
            (checkout / PIN['tcp_tests']).parent.mkdir(parents=True)
            (checkout / PIN['tcp_tests']).symlink_to(self.directory.resolve(), target_is_directory=True)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('unused')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('unused')
            report = checkout / 'report.json'
            selection = BASIC17 + CONGESTION18
            executed = []

            def execute(argv, cwd, timeout):
                path = Path(argv[-1])
                name = next(n for n in selection if Path(n).name == path.name)
                entry = self.manifest['scripts'][name]
                self.assertFalse(entry.get('blocked_reasons'), name)
                self.assertNotIn(b'`', path.read_bytes())
                if '--dry_run' in argv:
                    return 0, False, ''
                executed.append(name)
                self.assertEqual(argv[:9],
                                 ['unshare', '--user', '--map-root-user', '--net',
                                  'env', 'PYTHONOPTIMIZE=0', f'LD_PRELOAD={plugin}',
                                  str(runner), f'--so_filename={plugin}'])
                return 1, False, 'packet mismatch'

            tracked = '\0'.join(str(Path(PIN['tcp_tests']) / name)
                                 for name in self.manifest['scripts'])
            argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                    '--suite', 'upstream', '--variant', 'ipv4', '--report', str(report)]
            for name in selection:
                argv.extend(['--script', name])
            with patch('run.check_checkout', return_value=PIN['revision']), \
                    patch('run.subprocess.check_output', return_value=tracked), \
                    patch('run.invoke', side_effect=execute), patch.object(sys, 'argv', argv):
                self.assertEqual(main(), 1)
            data = json.loads(report.read_text())
            self.assertEqual(data['selected_total'], 35)
            self.assertEqual(data['script_files'], 35)
            self.assertEqual({row['script'] for row in data['results']}, set(selection))
            self.assertFalse(data['all_passed'])
            self.assertEqual(len(executed), 26)
            self.assertIn('syscall_bad_arg/sendmsg-empty-iov.pkt', executed)
            for row in data['results']:
                entry = self.manifest['scripts'][row['script']]
                if entry.get('blocked_reasons'):
                    self.assertEqual(row['status'], 'unsupported')
                    self.assertEqual(row['reasons'], entry['blocked_reasons'])
                    self.assertFalse(row['behavior_executed'])
                    self.assertFalse(row['adapted'])
                    self.assertIsNone(row['syntax_returncode'])
                else:
                    self.assertTrue(row['behavior_executed'])
                    self.assertEqual(row['effective_flags']['preload'], str(plugin))
                    self.assertEqual(row['status'], 'failed')


class PipelineProfileTests(unittest.TestCase):
    def test_explicit_profiles_describe_configuration_not_offloaded_captures(self):
        for profile in ('pipeline', 'pipeline-paced', 'pipeline-gso', 'pipeline-paced-gso',
                        'baseline', 'sack', 'upstream'):
            with self.subTest(profile=profile):
                flags = profile_metadata(f'local=192.0.2.1,{profile}')
                self.assertEqual(flags['profile'], profile)
                self.assertEqual(flags['general_pacing'], 'paced' in profile)
                self.assertEqual(flags['software_gso'], profile == 'upstream' or 'gso' in profile)
                self.assertEqual(flags['prr_pacing'], flags['profile'] != 'upstream')
                self.assertEqual(flags['egress_pipeline'], 'shared production scheduler')
                self.assertEqual(flags['transmit_batch_clock'], 'monotonic sample per selection/accept')
                self.assertEqual(flags['capture_boundary'], 'individual raw IPv4 TCP wire segments')
                self.assertEqual(flags['capture_clock'], 'realtime epoch microseconds at backend submission')
                self.assertFalse(flags['hardware_tso'])
                self.assertFalse(flags['gro'])

    def test_common_read_window_coalescing_and_idempotent_option(self):
        base = profile_metadata('upstream,local=192.0.2.1')
        self.assertTrue(base['coalesce_read_window_updates'])
        explicit = profile_metadata('upstream,coalesce-read-window,local=192.0.2.1')
        self.assertEqual(explicit.pop('options'), ['coalesce-read-window'])
        self.assertEqual(explicit, {key: value for key, value in base.items() if key != 'options'})

    def test_common_adaptive_ack_and_immediate_override(self):
        base = profile_metadata('upstream,local=192.0.2.1')
        self.assertTrue(base['adaptive_ack'])
        self.assertEqual(base['delayed_ack_us'], 200000)
        self.assertEqual(base['initial_ack_timeout_us'], 40000)
        explicit = profile_metadata('upstream,adaptive-ack,local=192.0.2.1')
        self.assertEqual(explicit.pop('options'), ['adaptive-ack'])
        self.assertEqual(explicit, {key: value for key, value in base.items() if key != 'options'})
        for options in ('immediate-ack', 'paced,immediate-ack'):
            immediate = profile_metadata(f'upstream,{options},local=192.0.2.1')
            self.assertFalse(immediate['adaptive_ack'])
            self.assertEqual(immediate['delayed_ack_us'], 0)
            self.assertEqual(immediate['initial_ack_timeout_us'], 40000)
            self.assertEqual(immediate['general_pacing'], 'paced' in options)
            self.assertEqual(immediate['prr_pacing'], 'paced' in options)
        for options in ('adaptive-ack,immediate-ack', 'immediate-ack,adaptive-ack',
                        'paced,adaptive-ack,immediate-ack'):
            invalid = profile_metadata(f'upstream,{options},local=192.0.2.1')
            self.assertTrue(all(value is None for key, value in invalid.items() if key != 'profile'))

    def test_paced_is_one_positive_fixed_option(self):
        base = profile_metadata('upstream,local=192.0.2.1')
        paced = profile_metadata('upstream,paced,local=192.0.2.1')
        self.assertFalse(base['general_pacing'])
        self.assertFalse(base['prr_pacing'])
        self.assertIsNone(base['pacing_config'])
        self.assertTrue(paced['adaptive_ack'])
        self.assertEqual(paced['delayed_ack_us'], 200000)
        self.assertEqual(paced['initial_ack_timeout_us'], 40000)
        self.assertTrue(paced['general_pacing'])
        self.assertTrue(paced['prr_pacing'])
        self.assertEqual(paced['pacing_config'], {
            'rate_gain_percent': 125, 'max_bytes_per_second': None, 'max_burst_segments': 2})
        paced.update(options=[], general_pacing=False, prr_pacing=False, pacing_config=None)
        self.assertEqual(paced, base)

    def test_unknown_or_conflicting_profiles_do_not_claim_pipeline_policy(self):
        for flags in ('local=192.0.2.1', 'unknown,local=192.0.2.1',
                      'baseline,pipeline-gso,local=192.0.2.1',
                      'upstream-basic,local=192.0.2.1', 'upstream,ecn,ecn,local=192.0.2.1',
                      'upstream,unpaced,local=192.0.2.1', 'upstream,unpaced-prr,local=192.0.2.1',
                      'upstream,paced,paced,local=192.0.2.1',
                      'upstream,paced,unpaced,local=192.0.2.1',
                      'upstream,immediate-ack,adaptive-ack,local=192.0.2.1',
                      'upstream,budget128m,budget224m,local=192.0.2.1',
                      'baseline,ecn,local=192.0.2.1', 'upstream,rate=42,local=192.0.2.1',
                      'upstream,local=::1', 'upstream,local=192.0.2.1,local=192.0.2.2'):
            metadata = profile_metadata(flags)
            self.assertTrue(all(value is None for key, value in metadata.items() if key != 'profile'))


if __name__ == '__main__':
    unittest.main()
