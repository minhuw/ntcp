import copy
import hashlib
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run import HERE, PIN, adapt_source, invoke, main, outcome, preflight, select_cases, variants


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
        self.assertTrue(preflight('0 %{ assert tcpi_pacing_rate == 0 }%', True))
        self.assertTrue(preflight('`sysctl something`\n' + text, True))

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


class SelectionChecks(unittest.TestCase):
    def test_selection_combinations_and_exclusion_reasons(self):
        directory = Path('/tests')
        scripts = [directory / name for name in ('basic.pkt', 'only-v4.pkt', 'only-v6.pkt')]
        for suite in ('upstream', 'adapted'):
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
            ('upstream', ['native-ipv4'], None),
            ('adapted', ['unknown'], None),
            ('upstream', [''], None),
            ('upstream', [], None),
            ('upstream', ['ipv4'], ['only-v6.pkt']),
            ('upstream', None, []),
            *[('upstream', None, [name]) for name in
              ('', 'missing.pkt', '*.pkt', '/tests/only-v6.pkt',
               './only-v6.pkt', '../tests/only-v6.pkt', 'only-v6.pkt/')],
        ):
            with self.subTest(suite=suite, variants=variant_filter, scripts=script_filter):
                with self.assertRaises(ValueError):
                    select_cases(scripts, directory, suite, variant_filter, script_filter)
        with self.assertRaises(ValueError):
            select_cases([], directory, 'smoke')

    def test_main_smoke_and_upstream_reporting_status_and_argument_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('runner')
            runner.chmod(0o700)
            plugin = checkout / 'plugin.so'
            plugin.write_text('plugin')
            report = checkout / 'report.json'
            for suite in ('smoke', 'sack', 'upstream'):
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
                        self.assertTrue(data['results'][0]['behavior_executed'])
                        self.assertEqual(execute.call_args_list[1].args[0][:4],
                                         ['unshare', '--user', '--map-root-user', '--net'])
                    with patch.object(sys, 'argv', argv), \
                            patch('run.invoke', return_value=(0, False, '')):
                        self.assertEqual(main(), 0 if native else 1)
                    data = json.loads(report.read_text())
                    self.assertEqual(data['selected_total'], data['eligible_total'])
                    self.assertEqual(data['excluded_cases'], [])
                    self.assertEqual(data['selection'], {'variants': None, 'scripts': None})
                    if suite == 'upstream':
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


class AdaptationChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / PIN['tcp_tests']
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.source = (b'// assertions must survive exactly\n`../common/defaults.sh`\n'
                       b'0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3\n'
                       b'+0 > S 0:0(0) <...>\n+0 close(3) = 0\n')
        self.setup = b'#!/bin/sh\nsysctl -q net.ipv4.tcp_ecn=0\n'
        for name, entry in self.manifest['scripts'].items():
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.source)
            entry['source_sha256'] = hashlib.sha256(self.source).hexdigest()
            entry['setup_sha256'] = hashlib.sha256(self.setup).hexdigest()
        setup = self.directory / 'common/defaults.sh'
        setup.parent.mkdir(parents=True)
        setup.write_bytes(self.setup)
        self.name = 'close/close-on-syn-sent.pkt'
        self.flags = self.manifest['scripts'][self.name]['adapter_flags']

    def test_exact_replacement_preserves_every_other_byte(self):
        for name, entry in self.manifest['scripts'].items():
            generated, audit = adapt_source(self.directory, name, self.manifest,
                                             entry['adapter_flags'])
            before, after = self.source.split(entry['command_line'].encode())
            self.assertEqual(generated, before + entry['replacement_line'].encode() + after)
            self.assertEqual((self.directory / name).read_bytes(), self.source)
            self.assertEqual(audit['source_sha256'], entry['source_sha256'])
            self.assertEqual(audit['setup_sha256'], entry['setup_sha256'])
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
            self.assertFalse(audit['mapping']['linux_defaults_reproduced'])
            self.assertTrue(preflight(self.source.decode()))  # upstream still refuses it
            self.assertEqual(preflight(generated.decode()), [])

    def test_embedded_assertions_preserved_and_hash_bound(self):
        entry = self.manifest['scripts'][self.name]
        path = self.directory / self.name
        original = self.source + b'0 %{ assert tcpi_lost == 0 }%\n'
        path.write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        with self.assertRaises(ValueError):
            adapt_source(self.directory, self.name, self.manifest, self.flags)
        entry['embedded_tcp_info'] = True
        generated, audit = adapt_source(self.directory, self.name, self.manifest, self.flags)
        self.assertTrue(generated.endswith(b'0 %{ assert tcpi_lost == 0 }%\n'))
        self.assertTrue(audit['embedded_tcp_info'])
        path.write_bytes(original.replace(b'== 0', b'== 1'))
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            adapt_source(self.directory, self.name, self.manifest, self.flags)
        original = original.replace(b'tcpi_lost', b'tcpi_pacing_rate')
        path.write_bytes(original)
        entry['source_sha256'] = hashlib.sha256(original).hexdigest()
        with self.assertRaisesRegex(ValueError, 'unsupported TCP_INFO'):
            adapt_source(self.directory, self.name, self.manifest, self.flags)

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
            self.source.replace(b'`../common/defaults.sh`\n', b''),
            self.source + b'0 %{ assert 1 }%\n',
        ):
            with self.subTest(source=source):
                (self.directory / self.name).write_bytes(source)
                self.manifest['scripts'][self.name]['source_sha256'] = hashlib.sha256(source).hexdigest()
                with self.assertRaises(ValueError):
                    adapt_source(self.directory, self.name, self.manifest, self.flags)

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
                            for name in [*self.manifest['scripts'], 'unselected.pkt'])

        def execute(argv, cwd, timeout):
            generated = Path(argv[-1])
            self.assertNotEqual(generated.parent, self.directory)
            self.assertNotIn(b'`', generated.read_bytes())
            calls.append(argv)
            if '--dry_run' in argv or generated.name == 'close-on-syn-sent.pkt':
                return 0, False, ''
            return 1, False, 'packet mismatch'

        argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                '--suite', 'adapted', '--report', str(report)]
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke', side_effect=execute), patch.object(sys, 'argv', argv):
            self.assertEqual(main(), 1)
        data = json.loads(report.read_text())
        self.assertEqual(data['suite'], 'adapted')
        count = len(self.manifest['scripts'])
        self.assertEqual(data['coverage'], {'selected_script_files': count,
                                          'upstream_script_files': count + 1,
                                          'selection': 'adaptation_allowlist'})
        self.assertEqual(data['counts'], {'failed': count - 1, 'passed': 1, 'unsupported': 2 * count})
        self.assertFalse(data['all_passed'])
        self.assertEqual(len(calls), 2 * count)
        for row in data['results']:
            self.assertEqual(row['suite'], 'adapted')
            self.assertEqual(row['effective_flags']['adapter'],
                             self.manifest['scripts'][row['script']]['adapter_flags'])
            self.assertIn('generated_sha256', row['adaptation'])
            self.assertEqual(row['behavior_executed'], row['variant'] == 'ipv4')
            self.assertEqual(row['adapted'], row['variant'] == 'ipv4')
        for invocation in calls[1::2]:
            self.assertEqual(invocation[:4], ['unshare', '--user', '--map-root-user', '--net'])
            self.assertIn(f'--so_filename={plugin}', invocation)
            entry = next(entry for name, entry in self.manifest['scripts'].items()
                         if Path(name).name == Path(invocation[-1]).name)
            embedded = entry.get('embedded_tcp_info') is True
            self.assertEqual(f'LD_PRELOAD={plugin}' in invocation, embedded)
            self.assertEqual('PYTHONOPTIMIZE=0' in invocation, embedded)
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
            self.assertEqual(data['eligible_total'], 3 * count)
            self.assertEqual(data['eligible_script_files'], count)
            self.assertEqual(data['selected_total'], sum(expected_counts.values()))
            self.assertEqual(data['excluded_total'], 3 * count - data['selected_total'])
            self.assertEqual(len(calls), expected_calls)
            self.assertEqual(data['adaptation_manifest_sha256'],
                             hashlib.sha256((manifest_dir / 'adaptations.json').read_bytes()).hexdigest())
            self.assertEqual(data['runner_sha256'], hashlib.sha256(runner.read_bytes()).hexdigest())
            self.assertEqual(data['plugin_sha256'], hashlib.sha256(plugin.read_bytes()).hexdigest())
            for row in data['results']:
                self.assertEqual(row['adaptation']['source_sha256'],
                                 self.manifest['scripts'][row['script']]['source_sha256'])
                self.assertEqual(row['effective_flags']['packetdrill'], PIN['variants'][row['variant']])
        # An override cannot execute with settings different from the audit claim.
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke') as execute, patch.object(sys, 'argv',
                    ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                     '--suite', 'adapted', '--report', str(report), '--so-flags', 'baseline']):
            self.assertEqual(main(), 1)
            execute.assert_not_called()
        self.assertEqual(json.loads(report.read_text())['counts'], {'adaptation_rejected': 3 * count})


if __name__ == '__main__':
    unittest.main()
