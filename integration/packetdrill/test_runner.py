import copy
import hashlib
import json
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run import HERE, PIN, adapt_source, invoke, main, outcome, preflight, variants


class RunnerChecks(unittest.TestCase):
    def test_preflight_does_not_ignore_kernel_setup_or_change_packet_expectations(self):
        self.assertEqual(preflight('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3'), [])
        self.assertTrue(preflight('`../common/defaults.sh`'))
        self.assertTrue(preflight('0 %{ assert tcpi_snd_cwnd == 10 }%'))
        self.assertTrue(preflight('--init_scripts=/tmp/script'))
        self.assertTrue(preflight('--so_filename=other.so'))
        self.assertTrue(preflight('--wire_server'))
        self.assertTrue(preflight('0 > S. 0:0(0) ack 1 <mss 1460,sackOK>'))
        self.assertEqual(preflight('0 < S 0:0(0) win 1000 <sackOK>'), [])
        self.assertEqual(preflight('--tolerance_usecs=10000\n0 > . 1:1(0) ack 1'), [])

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
        self.assertEqual(data['coverage'], {'selected_script_files': 3,
                                          'upstream_script_files': 4,
                                          'selection': 'adaptation_allowlist'})
        self.assertEqual(data['counts'], {'failed': 2, 'passed': 1, 'unsupported': 6})
        self.assertFalse(data['all_passed'])
        self.assertEqual(len(calls), 6)
        for row in data['results']:
            self.assertEqual(row['suite'], 'adapted')
            self.assertEqual(row['effective_flags']['adapter'],
                             self.manifest['scripts'][row['script']]['adapter_flags'])
            self.assertIn('generated_sha256', row['adaptation'])
            self.assertEqual(row['behavior_executed'], row['variant'] == 'ipv4')
            self.assertEqual(row['adapted'], row['variant'] == 'ipv4')
        for argv in calls[1::2]:
            self.assertEqual(argv[:4], ['unshare', '--user', '--map-root-user', '--net'])
            self.assertIn(f'--so_filename={plugin}', argv)
        # An override cannot execute with settings different from the audit claim.
        with patch('run.HERE', manifest_dir), patch('run.check_checkout', return_value=PIN['revision']), \
                patch('run.subprocess.check_output', return_value=tracked), \
                patch('run.invoke') as execute, patch.object(sys, 'argv',
                    ['run.py', '--checkout', str(checkout), '--plugin', str(plugin),
                     '--suite', 'adapted', '--report', str(report), '--so-flags', 'baseline']):
            self.assertEqual(main(), 1)
            execute.assert_not_called()
        self.assertEqual(json.loads(report.read_text())['counts'], {'adaptation_rejected': 9})


if __name__ == '__main__':
    unittest.main()
