import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from expectations import PORTED_EXCLUSION, PORTED_SCRIPTS, apply_expectations, digest, load_expectations
from run import HERE, PIN, adapt_source, main, preflight, select_cases


class AccountingExpectations(unittest.TestCase):
    def setUp(self):
        self.adaptations = json.loads((HERE / 'adaptations.json').read_text())
        self.manifest, self.manifest_hash = load_expectations(HERE, PIN['revision'], self.adaptations)

    def checkout(self):
        path = Path(os.environ.get('PACKETDRILL_CHECKOUT', HERE.parent.parent / 'workbench/packetdrill-upstream'))
        base = path / PIN['tcp_tests']
        if not (base / 'timestamping/partial.pkt').exists():
            self.skipTest('pinned upstream checkout unavailable')
        return base

    def generated(self, name):
        return adapt_source(self.checkout(), name, self.adaptations,
                            self.adaptations['scripts'][name]['adapter_flags'])

    def test_adjustments_are_explicit_hash_bound_and_leave_original_audit_unchanged(self):
        for name, entry in self.manifest['scripts'].items():
            original, audit = self.generated(name)
            before = copy.deepcopy(audit)
            derived, changed = apply_expectations(HERE, name, original, audit, self.manifest)
            self.assertEqual(audit, before)
            self.assertTrue(audit['mapping']['assertions_preserved'])
            self.assertNotEqual(original, derived)
            self.assertEqual(changed['setup_generated_sha256'], digest(original))
            self.assertEqual(changed['generated_sha256'], digest(derived))
            self.assertEqual(changed['generated_sha256'], entry['fixture_sha256'])
            self.assertFalse(changed['mapping']['assertions_preserved'])
            self.assertFalse(changed['upstream_assertions_preserved'])
            self.assertNotIn('original packet', changed['mapping']['scope'])
            self.assertEqual(changed['expectation_adjustment'], entry)
            self.assertEqual(changed['upstream_setup_mapping'], audit['mapping'])
            self.assertFalse(any('assertion bytes remain unchanged' in reason
                                 or 'original timing bounds remain unchanged' in reason
                                 for reason in changed['mapping']['reasons']))
            self.assertEqual(preflight(derived.decode(), True), [])
            self.assertEqual(changed['mapping']['ntcp_settings'], audit['mapping']['ntcp_settings'])
        original, audit = self.generated('notsent_lowat/notsent-lowat-setsockopt.pkt')
        self.assertEqual(apply_expectations(HERE, 'notsent_lowat/notsent-lowat-setsockopt.pkt', original, audit, self.manifest), (original, audit))

    def test_stale_input_source_and_unsupported_cannot_be_rewritten(self):
        name = 'timestamping/partial.pkt'
        generated, audit = self.generated(name)
        for modified, altered in [(generated + b'\n', audit), (generated, {**audit, 'source_sha256': '0' * 64}), (generated, {**audit, 'blocked_reasons': ['unsupported']})]:
            with self.assertRaises(ValueError):
                apply_expectations(HERE, name, modified, altered, self.manifest)

    def test_fixture_content_hash_shell_and_escape_rejections(self):
        name = 'timestamping/partial.pkt'
        generated, audit = self.generated(name)
        entry = self.manifest['scripts'][name]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / entry['fixture']
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes((HERE / entry['fixture']).read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'fixture hash'):
                apply_expectations(root, name, generated, audit, self.manifest)
            for payload in [b'`false`\n', b'0 close(3) = 0\x00']:
                fixture.write_bytes(payload)
                altered = copy.deepcopy(self.manifest)
                altered['scripts'][name]['fixture_sha256'] = digest(payload)
                with self.assertRaisesRegex(ValueError, 'shell|NUL'):
                    apply_expectations(root, name, generated, audit, altered)
            external = root / 'outside.pkt'
            external.write_bytes(b'0 close(3) = 0\n')
            fixture.unlink()
            fixture.symlink_to(external)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                apply_expectations(root, name, generated, audit, self.manifest)

    def test_manifest_cannot_enable_blocked_cases_or_change_scope(self):
        for mutation in ('schema', 'revision', 'source', 'unsupported', 'path', 'rationale'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                altered = copy.deepcopy(self.manifest)
                name = 'timestamping/partial.pkt'
                if mutation == 'schema': altered['schema_version'] = 2
                if mutation == 'revision': altered['upstream_revision'] = '0' * 40
                if mutation == 'source': altered['scripts'][name]['source_sha256'] = '0' * 64
                if mutation == 'unsupported': altered['scripts']['blocking/blocking-write.pkt'] = {**altered['scripts'][name], 'source_sha256': self.adaptations['scripts']['blocking/blocking-write.pkt']['source_sha256']}
                if mutation == 'path': altered['scripts'][name]['fixture'] = 'ntcp-expectations/../../outside.pkt'
                if mutation == 'rationale': altered['scripts'][name]['rationale'] = ''
                (root / 'expectations.json').write_text(json.dumps(altered))
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    load_expectations(root, PIN['revision'], self.adaptations)

    def test_inventory_covers_every_selected_buffer_reference_and_original_hash(self):
        base = self.checkout()
        actual = {}
        symbols = ['SO_SNDBUF', 'TCP_NOTSENT_LOWAT', 'tcp_notsent_lowat', 'tcpi_sndbuf_limited']
        for name, entry in self.adaptations['scripts'].items():
            source = (base / name).read_bytes()
            found = [s for s in symbols if s.encode() in source]
            if found:
                actual[name] = (digest(source), found)
        inventory = self.manifest['inventory']
        self.assertEqual(len({r['script'] for r in inventory}), len(inventory))
        self.assertEqual({r['script']: (r['source_sha256'], r['symbols']) for r in inventory}, actual)
        self.assertEqual(sum(r['disposition'] == 'ntcp-accounting-expectation' for r in inventory), 2)
        for row in inventory:
            self.assertEqual(row['owner_suite'], 'ntcp-ported' if row['script'] in PORTED_SCRIPTS else 'upstream')
        self.assertEqual(sum(r['disposition'] == 'unsupported-setup-or-backend' for r in inventory), 15)

    def test_derived_scripts_retain_positive_counters_and_last_byte_phase_checks(self):
        partial = (HERE / self.manifest['scripts']['timestamping/partial.pkt']['fixture']).read_text()
        self.assertIn('write(3, ..., 10000) = 4608', partial)
        self.assertEqual(partial.count('ee_data=4607'), 3)
        self.assertEqual(partial.count('scm_nsec=20000000'), 2)
        self.assertEqual(partial.count('scm_nsec=30000000'), 1)
        self.assertIn('assert 5000 <= tcpi_rtt <= 20000', partial)
        limited = (HERE / self.manifest['scripts']['tcp_info/tcp-info-sndbuf-limited.pkt']['fixture']).read_text()
        self.assertEqual(limited.count('assert 16000 <= tcpi_sndbuf_limited <= 24000'), 2)
        self.assertIn('assert 49000 <= tcpi_busy_time <= 52000', limited)
        self.assertIn('assert 69000 <= tcpi_busy_time <= 73000', limited)
        self.assertEqual(limited.count('assert 0 == tcpi_rwnd_limited'), 2)
        self.assertNotIn('ack 70001', limited)

    def test_main_suites_are_disjoint_and_upstream_filters_cannot_run_ported_sources(self):
        base = self.checkout()
        names = [*self.manifest['scripts'], 'slow_start/slow-start-app-limited.pkt']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'checkout'
            source_root = checkout / PIN['tcp_tests']
            helper_root = root / 'integration'
            helper_root.mkdir()
            for name in names:
                target = source_root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((base / name).read_bytes())
            (source_root / 'common').mkdir()
            shutil.copyfile(base / 'common/defaults.sh', source_root / 'common/defaults.sh')
            selected = copy.deepcopy(self.adaptations)
            selected['scripts'] = {n: selected['scripts'][n] for n in names}
            (helper_root / 'adaptations.json').write_text(json.dumps(selected))
            shutil.copyfile(HERE / 'expectations.json', helper_root / 'expectations.json')
            shutil.copytree(HERE / 'ntcp-expectations', helper_root / 'ntcp-expectations')
            runner = checkout / PIN['runner']
            runner.parent.mkdir(parents=True)
            runner.write_text('#!/bin/sh\nexit 0\n')
            runner.chmod(0o755)
            plugin = root / 'plugin.so'
            plugin.write_bytes(b'backend identity is mocked')
            report = root / 'report.json'
            tracked = '\0'.join(str(Path(PIN['tcp_tests']) / n) for n in names) + '\0'
            calls = []
            def invoke(args, cwd, timeout):
                text = Path(args[-1]).read_text()
                calls.append((args, text))
                if '--dry_run' in args: return 0, False, ''
                original = ('write(3, ..., 10000) = 2964' in text or 'write(3, ..., 150000) = 150000' in text)
                return (1 if original else 0), False, ('mock native-byte-accounting mismatch' if original else '')
            owners = {}
            for suite in ['upstream', 'ntcp-ported']:
                calls.clear()
                argv = ['run.py', '--checkout', str(checkout), '--plugin', str(plugin), '--suite', suite, '--variant', 'ipv4', '--report', str(report)]
                with patch('run.HERE', helper_root), patch('run.check_checkout', return_value=PIN['revision']), patch('run.subprocess.check_output', return_value=tracked), patch('run.verify_backend', return_value=('ntcp-socket', digest(plugin.read_bytes()))), patch('run.invoke', side_effect=invoke), patch.object(sys, 'argv', argv):
                    self.assertEqual(main(), 0)
                data = json.loads(report.read_text())
                owners[suite] = {r['script'] for r in data['results']}
                self.assertEqual(data['suite'], suite)
                self.assertTrue(all(r['effective_flags']['profile'] == 'upstream' for r in data['results']))
                if suite == 'ntcp-ported':
                    self.assertEqual(data['total'], 2)
                    self.assertEqual(data['eligible_script_files'], 2)
                    self.assertEqual(len(calls), 4)
                    self.assertEqual(data['counts'], {'passed': 2})
                    self.assertEqual(data['counts_by_expectation'], {'ntcp-accounting': {'passed': 2}})
                    self.assertIn('expectation_manifest_sha256', data)
                    self.assertEqual(data['ported_exclusions'], [])
                    self.assertTrue(all(not r['adaptation']['mapping']['assertions_preserved'] for r in data['results']))
                else:
                    self.assertEqual(data['total'], 1)
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(data['counts'], {'passed': 1})
                    self.assertEqual({r['script'] for r in data['ported_exclusions']}, PORTED_SCRIPTS)
                    self.assertTrue(all(r['reasons'] == [PORTED_EXCLUSION] and r['ported_to'] == 'ntcp-ported' for r in data['ported_exclusions']))
                    self.assertNotIn('expectation_manifest_sha256', data)
                    self.assertTrue(all(r['adaptation']['mapping']['assertions_preserved'] for r in data['results']))
            self.assertFalse(owners['upstream'] & owners['ntcp-ported'])
            self.assertEqual(owners['upstream'] | owners['ntcp-ported'], set(names))
            # Explicit --script is a filter, never an override of suite ownership.
            port_only = argv.copy()
            port_only[port_only.index('ntcp-ported')] = 'upstream'
            port_only += ['--script', 'timestamping/partial.pkt']
            calls.clear()
            with patch('run.HERE', helper_root), patch('run.check_checkout', return_value=PIN['revision']), patch('run.subprocess.check_output', return_value=tracked), patch('run.verify_backend', return_value=('ntcp-socket', digest(plugin.read_bytes()))), patch('run.invoke', side_effect=invoke), patch.object(sys, 'argv', port_only):
                self.assertEqual(main(), 1) # No executed cases is not a passing suite.
            data = json.loads(report.read_text())
            self.assertEqual(data['total'], 0)
            self.assertEqual(data['counts'], {})
            self.assertFalse(data['all_passed'])
            self.assertEqual([r['script'] for r in data['ported_exclusions']], ['timestamping/partial.pkt'])
            self.assertEqual(calls, [])
            # Even a hash-approved derived fixture must pass option/code checks
            # before the external parser is invoked in dry-run mode.
            bad_path = helper_root / self.manifest['scripts']['timestamping/partial.pkt']['fixture']
            bad_path.write_bytes(b'--init_scripts=/tmp/not-allowed\n' + bad_path.read_bytes())
            altered = copy.deepcopy(self.manifest)
            altered['scripts']['timestamping/partial.pkt']['fixture_sha256'] = digest(bad_path.read_bytes())
            (helper_root / 'expectations.json').write_text(json.dumps(altered))
            calls.clear()
            with patch('run.HERE', helper_root), patch('run.check_checkout', return_value=PIN['revision']), patch('run.subprocess.check_output', return_value=tracked), patch('run.verify_backend', return_value=('ntcp-socket', digest(plugin.read_bytes()))), patch('run.invoke', side_effect=invoke), patch.object(sys, 'argv', argv):
                self.assertEqual(main(), 1)
            data = json.loads(report.read_text())
            self.assertEqual(data['counts'], {'adaptation_rejected': 1, 'passed': 1})
            self.assertEqual(len(calls), 2)
            self.assertFalse(any(Path(call[0][-1]).name == 'partial.pkt' for call in calls))
            # A broken port stays excluded; upstream never falls back to the
            # unmodified original simply because the port's audit failed.
            calls.clear()
            upstream_argv = argv.copy()
            upstream_argv[upstream_argv.index('ntcp-ported')] = 'upstream'
            with patch('run.HERE', helper_root), patch('run.check_checkout', return_value=PIN['revision']), patch('run.subprocess.check_output', return_value=tracked), patch('run.verify_backend', return_value=('ntcp-socket', digest(plugin.read_bytes()))), patch('run.invoke', side_effect=invoke), patch.object(sys, 'argv', upstream_argv):
                self.assertEqual(main(), 0)
            data = json.loads(report.read_text())
            self.assertEqual(data['counts'], {'passed': 1})
            self.assertEqual({r['script'] for r in data['ported_exclusions']}, PORTED_SCRIPTS)
            self.assertEqual(len(calls), 2)

    def test_old_expectations_option_cannot_reinclude_ported_cases(self):
        for suite in ['upstream', 'ntcp-ported', 'smoke']:
            with self.subTest(suite=suite), patch.object(sys, 'argv', ['run.py', '--checkout', '/missing', '--suite', suite, '--expectations', 'ntcp']), patch('run.check_checkout') as check, self.assertRaises(SystemExit):
                main()
            check.assert_not_called()

    def test_ported_registry_matches_audit_and_ipv4_suite(self):
        self.assertEqual(set(self.manifest['scripts']), PORTED_SCRIPTS)
        directory = Path('/tests')
        scripts = [directory / name for name in sorted(PORTED_SCRIPTS)]
        selected, excluded = select_cases(scripts, directory, 'ntcp-ported')
        self.assertEqual(len(selected), 2)
        self.assertEqual({v for _, v, _ in selected}, {'ipv4'})
        self.assertEqual(excluded, [])
        selected, excluded = select_cases(scripts, directory, 'upstream', ['ipv4'])
        self.assertEqual(selected, [])
        self.assertEqual(sum(PORTED_EXCLUSION in r['reasons'] for r in excluded), 2)
        for invalid in ['ipv6', 'native-ipv4']:
            with self.assertRaises(ValueError):
                select_cases(scripts, directory, 'ntcp-ported', [invalid])


if __name__ == '__main__':
    unittest.main()
