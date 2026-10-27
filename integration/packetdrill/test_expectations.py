import copy
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from expectations import NATIVE_SETUP_SCRIPTS, PORTED_EXCLUSION, PORTED_SCRIPTS, apply_expectations, digest, load_expectations
from run import HERE, PIN, adapt_source, enabled_controls, main, preflight, select_cases


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
            self.assertEqual(changed['expectation_input_sha256'], digest(original))
            if name in NATIVE_SETUP_SCRIPTS:
                self.assertNotIn('setup_generated_sha256', changed)
                self.assertFalse(changed['upstream_setup_supported'])
                self.assertEqual(changed['upstream_blocked_reasons'], audit['blocked_reasons'])
                self.assertEqual(changed['native_setup'], entry['native_setup'])
                self.assertNotIn('blocked_reasons', changed)
            else:
                self.assertTrue(changed['upstream_setup_supported'])
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
            self.assertEqual(preflight(derived.decode(), True, enabled_controls(changed)), [])
            self.assertEqual(changed['mapping']['ntcp_settings'], audit['mapping']['ntcp_settings'])
        original, audit = self.generated('notsent_lowat/notsent-lowat-setsockopt.pkt')
        self.assertEqual(apply_expectations(HERE, 'notsent_lowat/notsent-lowat-setsockopt.pkt', original, audit, self.manifest), (original, audit))

    def test_tfo_recovery_port_retains_feedback_timestamps_and_recovery_assertions(self):
        name = 'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        original, derived = source.decode().splitlines(), body.decode().splitlines()
        output = re.compile(r'\+0 > (?:P\.|\.) \d+:\d+\(\d+\) ack 1001')
        # Only the three data-output expectations may change. In particular,
        # do not lose the incoming feedback or any later state/window check.
        self.assertEqual([line for line in original if not output.match(line)],
                         [line for line in derived if not output.match(line)])
        packets = [line for line in derived if output.match(line)]
        self.assertEqual(len(packets), 12)
        self.assertTrue(all('(1000) ack 1001 win 32764 <nop,nop,TS val 2010 ecr '
                            in line for line in packets))
        self.assertEqual(sum('> P.' in line for line in packets[:10]), 5)
        self.assertIn('> P. 9001:10001(1000)', packets[9])
        self.assertEqual([re.search(r'(\d+):(\d+)\(1000\)', line).groups()
                          for line in packets[-2:]], [('1', '1001'), ('1001', '2001')])
        self.assertTrue(all('> .' in line and 'ecr 1010>' in line
                            for line in packets[-2:]))
        self.assertEqual(changed['expectation_adjustment']['expectation_kind'],
                         'ntcp-transport-policy')
        self.assertIn('transport-policy', changed['mapping']['claim'])
        self.assertTrue(changed['upstream_setup_supported'])
        self.assertEqual(changed['mapping']['ntcp_settings'], audit['mapping']['ntcp_settings'])

    def test_simple3_port_keeps_cookie_restart_and_full_early_response(self):
        name = 'fastopen/server/opt34/simple3.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        original, derived = source.decode(), body.decode()
        output = re.compile(r'\+0 > (?:P\.|\.) (\d+):(\d+)\((\d+)\) ack 1001')
        # All other executable events remain identical, except one explicitly
        # accounted SYN sequence slot. Comments describe the native fixture.
        def remaining(text):
            return [line.strip().replace(
                '252334000:252335000(1000) win 10001 ',
                '252334000:252335000(1000) win 10000 ')
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith('//')
                and not output.match(line.strip())]
        self.assertEqual(remaining(original), remaining(derived))
        packets = [line.strip() for line in derived.splitlines()
                   if output.match(line.strip())]
        self.assertEqual(len(packets), 11)
        read_ack = '+0 > . 1:1(0) ack 1001 win 32768 <nop,nop,TS val 100000 ecr 10>'
        self.assertEqual(packets[0], read_ack)
        self.assertLess(derived.index('read(4, ..., 65536) = 1000'), derived.index(read_ack))
        self.assertLess(derived.index(read_ack), derived.index('write(4, ..., 15000) = 15000'))
        frontier = 1
        pushes = []
        for packet in packets[1:]:
            start, end, length = map(int, output.match(packet).groups())
            self.assertEqual((start, end - start, length), (frontier, 1000, 1000))
            frontier = end
            self.assertIn('win 32768 <nop,nop,TS val 100001 ecr 10>', packet)
            if '> P.' in packet:
                pushes.append(end - 1)
        self.assertEqual(frontier, 10001)
        self.assertEqual(pushes, [2000, 4000, 6000, 8000, 10000])
        final_ack = '< . 1001:1001(0) ack 1 win 257 <nop,nop,TS val 20 ecr 100000>'
        self.assertLess(derived.index(packets[-1]), derived.index(final_ack))
        self.assertEqual(derived.count('win 10001 '), 1)
        self.assertEqual(changed['expectation_adjustment']['expectation_kind'],
                         'ntcp-transport-policy')
        self.assertEqual(changed['mapping']['ntcp_settings'], audit['mapping']['ntcp_settings'])

    def test_copied_iovec_port_keeps_send_and_completion_contract(self):
        name = 'zerocopy/maxfrags.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        original, derived = source.decode(), body.decode()
        output = re.compile(r'\+0 > P\. (\d+):(\d+)\((\d+)\) ack 1$')
        intermediate = re.compile(r'\+0 < \. 1:1\(0\) ack (?:36|54|71|88) win 257$')
        # Only data packet boundaries and their intermediate ACKs change.
        # All iovecs, syscall returns, completion cmsgs and timing stay intact.
        def remaining(text):
            return [line.strip() for line in text.splitlines()
                    if line.strip() and not line.lstrip().startswith('//')
                    and not output.fullmatch(line.strip())
                    and not intermediate.fullmatch(line.strip())]
        self.assertEqual(remaining(original), remaining(derived))
        packets = [tuple(map(int, output.fullmatch(line.strip()).groups()))
                   for line in derived.splitlines() if output.fullmatch(line.strip())]
        self.assertEqual(packets, [(1, 19, 18), (19, 37, 18), (37, 101, 64)])
        self.assertEqual(derived.count('SO_EE_CODE_ZEROCOPY_COPIED'), 2)
        self.assertEqual(derived.count('ee_info=0,'), 1)
        self.assertEqual(derived.count('ee_info=1,'), 1)
        self.assertEqual(derived.count('ee_data=0}'), 1)
        self.assertEqual(derived.count('ee_data=1}'), 1)
        self.assertEqual(changed['expectation_adjustment']['expectation_kind'],
                         'ntcp-transport-policy')
        self.assertEqual(changed['mapping']['ntcp_settings'], audit['mapping']['ntcp_settings'])

    def test_mtu_port_preserves_probe_feedback_and_exact_native_route_controls(self):
        name = 'mtu_probe/basic-v4.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        original, derived = source.decode(), body.decode()
        expected = original.replace(
            '  +.1 accept(3, ..., ...) = 4\n',
            '  +.1 accept(3, ..., ...) = 4\n   +0 setsockopt(4, SOL_TCP, TCP_NODELAY, [1], 4) = 0\n', 1
        ).replace('   +0 > P. 3387:3987(600) ack 1', '   +0 > . 3387:3987(600) ack 1', 1)
        executable = lambda text: [line for line in text.splitlines()
                                   if line.strip() and not line.lstrip().startswith('//')]
        self.assertEqual(executable(derived), executable(expected))
        self.assertEqual([line for line in body.splitlines() if b'`' in line],
                         [line for line in source.splitlines() if b'`' in line])
        self.assertIn('1:987(986)', derived)
        self.assertIn('4001:4987(986)', derived)
        self.assertIn('4987:5973(986)', derived)
        self.assertIn('5973:6001(28)', derived)
        self.assertEqual(preflight(derived, controls=('route_control',)), [])
        self.assertTrue(preflight(derived))
        self.assertEqual(changed['expectation_adjustment']['expectation_kind'], 'ntcp-transport-policy')

    def test_ported_controls_cannot_add_change_duplicate_or_retime_commands(self):
        name = 'mtu_probe/basic-v4.pkt'
        source, audit = self.generated(name)
        entry = self.manifest['scripts'][name]
        original = (HERE / entry['fixture']).read_bytes()
        line = entry['local_controls']['lines'][1]['line'].encode()
        variants = [original + b'0 `true`\n', original + line,
                    original.replace(line, b'', 1),
                    original.replace(line, line.replace(b'+0 ', b'+.01 '), 1),
                    original.replace(b'1500 1460 552`', b'1400 1360 552`', 1)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / entry['fixture']
            target.parent.mkdir(parents=True)
            for replacement in variants:
                target.write_bytes(replacement)
                altered = copy.deepcopy(self.manifest)
                altered['scripts'][name]['fixture_sha256'] = digest(replacement)
                with self.subTest(replacement=replacement[-80:]), self.assertRaises(ValueError):
                    apply_expectations(root, name, source, audit, altered)
            target.write_bytes(original)
            for key, value in [('route_control', False), ('route_control', None)]:
                with self.assertRaisesRegex(ValueError, 'local controls'):
                    apply_expectations(root, name, source, {**audit, key: value}, self.manifest)
            altered = copy.deepcopy(self.manifest)
            altered['scripts'][name].pop('local_controls')
            with self.assertRaisesRegex(ValueError, 'shell'):
                apply_expectations(root, name, source, audit, altered)

    def test_unknown_ported_expectation_kind_is_rejected(self):
        name = 'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt'
        source, audit = self.generated(name)
        altered = copy.deepcopy(self.manifest)
        altered['scripts'][name]['expectation_kind'] = 'upstream'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'expectations.json').write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, 'expectation kind'):
                load_expectations(root, PIN['revision'], self.adaptations)
        with self.assertRaisesRegex(ValueError, 'expectation kind'):
            apply_expectations(HERE, name, source, audit, altered)

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
        self.assertEqual(
            {r['script'] for r in inventory if r['owner_suite'] == 'ntcp-ported'},
            PORTED_SCRIPTS & actual.keys())
        for row in inventory:
            self.assertEqual(row['owner_suite'], 'ntcp-ported' if row['script'] in PORTED_SCRIPTS else 'upstream')
            if row['script'] in PORTED_SCRIPTS:
                kind = self.manifest['scripts'][row['script']].get('expectation_kind', 'ntcp-accounting')
                self.assertEqual(row['disposition'], kind + '-expectation')
        self.assertEqual(sum(r['disposition'] == 'unsupported-setup-or-backend' for r in inventory), 10)

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
            shutil.copyfile(base / 'common/set_sysctls.py', source_root / 'common/set_sysctls.py')
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
                    self.assertEqual(data['total'], len(PORTED_SCRIPTS))
                    self.assertEqual(data['eligible_script_files'], len(PORTED_SCRIPTS))
                    self.assertEqual(len(calls), 2 * len(PORTED_SCRIPTS))
                    self.assertEqual(data['counts'], {'passed': len(PORTED_SCRIPTS)})
                    self.assertEqual(data['counts_by_expectation'], {
                        'ntcp-accounting': {'passed': len(PORTED_SCRIPTS) - 4},
                        'ntcp-transport-policy': {'passed': 4},
                    })
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
            for name in ('timestamping/partial.pkt',
                         'fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt',
                         'fastopen/server/opt34/simple3.pkt',
                         'zerocopy/maxfrags.pkt'):
                port_only = argv.copy()
                port_only[port_only.index('ntcp-ported')] = 'upstream'
                port_only += ['--script', name]
                calls.clear()
                with patch('run.HERE', helper_root), patch('run.check_checkout', return_value=PIN['revision']), patch('run.subprocess.check_output', return_value=tracked), patch('run.verify_backend', return_value=('ntcp-socket', digest(plugin.read_bytes()))), patch('run.invoke', side_effect=invoke), patch.object(sys, 'argv', port_only):
                    self.assertEqual(main(), 1) # No executed cases is not a passing suite.
                data = json.loads(report.read_text())
                self.assertEqual(data['total'], 0)
                self.assertEqual(data['counts'], {})
                self.assertFalse(data['all_passed'])
                self.assertEqual([r['script'] for r in data['ported_exclusions']], [name])
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
            self.assertEqual(data['counts'], {'adaptation_rejected': 1, 'passed': len(PORTED_SCRIPTS) - 1})
            self.assertEqual(len(calls), 2 * (len(PORTED_SCRIPTS) - 1))
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

    def test_native_setup_requires_the_exact_blocked_source_contract(self):
        name = 'epoll/epoll_out_edge.pkt'
        original, audit = self.generated(name)
        for change in ('missing', 'kind', 'flags', 'command', 'reasons', 'input', 'fixture'):
            altered = copy.deepcopy(self.manifest)
            entry = altered['scripts'][name]
            if change == 'missing': entry.pop('native_setup')
            if change == 'kind': entry['native_setup']['kind'] = 'execute-linux-shell'
            if change == 'flags': entry['native_setup']['adapter_flags'] += ',reno'
            if change == 'command': entry['native_setup']['source_command_sha256'] = '0' * 64
            if change == 'reasons': entry['native_setup']['source_blocked_reasons'] = []
            if change == 'input': entry['input_generated_sha256'] = '0' * 64
            if change == 'fixture': entry['fixture'] = 'ntcp-expectations/timestamping/partial.pkt'
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'expectations.json').write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    load_expectations(root, PIN['revision'], self.adaptations)
                with self.assertRaises(ValueError):
                    apply_expectations(HERE, name, original, audit, altered)
        unblocked = copy.deepcopy(self.adaptations)
        unblocked['scripts'][name].pop('blocked_reasons')
        with self.assertRaises(ValueError):
            load_expectations(HERE, PIN['revision'], unblocked)
        for field in ('source_sha256', 'command_line', 'blocked_reasons'):
            wrong = copy.deepcopy(audit)
            wrong[field] = '0' * 64 if field == 'source_sha256' else ('`changed`' if field == 'command_line' else ['different missing capability'])
            with self.subTest(field=field), self.assertRaises(ValueError):
                apply_expectations(HERE, name, original, wrong, self.manifest)

    def test_native_epoll_ports_keep_partial_writes_thresholds_and_no_repoll_cycle(self):
        for name in sorted(n for n in NATIVE_SETUP_SCRIPTS if n.startswith('epoll/')):
            entry = self.manifest['scripts'][name]
            source, audit = self.generated(name)
            body, _ = apply_expectations(HERE, name, source, audit, self.manifest)
            text = body.decode()
            self.assertIn('write(4, ..., 59000) = 8000', text)
            self.assertEqual(text.count('write(4, ..., 180000) = 8000'), 2)
            self.assertNotIn('= -1 EAGAIN', text)
            self.assertEqual(text.count('events=EPOLLOUT, fd=4}, 1, 0) = 1'), 4)
            self.assertIn('ack 24001 win 2000', text)
            third = text[text.index('// Partial-write cycle 3'):]
            self.assertEqual(third.count('epoll_wait'), 2)
            self.assertGreater(third.index('epoll_wait'), third.index('ack 24001'))
            if name.endswith('edge_notsent_lowat.pkt'):
                self.assertIn('TCP_NOTSENT_LOWAT, [4000]', text)
                self.assertIn('ack 4001 win 2000', text)
        # The exception still rejects executable setup, even with a matching
        # fixture hash. No native port can turn into a host-shell escape.
        name = 'epoll/epoll_out_edge.pkt'
        source, audit = self.generated(name)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = self.manifest['scripts'][name]
            target = root / entry['fixture']
            target.parent.mkdir(parents=True)
            for body in (b'`sysctl changed`\n', b'0 close(4) = 0\x00'):
                target.write_bytes(body)
                altered = copy.deepcopy(self.manifest)
                altered['scripts'][name]['fixture_sha256'] = digest(body)
                with self.assertRaisesRegex(ValueError, 'shell|NUL'):
                    apply_expectations(root, name, source, audit, altered)

    def test_default_lowat_poll_port_keeps_blocking_and_level_semantics(self):
        name = 'notsent_lowat/notsent-lowat-default.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        text = body.decode()
        self.assertIn('getsockopt(4, SOL_TCP, TCP_NOTSENT_LOWAT, [0], [4]) = 0', text)
        self.assertNotIn('setsockopt(4, SOL_TCP, TCP_NOTSENT_LOWAT', text)
        self.assertIn('write(4, ..., 59000) = 8000', text)
        self.assertIn('write(4, ..., 59000) = 2000', text)
        self.assertNotIn('= -1 EAGAIN', text)
        self.assertNotIn('epoll', text)
        wait1 = '+0...0.020 poll([{fd=4, events=POLLOUT, revents=POLLOUT}], 1, 1000) = 1'
        wait2 = '+0...0.010 poll([{fd=4, events=POLLOUT, revents=POLLOUT}], 1, 1000) = 1'
        self.assertIn(wait1, text)
        self.assertIn(wait2, text)
        during_first = text[text.index(wait1):text.index(wait2)]
        self.assertLess(during_first.index('ack 1 win 0'), during_first.index('ack 1 win 2000'))
        self.assertLess(during_first.index('ack 1 win 2000'), during_first.index('ack 2001 win 2000'))
        self.assertEqual(text.count('events=POLLOUT, revents=0}], 1, 0) = 0'), 2)
        level = 'poll([{fd=4, events=POLLOUT, revents=POLLOUT}], 1, 0) = 1'
        self.assertGreaterEqual(text.count(level), 6)
        # ACKs may only follow actual contiguous emitted ranges, including
        # both the full initial payload ring and the reclaimed2000-byte fill.
        lines = text.splitlines()
        frontier = 1
        for line in lines:
            packet = re.search(r'> P\. (\d+):(\d+)\((\d+)\)', line)
            if packet:
                start, end, length = map(int, packet.groups())
                self.assertEqual(start, frontier)
                self.assertEqual(end - start, length)
                frontier = end
            incoming = re.search(r'< \. 1:1\(0\) ack (\d+) win', line)
            if incoming:
                self.assertLessEqual(int(incoming.group(1)), frontier)
        self.assertEqual(frontier, 10001)
        self.assertIn('ack 10001 win 2000', text)
        self.assertFalse(changed['upstream_setup_supported'])
        self.assertEqual(changed['upstream_blocked_reasons'], audit['blocked_reasons'])
        altered = copy.deepcopy(self.manifest)
        altered['scripts'][name].pop('native_setup')
        with self.assertRaisesRegex(ValueError, 'native accounting setup'):
            apply_expectations(HERE, name, source, audit, altered)

    def test_blocking_write_port_keeps_capacity_boundary_and_valid_feedback(self):
        name = 'blocking/blocking-write.pkt'
        source, audit = self.generated(name)
        body, changed = apply_expectations(HERE, name, source, audit, self.manifest)
        text = body.decode()
        self.assertIn('--tolerance_usecs=10000', text)
        self.assertNotIn('O_NONBLOCK', text)
        self.assertNotIn('MSG_DONTWAIT', text)
        self.assertIn('SO_SNDBUF, [21000]', text)
        self.assertIn('SO_SNDBUF, [42000]', text)
        self.assertIn('+0...0.130 write(4, ..., 61000) = 61000', text)
        self.assertIn('+.010 < . 1:1(0) ack 19000 win 2000', text)
        self.assertIn('+.030 < . 1:1(0) ack 19001 win 2000', text)
        # The selected sequence ranges must support every feedback ACK, and
        # successful admission deliberately precedes full network delivery.
        frontier = 1
        acknowledged = 1
        for line in text.splitlines():
            outgoing = re.search(r'> \. (\d+):(\d+)\((\d+)\)', line)
            if outgoing:
                start, end, length = map(int, outgoing.groups())
                self.assertEqual(start, frontier)
                self.assertEqual(end - start, length)
                frontier = end
            incoming = re.search(r'< \. 1:1\(0\) ack (\d+) win', line)
            if incoming:
                ack = int(incoming.group(1))
                self.assertGreaterEqual(ack, acknowledged)
                self.assertLessEqual(ack, frontier)
                acknowledged = ack
        self.assertEqual(acknowledged, 19001)
        self.assertEqual(frontier, 21001)
        self.assertLess(frontier, 61001)
        self.assertGreater(text.index('< R.'), text.index('ack 19001 win'))
        self.assertFalse(changed['upstream_setup_supported'])
        self.assertEqual(changed['upstream_blocked_reasons'], audit['blocked_reasons'])
        altered = copy.deepcopy(self.manifest)
        altered['scripts'][name].pop('native_setup')
        with self.assertRaisesRegex(ValueError, 'native accounting setup'):
            apply_expectations(HERE, name, source, audit, altered)

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
        self.assertEqual(len(selected), len(PORTED_SCRIPTS))
        self.assertEqual({v for _, v, _ in selected}, {'ipv4'})
        self.assertEqual(excluded, [])
        selected, excluded = select_cases(scripts, directory, 'upstream', ['ipv4'])
        self.assertEqual(selected, [])
        self.assertEqual(sum(PORTED_EXCLUSION in r['reasons'] for r in excluded), len(PORTED_SCRIPTS))
        for invalid in ['ipv6', 'native-ipv4']:
            with self.assertRaises(ValueError):
                select_cases(scripts, directory, 'ntcp-ported', [invalid])


if __name__ == '__main__':
    unittest.main()
