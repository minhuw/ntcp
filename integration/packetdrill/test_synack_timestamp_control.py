# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from run import (HERE, PIN, SYNACK_DATA_SCRIPT, SYNACK_DATA_SETUP,
                 SYNACK_DATA_EVENT, SYNACK_DATA_CONTROL, CACHE_FLUSH_RESTORE,
                 CACHE_FLUSH_RESTORED, adapt_source, preflight, variant_setup)


class SynackTimestampMappingChecks(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][SYNACK_DATA_SCRIPT]
        self.source = (self.directory / SYNACK_DATA_SCRIPT).read_bytes()

    def test_exact_configuration_mapping_preserves_full_trace_and_cache(self):
        generated, audit = adapt_source(self.directory, SYNACK_DATA_SCRIPT,
                                        self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(SYNACK_DATA_SETUP, self.entry['replacement_line'].encode(), 1).replace(SYNACK_DATA_EVENT, SYNACK_DATA_CONTROL, 1).replace(CACHE_FLUSH_RESTORE, CACHE_FLUSH_RESTORED, 1)
        self.assertEqual(generated, expected)
        restored = generated.replace(self.entry['replacement_line'].encode(), SYNACK_DATA_SETUP, 1).replace(SYNACK_DATA_CONTROL, SYNACK_DATA_EVENT, 1).replace(CACHE_FLUSH_RESTORED, CACHE_FLUSH_RESTORE, 1)
        self.assertEqual(restored, self.source)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertFalse(audit['mapping']['ntcp_settings']['timestamps'])
        self.assertNotIn(b'clear-tfo', generated)
        self.assertNotIn(b'`sysctl', generated)
        self.assertTrue(preflight(generated.decode(), True))
        self.assertEqual(preflight(generated.decode(), True, timestamp_on_control=True), [])
        for variant in ('ipv4', 'ipv6', 'ipv4-mapped-v6'):
            _, variant_audit, reasons = variant_setup(SYNACK_DATA_SCRIPT, generated,
                                                     self.entry['adapter_flags'], variant)
            self.assertEqual(reasons, [])
            if variant_audit:
                self.assertFalse(variant_audit['body_rewritten'])

    def test_modified_audit_or_rehashed_source_cannot_expand_control(self):
        for key, value in [('timestamp_on_control', False), ('timestamp_event_sha256', 'bad'),
                           ('expected_command_count', 2), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('replacement_line', '// changed\n'),
                           ('restore_sha256', 'bad'), ('restore_replacement_line', ''),
                           ('additional_setup_files', []), ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][SYNACK_DATA_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(self.directory, SYNACK_DATA_SCRIPT, bad, self.entry['adapter_flags'])
        for altered in (self.source.replace(SYNACK_DATA_EVENT, SYNACK_DATA_EVENT.replace(b'+0', b'+.01')),
                        self.source.replace(SYNACK_DATA_EVENT, SYNACK_DATA_EVENT * 2),
                        self.source.replace(SYNACK_DATA_EVENT, SYNACK_DATA_EVENT.replace(b'=1', b'=0')),
                        self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for name, data in [(SYNACK_DATA_SCRIPT, altered),
                                   (self.entry['setup_path'], (self.directory / self.entry['setup_path']).read_bytes()),
                                   ('common/set_sysctls.py', (self.directory / 'common/set_sysctls.py').read_bytes())]:
                    p = root / name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(data)
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][SYNACK_DATA_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited SYNACK timestamp'):
                    adapt_source(root, SYNACK_DATA_SCRIPT, bad, self.entry['adapter_flags'])

    def test_preflight_only_allows_single_exact_timestamp_on_event(self):
        text = SYNACK_DATA_CONTROL.decode()
        self.assertEqual(preflight(text, timestamp_on_control=True), [])
        self.assertTrue(preflight(text))
        self.assertTrue(preflight(text, timestamp_control=True))
        for changed in (text * 2, text.replace('+0', '+.01'),
                        text.replace('-on', '-off'), text.replace('-on', '-on-clear-tfo-cache'),
                        text + '+0 `true`\n', text.replace('-on`', '-on; true`')):
            with self.subTest(text=changed):
                self.assertTrue(preflight(changed, timestamp_on_control=True))
