# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest

from run import (HERE, PIN, TIMESTAMP_SCRIPT, TIMESTAMP_SETUP, TIMESTAMP_EVENT,
                 TIMESTAMP_CONTROL, adapt_source, preflight)


class TimestampMappingChecks(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][TIMESTAMP_SCRIPT]
        self.source = (self.directory / TIMESTAMP_SCRIPT).read_bytes()

    def test_exact_timed_translation_preserves_every_nonconfiguration_byte(self):
        generated, audit = adapt_source(self.directory, TIMESTAMP_SCRIPT, self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(TIMESTAMP_SETUP, self.entry['replacement_line'].encode(), 1).replace(TIMESTAMP_EVENT, TIMESTAMP_CONTROL, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        restored = generated.replace(self.entry['replacement_line'].encode(), TIMESTAMP_SETUP, 1).replace(TIMESTAMP_CONTROL, TIMESTAMP_EVENT, 1)
        self.assertEqual(restored, self.source)
        self.assertEqual(preflight(generated.decode(), timestamp_control=True), [])
        self.assertTrue(preflight(generated.decode()))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertTrue(audit['mapping']['ntcp_settings']['timestamps'])
        self.assertNotIn('no-timestamps', audit['adapter_flags'])

    def test_changed_event_and_audit_cannot_enable_execution(self):
        for key, value in [('timestamp_control', False), ('timestamp_event_sha256', 'bad'),
                           ('expected_command_count', 1), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('replacement_line', '// changed\n'),
                           ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][TIMESTAMP_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(self.directory, TIMESTAMP_SCRIPT, bad, self.entry['adapter_flags'])
        for altered in (self.source.replace(b' +.07 `', b' +.08 `'),
                        self.source.replace(b'tcp_timestamps=0', b'tcp_timestamps=1'),
                        self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for name, data in [(TIMESTAMP_SCRIPT, altered), (self.entry['setup_path'], (self.directory / self.entry['setup_path']).read_bytes())]:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                bad = copy.deepcopy(self.manifest)
                # Even a rehashed altered source cannot extend the capability.
                bad['scripts'][TIMESTAMP_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited timestamp'):
                    adapt_source(root, TIMESTAMP_SCRIPT, bad, self.entry['adapter_flags'])

    def test_preflight_accepts_only_one_exact_enabled_control(self):
        text = TIMESTAMP_CONTROL.decode()
        self.assertEqual(preflight(text, timestamp_control=True), [])
        self.assertTrue(preflight(text))
        for changed in (text * 2, text.replace('+.07', '+.08'), text.replace('-off', '-on'),
                        text + '+0 `true`\n', text.replace('-off`', '-off; true`')):
            with self.subTest(text=changed):
                self.assertTrue(preflight(changed, timestamp_control=True))
