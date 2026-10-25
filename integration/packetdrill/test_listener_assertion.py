# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest

from run import (HERE, PIN, LISTENER_ASSERT_SCRIPT, LISTENER_ASSERT_SETUP,
                 LISTENER_ASSERT_EVENT, LISTENER_ASSERT_CONTROL,
                 adapt_source, preflight)


class ListenerAssertionMappingChecks(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][LISTENER_ASSERT_SCRIPT]
        self.source = (self.directory / LISTENER_ASSERT_SCRIPT).read_bytes()

    def test_exact_assertion_translation_preserves_packets_syscalls_and_timing(self):
        generated, audit = adapt_source(self.directory, LISTENER_ASSERT_SCRIPT, self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(LISTENER_ASSERT_SETUP, self.entry['replacement_line'].encode(), 1).replace(LISTENER_ASSERT_EVENT, LISTENER_ASSERT_CONTROL, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        restored = generated.replace(self.entry['replacement_line'].encode(), LISTENER_ASSERT_SETUP, 1).replace(LISTENER_ASSERT_CONTROL, LISTENER_ASSERT_EVENT, 1)
        self.assertEqual(restored, self.source)
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertEqual(preflight(generated.decode(), listener_assertion_control=True), [])
        self.assertTrue(preflight(generated.decode()))
        self.assertEqual(generated.count(b'<md5 000102030405060708090a0b0c0d0e0f,nop,nop>'), 2)

    def test_changed_audit_cannot_enable_assertion_execution(self):
        for key, value in [('listener_assertion_control', False), ('listener_assertion_event_sha256', 'bad'),
                           ('expected_command_count', 1), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('replacement_line', '// changed\n'), ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][LISTENER_ASSERT_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact audited listener assertion'):
                adapt_source(self.directory, LISTENER_ASSERT_SCRIPT, bad, self.entry['adapter_flags'])

    def test_rehashed_port_time_or_extra_command_changes_still_fail_closed(self):
        for altered in (self.source.replace(b':1F90', b':1F91'),
                        self.source.replace(b'   +0 `grep', b' +.01 `grep'),
                        self.source.replace(b'0A', b'01'), self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                for name in [LISTENER_ASSERT_SCRIPT, self.entry['setup_path']]:
                    p = directory / name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(altered if name == LISTENER_ASSERT_SCRIPT else (self.directory / name).read_bytes())
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][LISTENER_ASSERT_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited listener assertion'):
                    adapt_source(directory, LISTENER_ASSERT_SCRIPT, bad, self.entry['adapter_flags'])

    def test_preflight_allows_only_the_exact_enabled_assertion(self):
        text = LISTENER_ASSERT_CONTROL.decode()
        self.assertEqual(preflight(text, listener_assertion_control=True), [])
        self.assertTrue(preflight(text))
        for changed in [text * 2, text.replace('8080', '8081'), text.replace('+0', '+.01'),
                        text.replace('8080`', '8080; true`'), text + '+0 `true`\n']:
            with self.subTest(text=changed):
                self.assertTrue(preflight(changed, listener_assertion_control=True))
