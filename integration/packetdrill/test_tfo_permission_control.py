# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest

from run import (HERE, PIN, TFO_PERMISSION_SOURCES, TFO_PERMISSION_SETUP,
                 TFO_PERMISSION_EVENTS, TFO_PERMISSION_RESTORE,
                 TFO_PERMISSION_RESTORED, adapt_source, preflight)


class ClientPermissionMappingChecks(unittest.TestCase):
    script = 'fastopen/client/nonblocking-sendto-errnos.pkt'

    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][self.script]
        self.source = (self.directory / self.script).read_bytes()
        self.events = TFO_PERMISSION_EVENTS[self.script]

    def test_exact_events_preserve_all_nonconfiguration_bytes_and_line_numbers(self):
        generated, audit = adapt_source(self.directory, self.script, self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(TFO_PERMISSION_SETUP, self.entry['replacement_line'].encode(), 1).replace(TFO_PERMISSION_RESTORE, TFO_PERMISSION_RESTORED, 1)
        restored = generated
        for event, control in self.events:
            expected = expected.replace(event, control, 1)
            restored = restored.replace(control, event, 1)
        restored = restored.replace(self.entry['replacement_line'].encode(), TFO_PERMISSION_SETUP, 1).replace(TFO_PERMISSION_RESTORED, TFO_PERMISSION_RESTORE, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(restored, self.source)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        self.assertEqual(preflight(generated.decode(), True, tfo_permission_control=True), [])
        self.assertTrue(preflight(generated.decode(), True))
        self.assertTrue(audit['mapping']['ntcp_settings']['fast_open_client_enabled'])
        self.assertFalse(audit['mapping']['ntcp_settings']['timestamps'])
        self.assertIn(b'EOPNOTSUPP', generated)
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())

    def test_corrupted_audit_cannot_enable_execution(self):
        for key, value in [('tfo_permission_control', False), ('tfo_permission_event_sha256', []),
                           ('expected_command_count', 2), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('replacement_line', '// changed\n'),
                           ('restore_line', ''), ('restore_sha256', 'bad'),
                           ('restore_replacement_line', ''), ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][self.script][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact audited TFO permission'):
                adapt_source(self.directory, self.script, bad, self.entry['adapter_flags'])

    def test_rehashed_source_changes_do_not_extend_capability(self):
        for altered in (self.source.replace(self.events[0][0], self.events[0][0].replace(b'+0 ', b'+.01 ')),
                        self.source.replace(b'tcp_fastopen=1`', b'tcp_fastopen=3`'),
                        self.source.replace(b'blackhole_timeout_sec=0', b'blackhole_timeout_sec=60'),
                        self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                for name in [self.script, self.entry['setup_path'],
                             *(r['path'] for r in self.entry['additional_setup_files'])]:
                    target = directory / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(altered if name == self.script else (self.directory / name).read_bytes())
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][self.script]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited TFO permission'):
                    adapt_source(directory, self.script, bad, self.entry['adapter_flags'])

    def test_preflight_requires_exactly_one_off_and_one_on_event(self):
        text = b''.join(control for _, control in self.events).decode()
        self.assertEqual(preflight(text, tfo_permission_control=True), [])
        self.assertTrue(preflight(text))
        for changed in [text * 2, self.events[0][1].decode(), self.events[1][1].decode(),
                        text.replace('-off`', '-off; true`'), text + '+0 `true`\n']:
            with self.subTest(text=changed):
                self.assertTrue(preflight(changed, tfo_permission_control=True))
        self.assertEqual(len(TFO_PERMISSION_SOURCES), 2)


class DeferredPermissionMappingChecks(ClientPermissionMappingChecks):
    script = 'fastopen/client/nonblocking-connect-bypass-errno.pkt'
