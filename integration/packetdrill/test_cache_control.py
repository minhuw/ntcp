# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import tempfile
from pathlib import Path
import unittest

from run import (HERE, PIN, CACHE_FLUSH_SCRIPT, CACHE_FLUSH_SETUP,
                 CACHE_FLUSH_EVENT, CACHE_FLUSH_CONTROL, CACHE_FLUSH_RESTORE,
                 CACHE_FLUSH_RESTORED, adapt_source, preflight)


class ClientCacheMappingChecks(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][CACHE_FLUSH_SCRIPT]
        self.source = (self.directory / CACHE_FLUSH_SCRIPT).read_bytes()

    def test_exact_translation_preserves_every_nonconfiguration_byte(self):
        generated, audit = adapt_source(self.directory, CACHE_FLUSH_SCRIPT, self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(CACHE_FLUSH_SETUP, self.entry['replacement_line'].encode(), 1).replace(CACHE_FLUSH_EVENT, CACHE_FLUSH_CONTROL, 1).replace(CACHE_FLUSH_RESTORE, CACHE_FLUSH_RESTORED, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        restored = generated.replace(self.entry['replacement_line'].encode(), CACHE_FLUSH_SETUP, 1).replace(CACHE_FLUSH_CONTROL, CACHE_FLUSH_EVENT, 1).replace(CACHE_FLUSH_RESTORED, CACHE_FLUSH_RESTORE, 1)
        self.assertEqual(restored, self.source)
        self.assertEqual(preflight(generated.decode(), True, cache_flush_control=True), [])
        self.assertTrue(preflight(generated.decode(), True))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertFalse(audit['mapping']['ntcp_settings']['timestamps'])

    def test_altered_audit_cannot_enable_execution(self):
        for key, value in [('cache_flush_control', False), ('cache_flush_event_sha256', 'bad'),
                           ('expected_command_count', 2), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('replacement_line', '// changed\n'),
                           ('restore_line', ''), ('restore_sha256', 'bad'),
                           ('restore_replacement_line', ''), ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][CACHE_FLUSH_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact audited cache-flush'):
                adapt_source(self.directory, CACHE_FLUSH_SCRIPT, bad, self.entry['adapter_flags'])

    def test_rehashed_changed_source_cannot_extend_capability(self):
        for altered in (self.source.replace(b'+.001 `sysctl', b'+.002 `sysctl'),
                        self.source.replace(b'flush all', b'flush address 192.0.2.1'),
                        self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                for name in [CACHE_FLUSH_SCRIPT, self.entry['setup_path'],
                             *(r['path'] for r in self.entry['additional_setup_files'])]:
                    target = directory / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(altered if name == CACHE_FLUSH_SCRIPT else (self.directory / name).read_bytes())
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][CACHE_FLUSH_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited cache-flush'):
                    adapt_source(directory, CACHE_FLUSH_SCRIPT, bad, self.entry['adapter_flags'])

    def test_preflight_accepts_only_the_exact_enabled_event(self):
        text = CACHE_FLUSH_CONTROL.decode()
        self.assertEqual(preflight(text, cache_flush_control=True), [])
        self.assertTrue(preflight(text))
        for changed in [text * 2, text.replace('+.001', '+.002'),
                        text.replace('-on-clear', '-off-clear'),
                        text.replace('-cache`', '-cache; true`'), text + '+0 `true`\n']:
            with self.subTest(text=changed):
                self.assertTrue(preflight(changed, cache_flush_control=True))
