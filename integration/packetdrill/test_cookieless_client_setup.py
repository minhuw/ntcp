import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from run import (HERE, PIN, COOKIELESS_CLIENT_SCRIPT, COOKIELESS_CLIENT_SETUP,
                 COOKIELESS_CLIENT_EVENT, COOKIELESS_CLIENT_CONTROL,
                 CACHE_FLUSH_RESTORE, CACHE_FLUSH_RESTORED, adapt_source,
                 preflight, variant_setup)

class CookielessClientMapping(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][COOKIELESS_CLIENT_SCRIPT]
        self.source = (self.directory / COOKIELESS_CLIENT_SCRIPT).read_bytes()

    def test_exact_mode_switch_preserves_source_assertions_and_line_numbers(self):
        generated, audit = adapt_source(self.directory, COOKIELESS_CLIENT_SCRIPT, self.manifest, self.entry['adapter_flags'])
        restored = generated.replace(self.entry['replacement_line'].encode(), COOKIELESS_CLIENT_SETUP, 1).replace(COOKIELESS_CLIENT_CONTROL, COOKIELESS_CLIENT_EVENT, 1).replace(CACHE_FLUSH_RESTORED, CACHE_FLUSH_RESTORE, 1)
        self.assertEqual(restored, self.source)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertIn(b'> S 0:1000(1000)', generated)
        self.assertIn(b'> S 0:900(900)', generated)
        self.assertIn(b'> S 0:1420(1420)', generated)
        self.assertNotIn(b'clear-tfo', generated)
        self.assertTrue(preflight(generated.decode(), True))
        self.assertEqual(preflight(generated.decode(), True, cookieless_client_control=True), [])
        for variant in PIN['variants']:
            _, setup, reasons = variant_setup(COOKIELESS_CLIENT_SCRIPT, generated, self.entry['adapter_flags'], variant)
            self.assertEqual(reasons, [])
            if setup:
                self.assertFalse(setup['body_rewritten'])

    def test_modified_audit_or_rehashed_source_cannot_expand_controls(self):
        for key, value in [('cookieless_client_control', False), ('cookieless_client_event_sha256', 'bad'),
                           ('expected_command_count', 2), ('audited_shell_commands', []),
                           ('command_sha256', 'bad'), ('additional_setup_files', []),
                           ('restore_sha256', 'bad'), ('restore_replacement_line', ''),
                           ('replacement_line', '// changed\n'), ('variant', 'ipv6')]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][COOKIELESS_CLIENT_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(self.directory, COOKIELESS_CLIENT_SCRIPT, bad, self.entry['adapter_flags'])
        for source in (self.source.replace(COOKIELESS_CLIENT_EVENT, COOKIELESS_CLIENT_EVENT.replace(b'=1', b'=5')),
                       self.source.replace(COOKIELESS_CLIENT_EVENT, COOKIELESS_CLIENT_EVENT * 2),
                       self.source + b'+0 `true`\n'):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for name in [COOKIELESS_CLIENT_SCRIPT, self.entry['setup_path'], 'common/set_sysctls.py']:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source if name == COOKIELESS_CLIENT_SCRIPT else (self.directory / name).read_bytes())
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][COOKIELESS_CLIENT_SCRIPT]['source_sha256'] = hashlib.sha256(source).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited cookie-less client'):
                    adapt_source(root, COOKIELESS_CLIENT_SCRIPT, bad, self.entry['adapter_flags'])

    def test_control_preflight_is_one_exact_command(self):
        text = COOKIELESS_CLIENT_CONTROL.decode()
        self.assertTrue(preflight(text))
        self.assertEqual(preflight(text, cookieless_client_control=True), [])
        for source in [text * 2, text.replace('require-cookie', 'protected'), text + '+0 `true`\n']:
            self.assertTrue(preflight(source, cookieless_client_control=True))
