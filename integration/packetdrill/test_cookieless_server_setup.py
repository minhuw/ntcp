import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from run import HERE, PIN, COOKIELESS_SERVER_SETUP, adapt_source, preflight, profile_metadata


class CookielessServerMapping(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.exists():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())

    def test_only_setup_changes_and_original_protocol_assertions_are_preserved(self):
        self.assertEqual(len(COOKIELESS_SERVER_SETUP), 3)
        for name in COOKIELESS_SERVER_SETUP:
            entry = self.manifest['scripts'][name]
            source = (self.directory / name).read_bytes()
            generated, audit = adapt_source(self.directory, name, self.manifest, entry['adapter_flags'])
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            if entry.get('restore_line'):
                expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertEqual(generated.count(b'\n'), source.count(b'\n'))
            self.assertEqual(preflight(generated.decode(), True), [])
            self.assertTrue(audit['mapping']['assertions_preserved'])
            settings = audit['mapping']['ntcp_settings']
            self.assertEqual(settings['fast_open_early_data_policy'], 'ApplicationProtected')
            self.assertFalse(settings['fast_open_client_default'])
            self.assertFalse(settings['fast_open_listener_default'])
            self.assertIn('TCP_FASTOPEN, [2]', generated.decode())
            if name.startswith('zerocopy/'):
                self.assertIn(b'SO_EE_CODE_ZEROCOPY_COPIED', generated)
                self.assertTrue(settings['fast_open_early_response'])
        self.assertEqual(profile_metadata('upstream,local=192.168.0.1')['fast_open_early_data_policy'], 'RequireCookie')
        client = self.manifest['scripts']['fastopen/client/cookie-less-sendto.pkt']
        self.assertFalse(client.get('blocked_reasons'))
        self.assertEqual(client['mapping']['ntcp_settings']['fast_open_client_policy'], 'ApplicationProtected')
        self.assertEqual(client['mapping']['ntcp_settings']['fast_open_early_data_policy'], 'RequireCookie')

    def test_corrupt_audit_and_rehashed_alternate_policy_cannot_run(self):
        for name in COOKIELESS_SERVER_SETUP:
            entry = self.manifest['scripts'][name]
            for key, value in [('command_sha256', 'bad'), ('audited_shell_commands', []),
                               ('replacement_line', '// bad\n'), ('expected_command_count', 8)]:
                changed = copy.deepcopy(self.manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(self.directory, name, changed, entry['adapter_flags'])
            with tempfile.TemporaryDirectory() as directory:
                scratch = Path(directory)
                for relative in (name, entry['setup_path'], *(r['path'] for r in entry.get('additional_setup_files', []))):
                    target = scratch / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((self.directory / relative).read_bytes())
                source = (scratch / name).read_bytes().replace(b'0x202', b'0x203').replace(b'0x207', b'0x607')
                (scratch / name).write_bytes(source)
                changed = copy.deepcopy(self.manifest)
                changed['scripts'][name]['source_sha256'] = hashlib.sha256(source).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited cookieless'):
                    adapt_source(scratch, name, changed, entry['adapter_flags'])
