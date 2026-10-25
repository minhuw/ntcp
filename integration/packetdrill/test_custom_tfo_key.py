# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from run import (HERE, PIN, CUSTOM_TFO_SOURCES, CUSTOM_TFO_SETUP,
                 CUSTOM_TFO_KEY_OPTION, linux_key_words, adapt_source,
                 profile_metadata, select_cases)


class CustomTfoKeyMapping(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())

    def test_sysctl_words_are_little_endian_raw_socket_key(self):
        self.assertEqual(linux_key_words('a0bf63f7-ed803d81-cd641d30-cebc4a90'), 'f763bfa0813d80ed301d64cd904abcce')
        self.assertEqual(linux_key_words('00010203-04050607-08090a0b-0c0d0e0f'), '03020100070605040b0a09080f0e0d0c')
        for malformed in ['a0bf63f7ed803d81cd641d30cebc4a90', '00000000-00000000-00000000',
                          '00000000-00000000-00000000-0000000g', '00000000-00000000-00000000-00000000;true']:
            with self.assertRaises(ValueError):
                linux_key_words(malformed)

    def test_original_assertions_and_address_headers_preserved(self):
        for name, (_, local, remote) in CUSTOM_TFO_SOURCES.items():
            entry = self.manifest['scripts'][name]
            source = (self.directory / name).read_bytes()
            generated, audit = adapt_source(self.directory, name, self.manifest, entry['adapter_flags'])
            self.assertEqual(generated, source.replace(CUSTOM_TFO_SETUP, entry['replacement_line'].encode(), 1))
            self.assertEqual(generated.count(b'\n'), source.count(b'\n'))
            self.assertNotIn(b'TCP_FASTOPEN_KEY', generated)  # Inheritance; no added syscalls.
            self.assertNotIn(b'`', generated)
            self.assertIn(f'--local_ip={local}'.encode(), generated)
            self.assertIn(f'--remote_ip={remote}'.encode(), generated)
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
            metadata = profile_metadata(entry['adapter_flags'])
            self.assertEqual(metadata['fast_open_key_hex'], 'f763bfa0813d80ed301d64cd904abcce')
            self.assertTrue(metadata['fast_open_listener_default'])
            self.assertEqual(metadata['fast_open_early_response'], name.endswith('simple3.pkt'))
            self.assertEqual(metadata['preallocate_connections'], 3)
            selected, _ = select_cases([self.directory / name], self.directory, 'upstream', ['ipv4'])
            self.assertIn(f'--local_ip={local}', selected[0][2])
            self.assertIn(f'--remote_ip={remote}', selected[0][2])
            self.assertEqual(PIN['variants']['ipv4'][1], '--local_ip=192.168.0.1')

    def test_rehashed_key_address_or_policy_changes_are_rejected(self):
        name = next(iter(CUSTOM_TFO_SOURCES));entry = self.manifest['scripts'][name]
        original = (self.directory / name).read_bytes()
        for altered in [original.replace(b'a0bf63f7-', b'a0bf63f6-'), original.replace(b'192.168.0.2', b'192.168.0.4'),
                        original.replace(b'0x30403', b'0x30407'), original + b'+0 `true`\n']:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for relative in [name, entry['setup_path']]:
                    p = directory / relative;p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(altered if relative == name else (self.directory / relative).read_bytes())
                bad = copy.deepcopy(self.manifest);row = bad['scripts'][name]
                row['source_sha256'] = hashlib.sha256(altered).hexdigest()
                command = re.findall(rb'`[^`]*`', altered)[0]
                row['command_line'] = command.decode() + '\n'
                row['command_sha256'] = hashlib.sha256(command + b'\n').hexdigest()
                row['audited_shell_commands'][0].update(command=command.decode(), sha256=hashlib.sha256(command).hexdigest())
                with self.assertRaisesRegex(ValueError, 'exact audited custom TFO'):
                    adapt_source(directory, name, bad, row['adapter_flags'])
        for key, value in [('packetdrill_addresses', {'local': '192.168.0.1', 'remote': '10.248.0.2'}),
                           ('ntcp_settings', profile_metadata('upstream,local=192.168.0.2,linux-cookie'))]:
            bad = copy.deepcopy(self.manifest);bad['scripts'][name]['mapping'][key] = value
            with self.assertRaises(ValueError):
                adapt_source(self.directory, name, bad, entry['adapter_flags'])

    def test_key_metadata_rejects_malformed_duplicate_and_wrong_policy(self):
        base = 'upstream,local=192.0.2.1'
        valid = base + ',linux-cookie,' + CUSTOM_TFO_KEY_OPTION
        self.assertEqual(profile_metadata(valid)['fast_open_key_hex'], CUSTOM_TFO_KEY_OPTION[8:])
        for invalid in [base + ',' + CUSTOM_TFO_KEY_OPTION, valid + ',' + CUSTOM_TFO_KEY_OPTION,
                        valid + ',tfo-key=' + '0' * 32, valid[:-1], valid + '0', valid.replace('f763', 'g763'),
                        valid.replace('f763', 'F763'), valid.replace('upstream,', 'baseline,')]:
            with self.subTest(flags=invalid):
                self.assertIsNone(profile_metadata(invalid)['software_gso'])
