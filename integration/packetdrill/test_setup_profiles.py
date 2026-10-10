# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import unittest
from run import HERE, PIN, adapt_source, profile_metadata


class SetupProfiles(unittest.TestCase):
    def test_exact_setup_only_and_fail_closed(self):
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        for name in ('nagle/https_client.pkt', 'notsent_lowat/notsent-lowat-sysctl.pkt'):
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            if 'restore_line' in entry:
                expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertNotIn(b'`', generated)
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(source, (directory / name).read_bytes())
            metadata = profile_metadata(entry['adapter_flags'])
            for key in ('general_pacing', 'software_gso', 'hardware_tso'):
                self.assertIs(metadata[key], False)
            mutations = [('command_sha256', 'bad'), ('adapter_flags', 'upstream-basic,local=192.168.0.1'),
                         ('expected_command_count', 3), ('audited_shell_commands', [])]
            if 'restore_line' in entry:
                mutations += [('restore_sha256', 'bad'), ('restore_line', '`false`\n'),
                              ('additional_setup_files', [])]
            for key, value in mutations:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
            policy_keys = ('timestamps', 'sack', 'output_push_batch_segments') if name.startswith('nagle/') else ('global_notsent_lowat', 'socket_notsent_lowat')
            for key in ('general_pacing', 'software_gso', 'hardware_tso', *policy_keys):
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])
