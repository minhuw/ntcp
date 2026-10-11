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
        for name in ('nagle/https_client.pkt', 'notsent_lowat/notsent-lowat-sysctl.pkt',
                     'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt'):
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
                              ('restore_replacement_line', '`false`\n'),
                              ('additional_setup_files', [])]
            for key, value in mutations:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
            if name.startswith('nagle/'):
                policy_keys = ('timestamps', 'sack', 'output_push_batch_segments')
            elif name.startswith('syscall_bad_arg/'):
                policy_keys = ('timestamps', 'endpoint_max_buffer_bytes', 'fast_open_client_default',
                               'fast_open_listener_default', 'fast_open_cache')
            else:
                policy_keys = ('global_notsent_lowat', 'socket_notsent_lowat')
            for key in ('general_pacing', 'software_gso', 'hardware_tso', *policy_keys):
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])

    def test_linux_cookie_explicit_listener_setup_and_capability_metadata(self):
        from run import (LINUX_COOKIE_PROFILE, LINUX_COOKIE_SCRIPTS,
                         LINUX_COOKIE_SETTINGS, preflight, tcp_info_only)
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual({name for name, entry in manifest['scripts'].items()
                          if entry['adapter_flags'].startswith(LINUX_COOKIE_PROFILE + ',')},
                         LINUX_COOKIE_SCRIPTS)
        for name in sorted(LINUX_COOKIE_SCRIPTS):
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
            expected = source.replace(b'`../../../common/defaults.sh`\n',
                                      entry['replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertEqual(source, (directory / name).read_bytes())
            self.assertNotIn(b'`', generated)
            self.assertIn(b'TCP_FASTOPEN, [', generated)
            self.assertIn(b'FO 3021b9d889017eeb', generated)
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(preflight(generated.decode(), entry['embedded_tcp_info']), [])
            metadata = profile_metadata(entry['adapter_flags'])
            for key, value in LINUX_COOKIE_SETTINGS.items():
                self.assertEqual(metadata[key], value)
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])
            for key, value in [('source_sha256', 'bad'), ('setup_sha256', 'bad'),
                               ('command_sha256', 'bad'), ('audited_shell_commands', []),
                               ('expected_command_count', 2),
                               ('adapter_flags', 'upstream-fastopen,local=192.168.0.1')]:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
        # No mapping of implicit-listener/address-mismatch cases, FOEXP or nstat assertions.
        for name in ('fastopen/server/opt34/simple1.pkt',
                     'fastopen/server/fin-close-socket.pkt'):
            self.assertNotIn(name, LINUX_COOKIE_SCRIPTS)
        self.assertTrue(preflight('0 `nstat -as | grep TCPFastOpenPassive`'))
        self.assertTrue(tcp_info_only('0 %{ assert (tcpi_options & TCPI_OPT_SYN_DATA) != 0, tcpi_options }%'))
        self.assertFalse(tcp_info_only('0 %{ assert tcpi_options != 0, tcpi_options }%'))
        self.assertFalse(tcp_info_only('0 %{ assert (tcpi_options & TCPI_OPT_SYN_DATA) != 0, print(tcpi_options) }%'))
