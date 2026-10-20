# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import unittest
from run import HERE, PIN, SLOW_START_ACK_SCRIPTS, adapt_source, profile_metadata


class SetupProfiles(unittest.TestCase):
    def test_common_abort_ack_policy_and_native_defaults(self):
        for flags in ('upstream,local=192.0.2.1',
                      'upstream,local=192.0.2.1,abort-with-ack',
                      'upstream,local=192.0.2.1,no-timestamps'):
            self.assertIs(profile_metadata(flags)['abort_with_ack'], True)
            self.assertEqual(profile_metadata(flags)['output_push_batch_segments'], 0)
            self.assertIs(profile_metadata(flags)['output_push_batch_retransmissions'], False)
        self.assertNotIn('abort_with_ack', profile_metadata('baseline,local=192.0.2.1'))

    def test_exact_setup_only_and_fail_closed(self):
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        for name in ('nagle/https_client.pkt', 'notsent_lowat/notsent-lowat-sysctl.pkt',
                     'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt', *sorted(SLOW_START_ACK_SCRIPTS)):
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
            self.assertIs(metadata['software_gso'], True)
            self.assertIs(metadata['output_group_flush'], True)
            for key in ('general_pacing', 'hardware_tso'):
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
            elif name in SLOW_START_ACK_SCRIPTS:
                self.assertEqual(source.count(b'\n'), generated.count(b'\n'))
                policy_keys = ('endpoint_max_buffer_bytes', 'congestion_control', 'cubic_hystart')
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

    def test_slow_start_tso_mapping_rejects_rehashed_alternate_commands(self):
        import re
        import tempfile
        from pathlib import Path
        from run import SLOW_START_ACK_SETUP, preflight

        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        for name in sorted(SLOW_START_ACK_SCRIPTS):
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, _ = adapt_source(directory, name, manifest, entry['adapter_flags'])
            self.assertEqual(entry['command_line'].encode(), SLOW_START_ACK_SETUP)
            self.assertEqual(entry['mapping']['ntcp_settings']['endpoint_max_buffer_bytes'],
                             128 * 1024 * 1024)
            self.assertEqual(preflight(generated.decode(), True), [])
            for command in (SLOW_START_ACK_SETUP.replace(b'=100', b'=50'),
                            SLOW_START_ACK_SETUP.replace(b'=100`', b'=100; false`')):
                with self.subTest(name=name, command=command), tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp)
                    (target / name).parent.mkdir(parents=True)
                    altered = source.replace(SLOW_START_ACK_SETUP, command, 1)
                    (target / name).write_bytes(altered)
                    (target / entry['setup_path']).parent.mkdir(parents=True, exist_ok=True)
                    (target / entry['setup_path']).write_bytes((directory / entry['setup_path']).read_bytes())
                    changed = copy.deepcopy(manifest)
                    row = changed['scripts'][name]
                    row['source_sha256'] = hashlib.sha256(altered).hexdigest()
                    row['command_line'] = command.decode()
                    row['command_sha256'] = hashlib.sha256(command).hexdigest()
                    row['audited_shell_commands'] = [
                        {'command': raw.decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
                         'semantic_mapping': 'Unaudited alternate setup.'}
                        for raw in re.findall(rb'`[^`]*`', altered)]
                    with self.assertRaisesRegex(ValueError, 'exact audited setup'):
                        adapt_source(target, name, changed, row['adapter_flags'])

    def test_linux_cookie_explicit_listener_setup_and_capability_metadata(self):
        from run import (LINUX_COOKIE_OPTION, LINUX_COOKIE_SCRIPTS,
                         LINUX_COOKIE_SETTINGS, preflight, tcp_info_only)
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual({name for name, entry in manifest['scripts'].items()
                          if LINUX_COOKIE_OPTION in entry['adapter_flags'].split(',')},
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

    def test_fastopen_pmtud_only_two_exact_setup_mappings(self):
        from run import (FASTOPEN_PMTUD_OPTION, FASTOPEN_PMTUD_SCRIPTS,
                         FASTOPEN_PMTUD_SETTINGS, preflight)
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual({name for name, entry in manifest['scripts'].items()
                          if FASTOPEN_PMTUD_OPTION in entry['adapter_flags'].split(',')},
                         FASTOPEN_PMTUD_SCRIPTS)
        self.assertEqual(len(FASTOPEN_PMTUD_SCRIPTS), 2)
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        for name in sorted(FASTOPEN_PMTUD_SCRIPTS):
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertNotIn(b'`', generated)
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(preflight(generated.decode(), entry['embedded_tcp_info']), [])
            self.assertEqual(source, (directory / name).read_bytes())
            metadata = profile_metadata(entry['adapter_flags'])
            for key, value in {**FASTOPEN_PMTUD_SETTINGS, 'general_pacing': False,
                               'software_gso': True, 'hardware_tso': False}.items():
                self.assertEqual(metadata[key], value)
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])
            for key, value in [('source_sha256', 'bad'), ('setup_sha256', 'bad'),
                               ('command_sha256', 'bad'), ('audited_shell_commands', []),
                               ('expected_command_count', 1), ('additional_setup_files', []),
                               ('restore_sha256', 'bad'), ('restore_line', '`false`\n'),
                               ('restore_replacement_line', '`false`\n'),
                               ('adapter_flags', 'upstream-fastopen,local=192.168.0.1')]:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
        # The new policy cannot silently extend another existing mapping.
        name = 'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt'
        changed = copy.deepcopy(manifest)
        changed['scripts'][name]['adapter_flags'] = changed['scripts'][name]['adapter_flags'] + ',' + FASTOPEN_PMTUD_OPTION
        with self.assertRaises(ValueError):
            adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
        self.assertNotIn('pmtud_first_hop_mtu', profile_metadata('upstream,local=192.168.0.1'))

    def test_adaptive_ack_exact_three_setup_only_mappings(self):
        from run import ADAPTIVE_ACK_OPTION, ADAPTIVE_ACK_SCRIPTS, ADAPTIVE_ACK_SETTINGS, preflight
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual(len(manifest['scripts']), 105)
        self.assertEqual({name for name, entry in manifest['scripts'].items()
                          if ADAPTIVE_ACK_OPTION in entry['adapter_flags'].split(',')},
                         ADAPTIVE_ACK_SCRIPTS)
        self.assertEqual(len(ADAPTIVE_ACK_SCRIPTS), 3)
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        for name in sorted(ADAPTIVE_ACK_SCRIPTS):
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertEqual(source.count(b'\n'), generated.count(b'\n'))
            self.assertEqual(source, (directory / name).read_bytes())
            self.assertNotIn(b'`', generated)
            self.assertIn(b'FO abcd1234', generated)
            self.assertIn(b'FO 1234abcd5678dcba', generated)
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(preflight(generated.decode(), entry['embedded_tcp_info']), [])
            metadata = profile_metadata(entry['adapter_flags'])
            for key, value in {**ADAPTIVE_ACK_SETTINGS, 'general_pacing': False,
                               'software_gso': True, 'hardware_tso': False}.items():
                self.assertEqual(metadata[key], value)
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])
            for key, value in [('source_sha256', 'bad'), ('setup_sha256', 'bad'),
                               ('command_sha256', 'bad'), ('audited_shell_commands', []),
                               ('expected_command_count', 1), ('additional_setup_files', []),
                               ('restore_sha256', 'bad'), ('restore_line', '`false`\n'),
                               ('restore_replacement_line', '`false`\n'),
                               ('adapter_flags', 'upstream-fastopen,local=192.168.0.1')]:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
        name = 'syscall_bad_arg/fastopen-invalid-buf-ptr.pkt'
        changed = copy.deepcopy(manifest)
        changed['scripts'][name]['adapter_flags'] = changed['scripts'][name]['adapter_flags'] + ',' + ADAPTIVE_ACK_OPTION
        with self.assertRaises(ValueError):
            adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
        for options in ('', ',pmtud1500', ',linux-cookie'):
            self.assertTrue(profile_metadata('upstream,local=192.168.0.1' + options)['adaptive_ack'])

    def test_unified_tfo26_exact_setup_only_and_fail_closed(self):
        import re
        import tempfile
        from pathlib import Path
        from run import FASTOPEN_CLIENT_SCRIPTS, NON_TFO_SETUP_COMMANDS, preflight
        from test_runner import TFO26
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        new_supported = FASTOPEN_CLIENT_SCRIPTS | NON_TFO_SETUP_COMMANDS.keys()
        self.assertEqual(len(new_supported), 17)
        for name in TFO26:
            entry = manifest['scripts'][name]
            source = (directory / name).read_bytes()
            generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
            commands = re.findall(rb'`[^`]*`', source)
            self.assertEqual([c['command'].encode() for c in entry['audited_shell_commands']], commands)
            for command, recorded in zip(commands, entry['audited_shell_commands']):
                self.assertEqual(hashlib.sha256(command).hexdigest(), recorded['sha256'])
            self.assertFalse(entry.get('blocked_reasons'))
            expected = source.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
            if 'restore_line' in entry:
                expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
            self.assertEqual(generated, expected)
            self.assertEqual(preflight(generated.decode(), entry.get('embedded_tcp_info') is True), [])
            self.assertEqual(source, (directory / name).read_bytes())
            self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
            if name not in new_supported:
                continue
            mutations = [('source_sha256', 'bad'), ('setup_sha256', 'bad'),
                         ('command_line', '`true`\n'), ('replacement_line', '// hidden\n'),
                         ('adapter_flags', 'baseline,local=192.168.0.1')]
            mutations += [('command_sha256', 'bad'), ('audited_shell_commands', []),
                          ('expected_command_count', 99)]
            if 'restore_line' in entry:
                mutations += [('restore_sha256', 'bad'), ('restore_line', '`false`\n'),
                              ('restore_replacement_line', '`false`\n'),
                              ('additional_setup_files', [])]
            for key, value in mutations:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, changed['scripts'][name]['adapter_flags'])
            policy_keys = ['timestamps', 'endpoint_max_buffer_bytes', 'preallocate_connections',
                           'fast_open_client_default', 'fast_open_listener_default',
                           'general_pacing', 'software_gso', 'hardware_tso']
            if name in FASTOPEN_CLIENT_SCRIPTS:
                policy_keys += ['fast_open_cache', 'fast_open_cookie_policy']
            for key in policy_keys:
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['mapping']['ntcp_settings'][key] = 'incorrect'
                with self.subTest(name=name, policy=key), self.assertRaises(ValueError):
                    adapt_source(directory, name, changed, entry['adapter_flags'])
            # Even a rehashed source must not gain an unaudited shell command.
            with tempfile.TemporaryDirectory() as temporary:
                scratch = Path(temporary)
                for relative in (name, entry['setup_path'],
                                 *(e['path'] for e in entry.get('additional_setup_files', []))):
                    path = scratch / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes((directory / relative).read_bytes())
                altered = source + b'\n`echo unaudited`\n'
                (scratch / name).write_bytes(altered)
                changed = copy.deepcopy(manifest)
                changed['scripts'][name]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaises(ValueError):
                    adapt_source(scratch, name, changed, entry['adapter_flags'])
