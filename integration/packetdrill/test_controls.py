# SPDX-License-Identifier: GPL-2.0-or-later
import collections
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from expectations import PORTED_EXCLUSION, PORTED_SCRIPTS
from run import (AUDITED_CONTROLS, CUSTOM_TFO_KEY_OPTION, CUSTOM_TFO_SCRIPTS, HERE, PIN,
                 UPSTREAM_OPTION_AUDIT, adapt_source, enabled_controls, execution_variant_flags,
                 linux_key_words, preflight, profile_metadata, runner_provenance, select_cases,
                 pinned_source, variant_setup)


DELETED = object()
CONTROL_NAMES = {control['control'] for control in AUDITED_CONTROLS.values()} - {None}
# The only audited entries that refuse blocked_reasons; the others return a
# blocked source untouched so the runner reports the operator's reasons.
REFUSES_BLOCKED = {'fastopen/server/basic-cookie-not-reqd.pkt',
                   'fastopen/server/opt34/basic-cookie-not-reqd.pkt',
                   'zerocopy/fastopen-server.pkt'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def local_commands(control):
    """The exact local command lines an entry adds to its translated source."""
    commands = [local for _, local in control['events']]
    if 'initial' in control:
        commands.insert(0, control['initial'])
    return commands


def tamperings(control, entry, other_setup):
    """Single audit-key changes; a changed line is also tried with its digest recomputed."""
    if control.get('refuses_blocked'):
        yield 'blocked_reasons', {'blocked_reasons': ['unsupported']}
    yield 'variant', {'variant': 'ipv4' if control['variant'] == 'ipv6' else 'ipv6'}
    path, data = other_setup
    yield 'setup_path rehashed', {'setup_path': path, 'setup_sha256': digest(data)}
    yield 'command_sha256', {'command_sha256': 'bad'}
    changed = entry['command_line'] + '\n'
    yield 'command_line', {'command_line': changed}
    yield 'command_line rehashed', {'command_line': changed, 'command_sha256': digest(changed.encode())}
    for line in ('// changed\n', '// bad\n', ''):
        yield 'replacement_line', {'replacement_line': line}
    count = entry['expected_command_count']
    for value in sorted({0, 1, 2, 8, count - 1, count + 1} - {count}):
        yield 'expected_command_count', {'expected_command_count': value}
    yield 'audited_shell_commands', {'audited_shell_commands': []}
    command = entry['audited_shell_commands'][-1]['command'] + ' '
    yield 'audited_shell_commands rehashed', {'audited_shell_commands': [
        *entry['audited_shell_commands'][:-1], {'command': command, 'sha256': digest(command.encode())}]}
    if control['control'] is not None:
        for value in (False, None, DELETED):
            yield control['control'], {control['control']: value}
        key = control['event_sha256_key']
        for value in ('bad', [], DELETED):
            yield key, {key: value}
        retimed = [digest(b' +.09' + event) for event, _ in control['events']]
        yield key + ' rehashed', {key: retimed[0] if len(retimed) == 1 else retimed}
    if 'restore' in control:
        yield 'restore_line', {'restore_line': ''}
        yield 'restore_sha256', {'restore_sha256': 'bad'}
        yield 'restore_replacement_line', {'restore_replacement_line': ''}
        yield 'additional_setup_files', {'additional_setup_files': []}
        restore = '`/bin/true`\n'
        yield 'restore_line rehashed', {'restore_line': restore, 'restore_sha256': digest(restore.encode())}
    for key in control.get('mapping', {}):
        yield 'mapping.' + key, {'mapping': {**entry['mapping'], key: {}}}
    if control['kind'] == 'custom-tfo-key':
        yield 'mapping.packetdrill_addresses', {'mapping': {**entry['mapping'], 'packetdrill_addresses': {}}}


# Source changes the former per-control modules rehashed; each must stay refused.
SOURCE_ALTERATIONS = {
    'mtu_probe/basic-v4.pkt': [(b'initcwnd 11', b'initcwnd 12'), (b'192.0.2.1', b'192.0.2.2'),
                               (b'tcp_base_mss=512', b'tcp_base_mss=600'),
                               (b'   +0 `ip route', b' +.01 `ip route')],
    'mtu_probe/basic-v6.pkt': [(b'initcwnd 11', b'initcwnd 12'), (b'tcp_base_mss=512', b'tcp_base_mss=600'),
                               (b'mtu lock 660', b'mtu lock 661'),
                               (b'   +0 `ip -6 route', b' +.01 `ip -6 route')],
    'md5/md5-only-on-client-ack.pkt': [(b':1F90', b':1F91'), (b'   +0 `grep', b' +.01 `grep'),
                                       (b'0A', b'01')],
    'fastopen/client/nonblocking-sendto-errnos.pkt': [
        (b'   +0 `sysctl -q net.ipv4.tcp_fastopen=0`', b'   +.01 `sysctl -q net.ipv4.tcp_fastopen=0`'),
        (b'tcp_fastopen=1`', b'tcp_fastopen=3`'),
        (b'blackhole_timeout_sec=0', b'blackhole_timeout_sec=60')],
    'fastopen/client/nonblocking-connect-bypass-errno.pkt': [
        (b'   +0 `sysctl -q net.ipv4.tcp_fastopen=0`', b'   +.01 `sysctl -q net.ipv4.tcp_fastopen=0`'),
        (b'tcp_fastopen=1`', b'tcp_fastopen=3`'),
        (b'blackhole_timeout_sec=0', b'blackhole_timeout_sec=60')],
    'fastopen/client/cookie-less-sendto.pkt': [(b' +.03 `sysctl -q net.ipv4.tcp_fastopen=1`',
                                                b' +.03 `sysctl -q net.ipv4.tcp_fastopen=5`')],
    'fastopen/client/synack-data.pkt': [(b'   +0 `sysctl -q net.ipv4.tcp_timestamps=1`',
                                         b'   +0 `sysctl -q net.ipv4.tcp_timestamps=0`'),
                                        (b'   +0 `sysctl -q net.ipv4.tcp_timestamps=1`',
                                         b'   +.01 `sysctl -q net.ipv4.tcp_timestamps=1`')],
    'fastopen/client/nonblocking-sendto.pkt': [(b'+.001 `sysctl', b'+.002 `sysctl'),
                                               (b'flush all', b'flush address 192.0.2.1')],
    'fastopen/client/syn-data-mss.pkt': [(b' +.07 `', b' +.08 `'), (b'tcp_timestamps=0', b'tcp_timestamps=1')],
    'zerocopy/fastopen-client.pkt': [(b' +.07 `', b' +.08 `'), (b'tcp_timestamps=0', b'tcp_timestamps=1')],
    'user_timeout/user-timeout-probe.pkt': [(b'pfifo limit 0', b'pfifo limit 1')],
    'fastopen/server/basic-cookie-not-reqd.pkt': [(b'0x202', b'0x203')],
    'fastopen/server/opt34/basic-cookie-not-reqd.pkt': [(b'0x202', b'0x203')],
    'zerocopy/fastopen-server.pkt': [(b'0x207', b'0x607')],
    'fastopen/server/opt34/simple1.pkt': [(b'a0bf63f7-', b'a0bf63f6-'), (b'192.168.0.2', b'192.168.0.4'),
                                          (b'0x30403', b'0x30407')],
    'fastopen/server/opt34/simple2.pkt': [(b'a0bf63f7-', b'a0bf63f6-'), (b'192.168.0.2', b'192.168.0.4'),
                                          (b'0x30403', b'0x30407')],
    'fastopen/server/opt34/simple3.pkt': [(b'a0bf63f7-', b'a0bf63f6-'), (b'192.168.0.3', b'192.168.0.4'),
                                          (b'0x30403', b'0x30407')],
}


# Local-command text changes the former per-control modules refused in preflight.
PREFLIGHT_ALTERATIONS = {
    'mtu_probe/basic-v4.pkt': [('640', '641'), ('1500 1460', '1500 1461'), ('192.0.2.1', '192.0.2.2')],
    'mtu_probe/basic-v6.pkt': [('660', '661'), ('572', '571'), ('2001:db8::1', '2001:db8::2')],
    'md5/md5-only-on-client-ack.pkt': [('8080', '8081'), ('+0', '+.01')],
    'fastopen/client/nonblocking-sendto.pkt': [('+.001', '+.002'), ('-on-clear', '-off-clear')],
    'fastopen/client/syn-data-mss.pkt': [('+.07', '+.08'), ('-off', '-on')],
    'zerocopy/fastopen-client.pkt': [('+.07', '+.08'), ('-off', '-on')],
    'fastopen/client/synack-data.pkt': [('+0', '+.01'), ('-on', '-off'), ('-on', '-on-clear-tfo-cache')],
    'fastopen/client/cookie-less-sendto.pkt': [('require-cookie', 'protected')],
    'user_timeout/user-timeout-probe.pkt': [(' +0 ', ' +1 '), ('-on', '-off')],
}


COOKIELESS_SERVER_SETTINGS = {'fast_open_early_data_policy': 'ApplicationProtected',
                              'fast_open_client_default': False, 'fast_open_listener_default': False}
CUSTOM_TFO_SETTINGS = {'fast_open_key_hex': 'f763bfa0813d80ed301d64cd904abcce',
                       'fast_open_listener_default': True, 'preallocate_connections': 3}
ALL_VARIANTS = {'ipv4': True, 'ipv6': True, 'ipv4-mapped-v6': True}


# Original assertions each translation keeps, resolved settings, and the IP
# execution variants variant_setup accepts (True) or refuses (False).
ENTRY_EXPECTATIONS = {
    'mtu_probe/basic-v4.pkt': {
        'contains': [b'987:1587(600)', b'3987:4001(14)'],
        'settings': {'software_gso': False, 'initial_window': 'Iw10', 'pmtud_first_hop_mtu': 1500}},
    'mtu_probe/basic-v6.pkt': {
        'settings': {'software_gso': False, 'initial_window': 'Iw10', 'pmtud_first_hop_mtu': 1520},
        'variants': {'ipv6': True, 'ipv4': False, 'ipv4-mapped-v6': False}},
    'md5/md5-only-on-client-ack.pkt': {
        'counts': {b'<md5 000102030405060708090a0b0c0d0e0f,nop,nop>': 2}},
    'fastopen/client/nonblocking-sendto-errnos.pkt': {
        'contains': [b'EOPNOTSUPP'],
        'settings': {'fast_open_client_enabled': True, 'timestamps': False}},
    'fastopen/client/nonblocking-connect-bypass-errno.pkt': {
        'contains': [b'EOPNOTSUPP'],
        'settings': {'fast_open_client_enabled': True, 'timestamps': False}},
    'fastopen/client/cookie-less-sendto.pkt': {
        'contains': [b'> S 0:1000(1000)', b'> S 0:900(900)', b'> S 0:1420(1420)'],
        'absent': [b'clear-tfo'],
        'settings': {'fast_open_client_policy': 'ApplicationProtected',
                     'fast_open_early_data_policy': 'RequireCookie'},
        'variants': ALL_VARIANTS},
    'fastopen/client/synack-data.pkt': {
        'absent': [b'clear-tfo', b'`sysctl'],
        'settings': {'timestamps': False},
        'variants': ALL_VARIANTS},
    'fastopen/client/nonblocking-sendto.pkt': {
        'settings': {'timestamps': False}},
    'fastopen/client/syn-data-mss.pkt': {
        'settings': {'timestamps': True}},
    'zerocopy/fastopen-client.pkt': {
        'settings': {'timestamps': True}},
    'user_timeout/user-timeout-probe.pkt': {},
    'fastopen/server/basic-cookie-not-reqd.pkt': {
        'contains': [b'TCP_FASTOPEN, [2]'],
        'settings': COOKIELESS_SERVER_SETTINGS},
    'fastopen/server/opt34/basic-cookie-not-reqd.pkt': {
        'contains': [b'TCP_FASTOPEN, [2]'],
        'settings': COOKIELESS_SERVER_SETTINGS},
    'zerocopy/fastopen-server.pkt': {
        'contains': [b'TCP_FASTOPEN, [2]', b'SO_EE_CODE_ZEROCOPY_COPIED'],
        'settings': {**COOKIELESS_SERVER_SETTINGS, 'fast_open_early_response': True}},
    'fastopen/server/opt34/simple1.pkt': {
        'contains': [b'--local_ip=192.168.0.2', b'--remote_ip=10.248.0.2'],
        'absent': [b'TCP_FASTOPEN_KEY'],  # Inheritance; no added syscalls.
        'settings': {**CUSTOM_TFO_SETTINGS, 'fast_open_early_response': False},
        'variants': {'ipv4': True, 'ipv4-mapped-v6': True, 'ipv6': False}},
    'fastopen/server/opt34/simple2.pkt': {
        'contains': [b'--local_ip=192.168.0.2', b'--remote_ip=10.248.0.3'],
        'absent': [b'TCP_FASTOPEN_KEY'],
        'settings': {**CUSTOM_TFO_SETTINGS, 'fast_open_early_response': False},
        'variants': {'ipv4': True, 'ipv4-mapped-v6': True, 'ipv6': False}},
    'fastopen/server/opt34/simple3.pkt': {
        'contains': [b'--local_ip=192.168.0.3', b'--remote_ip=10.248.0.3'],
        'absent': [b'TCP_FASTOPEN_KEY'],
        'settings': {**CUSTOM_TFO_SETTINGS, 'fast_open_early_response': True},
        'variants': {'ipv4': True, 'ipv4-mapped-v6': True, 'ipv6': False}},
}


class AuditedControlTable(unittest.TestCase):
    def test_table_covers_each_audited_family_once_per_script(self):
        families = collections.Counter(control['family'] for control in AUDITED_CONTROLS.values())
        self.assertEqual(families, {'route': 2, 'listener assertion': 1, 'TFO permission': 2,
                                    'cookie-less client': 1, 'SYNACK timestamp': 1, 'cache-flush': 1,
                                    'timestamp': 2, 'resource': 1, 'cookieless server': 3,
                                    'custom TFO key': 3})
        self.assertEqual(set(ENTRY_EXPECTATIONS), set(AUDITED_CONTROLS))
        self.assertEqual(set(SOURCE_ALTERATIONS), set(AUDITED_CONTROLS))
        self.assertEqual(CONTROL_NAMES, {'route_control', 'listener_assertion_control',
                                         'tfo_permission_control', 'cookieless_client_control',
                                         'timestamp_on_control', 'cache_flush_control',
                                         'timestamp_control', 'resource_control'})
        for name, control in AUDITED_CONTROLS.items():
            with self.subTest(script=name):
                self.assertEqual(control['control'] is None, not control['events'])
                if control['control'] is not None:
                    self.assertTrue(control['event_sha256_key'].endswith('_event_sha256'))
                # Every replaced line keeps the source's line numbering.
                if 'initial' in control:
                    self.assertEqual(control['initial'].count(b'\n'), control['setup'].count(b'\n'))
                for event, local in control['events']:
                    self.assertEqual(local.count(b'\n'), event.count(b'\n'))
                if 'restore' in control:
                    restore, restored = control['restore']
                    self.assertEqual((restore.count(b'\n'), restored.count(b'\n')), (1, 1))
                    self.assertNotIn(b'`', restored)

    def test_kinds_and_table_data_decide_handling_not_family_labels(self):
        kinds = collections.Counter(control['kind'] for control in AUDITED_CONTROLS.values())
        self.assertEqual(kinds, {'route': 2, 'listener-assertion': 1, 'tfo-permission': 2,
                                 'cookieless-client': 1, 'synack-timestamp': 1, 'cache-flush': 1,
                                 'timestamp': 2, 'resource': 1, 'cookieless-server': 3,
                                 'custom-tfo-key': 3})
        self.assertEqual(CUSTOM_TFO_SCRIPTS, {'fastopen/server/opt34/simple1.pkt',
                                              'fastopen/server/opt34/simple2.pkt',
                                              'fastopen/server/opt34/simple3.pkt'})
        self.assertEqual({name for name, control in AUDITED_CONTROLS.items()
                          if control.get('refuses_blocked')}, REFUSES_BLOCKED)
        for name, control in AUDITED_CONTROLS.items():
            with self.subTest(script=name):
                self.assertEqual(control['kind'] == 'cookieless-server',
                                 'application-protected-tfo' in UPSTREAM_OPTION_AUDIT.get(name, {}))
                self.assertEqual(control['kind'] == 'custom-tfo-key',
                                 CUSTOM_TFO_KEY_OPTION in UPSTREAM_OPTION_AUDIT.get(name, {}))
                # Custom TFO addresses are kept once; the address lines and the
                # required packetdrill_addresses mapping derive from them.
                self.assertNotIn('address_lines', control)
                self.assertNotIn('packetdrill_addresses', control.get('mapping', {}))


class AuditedControlMappings(unittest.TestCase):
    def setUp(self):
        self.directory = pinned_source() / PIN['tcp_tests']
        if not self.directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())

    def adapt(self, name):
        entry = self.manifest['scripts'][name]
        return adapt_source(self.directory, name, self.manifest, entry['adapter_flags'])

    def test_every_entry_translates_only_its_audited_lines(self):
        for name, control in AUDITED_CONTROLS.items():
            with self.subTest(script=name):
                entry = self.manifest['scripts'][name]
                source = (self.directory / name).read_bytes()
                generated, audit = self.adapt(name)
                self.assertEqual(entry['command_line'].encode(), control['setup'])
                pairs = [(entry['command_line'].encode(), entry['replacement_line'].encode()),
                         *control['events']]
                if 'restore' in control:
                    pairs.append((entry['restore_line'].encode(), entry['restore_replacement_line'].encode()))
                    self.assertEqual(pairs[-1], control['restore'])
                expected = source
                for old, new in pairs:
                    self.assertEqual(source.count(old), 1)
                    expected = expected.replace(old, new, 1)
                self.assertEqual(generated, expected)
                self.assertEqual(generated.count(b'\n'), source.count(b'\n'))
                restored = generated
                for old, new in pairs:
                    restored = restored.replace(new, old, 1)
                self.assertEqual(restored, source)
                self.assertEqual(audit['generated_sha256'], digest(generated))
                self.assertEqual((self.directory / name).read_bytes(), source)
                self.assertTrue(audit['mapping']['assertions_preserved'])
                embedded = entry.get('embedded_tcp_info') is True
                self.assertEqual(preflight(generated.decode(), embedded, enabled_controls(entry)), [])
                self.assertTrue(preflight(generated.decode() + '+0 `true`\n', embedded, enabled_controls(entry)))
                if control['control'] is None:
                    self.assertEqual(enabled_controls(entry), ())
                    self.assertNotIn(b'`', generated)
                    continue
                self.assertEqual(enabled_controls(entry), (control['control'],))
                digests = [digest(event) for event, _ in control['events']]
                self.assertEqual(entry[control['event_sha256_key']],
                                 digests[0] if len(digests) == 1 else digests)
                self.assertTrue(preflight(generated.decode(), embedded))
                for other in CONTROL_NAMES - {control['control']}:
                    self.assertTrue(preflight(generated.decode(), embedded, (other,)))

    def test_every_entry_keeps_original_assertions_settings_and_variants(self):
        for name, expectation in ENTRY_EXPECTATIONS.items():
            with self.subTest(script=name):
                entry = self.manifest['scripts'][name]
                generated, audit = self.adapt(name)
                for data in expectation.get('contains', []):
                    self.assertIn(data, generated)
                for data in expectation.get('absent', []):
                    self.assertNotIn(data, generated)
                for data, count in expectation.get('counts', {}).items():
                    self.assertEqual(generated.count(data), count)
                metadata = profile_metadata(entry['adapter_flags'])
                for key, value in expectation.get('settings', {}).items():
                    self.assertEqual(metadata[key], value)
                    self.assertEqual(audit['mapping']['ntcp_settings'][key], value)
                if expectation.get('settings', {}).get('timestamps') is True:
                    self.assertNotIn('no-timestamps', audit['adapter_flags'])
                for variant, accepted in expectation.get('variants', {}).items():
                    flags, variant_audit, reasons = variant_setup(name, generated, entry['adapter_flags'], variant)
                    if not accepted:
                        self.assertTrue(reasons, variant)
                        continue
                    self.assertEqual(reasons, [], variant)
                    if variant_audit is not None:
                        self.assertFalse(variant_audit['body_rewritten'])
                        self.assertEqual(variant_audit['generated_sha256'], digest(generated))

    def test_every_entry_rejects_tampered_audit_keys(self):
        # Another existing setup file, so only the audited setup path can differ.
        other_setup = ('common/set_sysctls.py', (self.directory / 'common/set_sysctls.py').read_bytes())
        for name, control in AUDITED_CONTROLS.items():
            entry = self.manifest['scripts'][name]
            for label, changes in tamperings(control, entry, other_setup):
                manifest = copy.deepcopy(self.manifest)
                row = manifest['scripts'][name]
                for key, value in changes.items():
                    if value is DELETED:
                        row.pop(key, None)
                    else:
                        row[key] = value
                with self.subTest(script=name, tampered=label, changes=changes), \
                        self.assertRaisesRegex(ValueError, 'exact audited ' + re.escape(control['family'])):
                    adapt_source(self.directory, name, manifest, entry['adapter_flags'])

    def test_blocked_entries_are_returned_untouched_unless_the_entry_refuses_them(self):
        # A blocked entry keeps its source for the runner to report unsupported
        # with the operator's reasons; only the cookieless server audit refuses it.
        for name, control in AUDITED_CONTROLS.items():
            manifest = copy.deepcopy(self.manifest)
            entry = manifest['scripts'][name]
            entry['blocked_reasons'] = ['operator: no ntcp mapping here']
            with self.subTest(script=name):
                if name in REFUSES_BLOCKED:
                    with self.assertRaisesRegex(ValueError, 'exact audited ' + re.escape(control['family'])):
                        adapt_source(self.directory, name, manifest, entry['adapter_flags'])
                    continue
                generated, audit = adapt_source(self.directory, name, manifest, entry['adapter_flags'])
                self.assertEqual(generated, (self.directory / name).read_bytes())
                self.assertEqual(audit, entry)
                self.assertNotIn('generated_sha256', audit)

    def test_family_labels_only_name_rejections(self):
        for name, control in AUDITED_CONTROLS.items():
            entry = self.manifest['scripts'][name]
            generated, audit = self.adapt(name)
            accepted = {variant: variant_setup(name, generated, entry['adapter_flags'], variant)[2] == []
                        for variant in ALL_VARIANTS}
            with self.subTest(script=name), patch.dict(control, {'family': 'relabelled'}):
                self.assertEqual(self.adapt(name), (generated, audit))
                for variant, was_accepted in accepted.items():
                    reasons = variant_setup(name, generated, entry['adapter_flags'], variant)[2]
                    self.assertEqual(reasons == [], was_accepted, variant)
                manifest = copy.deepcopy(self.manifest)
                manifest['scripts'][name]['command_sha256'] = 'bad'
                with self.assertRaisesRegex(ValueError, 'expected exact audited relabelled setup'):
                    adapt_source(self.directory, name, manifest, entry['adapter_flags'])

    def test_every_entry_enforces_its_required_settings(self):
        # The resolved profile follows the code-owned option audit, so check
        # the requirement itself: any other required value refuses the entry.
        for name, control in AUDITED_CONTROLS.items():
            entry = self.manifest['scripts'][name]
            for key in control.get('settings', {}):
                with self.subTest(script=name, setting=key), \
                        patch.dict(control['settings'], {key: 'other'}), \
                        self.assertRaisesRegex(ValueError, 'exact audited ' + re.escape(control['family'])):
                    adapt_source(self.directory, name, self.manifest, entry['adapter_flags'])

    def test_every_entry_rejects_rehashed_sources(self):
        for name, control in AUDITED_CONTROLS.items():
            source = (self.directory / name).read_bytes()
            # Each of these changes audited content, so even a table re-pinned
            # to the altered source refuses it.
            alterations = [source + b'+0 `true`\n',
                           source.replace(control['setup'], control['setup'][:-2] + b' `\n', 1)]
            for event, _ in control['events']:
                retimed = re.sub(rb'^(\s*)\S+', rb'\1+.09', event, count=1)
                alterations += [source.replace(event, retimed, 1), source.replace(event, event * 2, 1),
                                source.replace(event, b'0 ' + event, 1)]
            if 'restore' in control:
                alterations.append(source.replace(control['restore'][0], b'', 1))
            for old, new in SOURCE_ALTERATIONS[name]:
                alterations.append(source.replace(old, new))
            for altered in [source + b'\n// tampered\n', *alterations]:
                self.assertNotEqual(altered, source)
                for rehash_commands in (False, True):
                    with self.subTest(script=name, altered=altered[-60:], rehash_commands=rehash_commands):
                        self.assert_rehashed_source_rejected(name, control, altered, rehash_commands)
            for altered in alterations:
                for rehash_commands in (False, True):
                    with self.subTest(script=name, altered=altered[-60:], rehash_commands=rehash_commands,
                                      table='re-pinned'), \
                            patch.dict(control, {'source_sha256': digest(altered)}):
                        self.assert_rehashed_source_rejected(name, control, altered, rehash_commands)
            # Audited lines intact: the final preflight still screens the translation.
            altered = b'--wire_server\n' + source
            with self.subTest(script=name, altered='option', table='re-pinned'), \
                    patch.dict(control, {'source_sha256': digest(altered)}):
                self.assert_rehashed_source_rejected(name, control, altered, False,
                                                     'outside the supported profile')

    def assert_rehashed_source_rejected(self, name, control, altered, rehash_commands, reason=None):
        entry = self.manifest['scripts'][name]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in [name, entry['setup_path'], *(e['path'] for e in entry.get('additional_setup_files', []))]:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(altered if relative == name else (self.directory / relative).read_bytes())
            manifest = copy.deepcopy(self.manifest)
            row = manifest['scripts'][name]
            row['source_sha256'] = digest(altered)
            if rehash_commands:
                # Even an audit recomputed for the altered source cannot extend the capability.
                commands = re.findall(rb'`[^`]*`', altered)
                row['command_line'] = (commands[0] + b'\n').decode()
                row['command_sha256'] = digest(commands[0] + b'\n')
                row['expected_command_count'] = len(commands)
                row['audited_shell_commands'] = [{'command': command.decode(), 'sha256': digest(command)}
                                                 for command in commands]
            if reason is None:
                reason = 'exact audited ' + re.escape(control['family'])
            with self.assertRaisesRegex(ValueError, reason):
                adapt_source(root, name, manifest, entry['adapter_flags'])

    def test_ipv6_route_keeps_original_addresses_and_runs_only_ipv6(self):
        name = 'mtu_probe/basic-v6.pkt'
        entry = self.manifest['scripts'][name]
        generated, _ = self.adapt(name)
        flags, mapping, reasons = variant_setup(name, generated, entry['adapter_flags'], 'ipv6')
        self.assertEqual(reasons, [])
        self.assertFalse(mapping['body_rewritten'])
        self.assertEqual(flags, entry['adapter_flags'])
        packet_flags = execution_variant_flags(name, 'ipv6')
        self.assertIn('--local_ip=fd::1', packet_flags)
        self.assertIn('--remote_ip=2001:db8::1', packet_flags)
        self.assertEqual(mapping['packetdrill_flags'], packet_flags)
        self.assertIn('local=fd::1', entry['adapter_flags'].split(','))
        metadata = profile_metadata(flags)
        self.assertEqual(metadata['pmtud_first_hop_mtu'], 1520)
        self.assertFalse(metadata['software_gso'])
        self.assertEqual(metadata['initial_window'], 'Iw10')
        for variant in ['ipv4', 'ipv4-mapped-v6']:
            self.assertTrue(variant_setup(name, generated, flags, variant)[2])

    def test_cookieless_policies_stay_role_specific(self):
        self.assertEqual(profile_metadata('upstream,local=192.168.0.1')['fast_open_early_data_policy'], 'RequireCookie')
        client = self.manifest['scripts']['fastopen/client/cookie-less-sendto.pkt']
        self.assertFalse(client.get('blocked_reasons'))
        self.assertEqual(client['mapping']['ntcp_settings']['fast_open_client_policy'], 'ApplicationProtected')
        self.assertEqual(client['mapping']['ntcp_settings']['fast_open_early_data_policy'], 'RequireCookie')

    def test_custom_tfo_addresses_select_the_audited_execution_flags(self):
        self.assertEqual(len(CUSTOM_TFO_SCRIPTS), 3)
        for name in sorted(CUSTOM_TFO_SCRIPTS):
            addresses = AUDITED_CONTROLS[name]['addresses']
            entry = self.manifest['scripts'][name]
            self.assertEqual(entry['mapping']['packetdrill_addresses'], addresses)
            self.assertIn('local=' + addresses['local'], entry['adapter_flags'].split(','))
            owner = 'ntcp-ported' if name in PORTED_SCRIPTS else 'upstream'
            selected, _ = select_cases([self.directory / name], self.directory, owner, ['ipv4'])
            self.assertEqual(len(selected), 1)
            self.assertIn(f"--local_ip={addresses['local']}", selected[0][2])
            self.assertIn(f"--remote_ip={addresses['remote']}", selected[0][2])
            if owner == 'ntcp-ported':
                upstream, excluded = select_cases([self.directory / name], self.directory,
                                                  'upstream', ['ipv4'])
                self.assertEqual(upstream, [])
                self.assertEqual(excluded[0]['reasons'], [PORTED_EXCLUSION])
        self.assertEqual(PIN['variants']['ipv4'][1], '--local_ip=192.168.0.1')
        name = 'fastopen/server/opt34/simple1.pkt'
        entry = self.manifest['scripts'][name]
        for key, value in [('packetdrill_addresses', {'local': '192.168.0.1', 'remote': '10.248.0.2'}),
                           ('ntcp_settings', profile_metadata('upstream,local=192.168.0.2,linux-cookie'))]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][name]['mapping'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(self.directory, name, bad, entry['adapter_flags'])

    def test_mapped_address_selection_and_audit_use_the_same_canonical_ipv4_setup(self):
        for name in sorted(CUSTOM_TFO_SCRIPTS):
            if name in PORTED_SCRIPTS:
                continue
            addresses = AUDITED_CONTROLS[name]['addresses']
            entry = self.manifest['scripts'][name]
            generated, _ = self.adapt(name)
            selected, _ = select_cases([self.directory / name], self.directory, 'upstream', ['ipv4-mapped-v6'])
            self.assertEqual(len(selected), 1)
            flags = selected[0][2]
            self.assertIn('--ip_version=ipv4-mapped-ipv6', flags)
            self.assertIn(f"--local_ip={addresses['local']}", flags)
            self.assertIn(f"--remote_ip={addresses['remote']}", flags)
            resolved, audit, reasons = variant_setup(name, generated, entry['adapter_flags'], 'ipv4-mapped-v6')
            self.assertEqual(reasons, [])
            self.assertEqual(resolved, entry['adapter_flags'])
            self.assertEqual(audit['packetdrill_flags'], flags)
            self.assertEqual(audit['generated_sha256'], digest(generated))
            self.assertFalse(audit['body_rewritten'])
        self.assertEqual(PIN['variants']['ipv4-mapped-v6'][1], '--local_ip=192.168.0.1')


class ControlPreflight(unittest.TestCase):
    def test_every_control_exempts_only_its_exact_local_commands_once(self):
        for name, control in AUDITED_CONTROLS.items():
            if control['control'] is None:
                continue
            commands = [command.decode() for command in local_commands(control)]
            text = ''.join(commands)
            enabled = (control['control'],)
            with self.subTest(script=name):
                self.assertEqual(preflight(text, controls=enabled), [])
                self.assertTrue(preflight(text))
                for other in CONTROL_NAMES - set(enabled):
                    self.assertTrue(preflight(text, controls=(other,)))
                changed = [text * 2, text + '+0 `true`\n']
                for command in commands:
                    # Shell appended inside one exact command.
                    closing = command.rindex('`')
                    changed.append(text.replace(command, command[:closing] + '; true' + command[closing:], 1))
                    if len(commands) > 1:
                        changed.append(command)
                for old, new in PREFLIGHT_ALTERATIONS.get(name, []):
                    self.assertNotEqual(text.replace(old, new), text)
                    changed.append(text.replace(old, new))
                for altered in changed:
                    self.assertTrue(preflight(altered, controls=enabled), altered)

    def test_one_control_name_exempts_a_single_audited_entry(self):
        # Both TFO permission entries share the off command; their on commands differ.
        errnos = AUDITED_CONTROLS['fastopen/client/nonblocking-sendto-errnos.pkt']['events']
        bypass = AUDITED_CONTROLS['fastopen/client/nonblocking-connect-bypass-errno.pkt']['events']
        self.assertEqual(errnos[0][1], bypass[0][1])
        text = (errnos[0][1] + errnos[1][1] + bypass[1][1]).decode()
        self.assertTrue(preflight(text, controls=('tfo_permission_control',)))
        route = [AUDITED_CONTROLS['mtu_probe/basic-v4.pkt'], AUDITED_CONTROLS['mtu_probe/basic-v6.pkt']]
        both = ''.join(command.decode() for control in route for command in local_commands(control))
        self.assertTrue(preflight(both, controls=('route_control',)))

    def test_main_enables_only_exactly_true_control_flags(self):
        audit = {'route_control': True, 'timestamp_control': 1, 'resource_control': 'true',
                 'cache_flush_control': False, 'listener_assertion_control': None,
                 'embedded_tcp_info': True, 'mapping': {'route_control': True}}
        self.assertEqual(enabled_controls(audit), ('route_control',))
        self.assertEqual(enabled_controls({}), ())

    def test_link_and_profile_metadata_reject_invalid_route_settings(self):
        self.assertIsNone(profile_metadata('baseline,local=192.0.2.1,no-gso')['software_gso'])
        # The IPv6 physical link floor stays independent of the route cap.
        for flags in ['upstream,local=invalid,link-mtu=1520',
                      'upstream,local=fd::1,link-mtu=660',
                      'upstream,local=fd::1,link-mtu=01520',
                      'upstream,local=fd::1,link-mtu=1520,pmtud1500']:
            self.assertIsNone(profile_metadata(flags)['software_gso'])


class CustomTfoKeyDerivation(unittest.TestCase):
    def test_sysctl_words_are_little_endian_raw_socket_key(self):
        self.assertEqual(linux_key_words('a0bf63f7-ed803d81-cd641d30-cebc4a90'), 'f763bfa0813d80ed301d64cd904abcce')
        self.assertEqual(linux_key_words('00010203-04050607-08090a0b-0c0d0e0f'), '03020100070605040b0a09080f0e0d0c')
        for malformed in ['a0bf63f7ed803d81cd641d30cebc4a90', '00000000-00000000-00000000',
                          '00000000-00000000-00000000-0000000g', '00000000-00000000-00000000-00000000;true']:
            with self.assertRaises(ValueError):
                linux_key_words(malformed)

    def test_key_metadata_rejects_malformed_duplicate_and_wrong_policy(self):
        base = 'upstream,local=192.0.2.1'
        valid = base + ',linux-cookie,' + CUSTOM_TFO_KEY_OPTION
        self.assertEqual(profile_metadata(valid)['fast_open_key_hex'], CUSTOM_TFO_KEY_OPTION[8:])
        for invalid in [base + ',' + CUSTOM_TFO_KEY_OPTION, valid + ',' + CUSTOM_TFO_KEY_OPTION,
                        valid + ',tfo-key=' + '0' * 32, valid[:-1], valid + '0', valid.replace('f763', 'g763'),
                        valid.replace('f763', 'F763'), valid.replace('upstream,', 'baseline,')]:
            with self.subTest(flags=invalid):
                self.assertIsNone(profile_metadata(invalid)['software_gso'])


@unittest.skipUnless(os.environ.get('PACKETDRILL_PATCHED_RUNNER'), 'patched runner required')
class ResourceCommandChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runner = Path(os.environ['PACKETDRILL_PATCHED_RUNNER']).resolve()
        runner_provenance(runner)
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        source = root / 'control.c'
        source.write_text(CONTROL_SOURCE)
        cls.binary = root / 'control'
        subprocess.run(['cc', '-g', '-Wall', '-Werror', '-rdynamic', '-I', str(runner.parent),
                        str(source), str(runner.parent / 'run_command.c'), '-ldl', '-o', str(cls.binary)], check=True)

    def test_exact_controls_and_all_error_paths_cannot_reach_shell(self):
        for command in ('ntcp-local-resource-reject-on', 'ntcp-local-resource-reject-off',
                        'ntcp-local-timestamps-on', 'ntcp-local-timestamps-off'):
            subprocess.run([str(self.binary), command, 'normal'], check=True)
        for command, mode in [('true', 'normal'), ('ntcp-local-resource-reject-on; true', 'normal'),
                              ('ntcp-local-resource-reject-on', 'missing'),
                              ('ntcp-local-resource-reject-on', 'no-so'),
                              ('ntcp-local-timestamps-off; true', 'normal'),
                              ('ntcp-local-timestamps-off', 'missing'),
                              ('ntcp-local-timestamps-off', 'no-so')]:
            result = subprocess.run([str(self.binary), command, mode], capture_output=True)
            self.assertEqual(result.returncode, 42, (command, mode, result.stderr))
            self.assertNotIn(b'UNEXPECTED_SHELL', result.stderr)


CONTROL_SOURCE = r'''
#include "run.h"
#include "run_command.h"
#include "so_testing.h"
#include "config.h"
#include "script.h"
#include <dlfcn.h>
#include <stdarg.h>
int opt_debug;
static int controls;
static int waits;
void wait_for_event(struct state *state) { waits++; }
void die(char *format, ...) { exit(42); }
void die_perror(char *message) { exit(43); }
int safe_system(const char *command, char **error) {
    fprintf(stderr, "UNEXPECTED_SHELL"); exit(90);
}
int ntcp_packetdrill_control(void *userdata, const char *command) {
    assert(userdata == (void *)123);
    assert(!strcmp(command, "ntcp-local-resource-reject-on") ||
           !strcmp(command, "ntcp-local-resource-reject-off") ||
           !strcmp(command, "ntcp-local-timestamps-on") ||
           !strcmp(command, "ntcp-local-timestamps-off"));
    controls++; return 0;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    struct config config = {.script_path = "control.pkt"};
    struct so_instance instance = {.ifc = {.userdata = (void *)123}};
    struct state state = {.config = &config, .so_instance = &instance};
    struct event event = {.line_number = 1};
    struct command_spec command = {.command_line = argv[1]};
    instance.handle = dlopen(!strcmp(argv[2], "missing") ? "libc.so.6" : NULL, RTLD_NOW);
    assert(instance.handle);
    if (!strcmp(argv[2], "no-so")) state.so_instance = NULL;
    run_command_event(&state, &event, &command);
    assert(controls == 1 && waits == 1);
    dlclose(instance.handle);
    return 0;
}
'''
