# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from expectations import PORTED_SCRIPTS
from run import (COOKIELESS_CLIENT_EVENT, COOKIELESS_CLIENT_CONTROL, ROUTE_CASES, SYNACK_DATA_EVENT, SYNACK_DATA_CONTROL, ROUTE_EVENT, ROUTE_CONTROL, LISTENER_ASSERT_EVENT, LISTENER_ASSERT_CONTROL, TFO_PERMISSION_EVENTS, CACHE_FLUSH_CONTROL, CACHE_FLUSH_EVENT, HERE, PIN, SYN_DATA_ACK_SCRIPTS, TIMESTAMP_CONTROL, TIMESTAMP_EVENT, adapt_source, preflight,
                 select_cases)


class CompleteInventory(unittest.TestCase):
    def test_every_pinned_tcp_source_has_an_owner_and_a_safe_audit(self):
        checkout = HERE.parent.parent / 'workbench/packetdrill-upstream'
        if not checkout.is_dir():
            self.skipTest('pinned checkout unavailable')
        directory = checkout / PIN['tcp_tests']
        tracked = subprocess.check_output(
            ['git', '-C', str(checkout), 'ls-files', '-z', '--', PIN['tcp_tests']],
            text=True).split('\0')
        names = {str(Path(n).relative_to(PIN['tcp_tests'])) for n in tracked if n.endswith('.pkt')}
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.assertEqual(len(names), 162)
        self.assertEqual(names, set(manifest['scripts']))
        selected, excluded = select_cases([directory / n for n in sorted(names)], directory, 'upstream')
        self.assertEqual({str(p.relative_to(directory)) for p, _, _ in selected}, names - PORTED_SCRIPTS)
        self.assertEqual({r['script'] for r in excluded}, PORTED_SCRIPTS)
        self.assertEqual({str(p.relative_to(directory)) for p, v, _ in selected if v == 'ipv4'},
                         {n for n in names - PORTED_SCRIPTS if manifest['scripts'][n]['variant'] == 'ipv4'})
        for name, entry in manifest['scripts'].items():
            with self.subTest(name=name):
                original = (directory / name).read_bytes()
                generated, audit = adapt_source(directory, name, manifest, entry['adapter_flags'])
                self.assertEqual(hashlib.sha256(original).hexdigest(), entry['source_sha256'])
                self.assertTrue(audit['mapping']['assertions_preserved'])
                self.assertEqual((directory / name).read_bytes(), original)
                if entry.get('blocked_reasons'):
                    self.assertEqual(generated, original)
                    self.assertNotIn('generated_sha256', audit)
                    self.assertTrue(entry['audited_shell_commands'])
                else:
                    expected = original.replace(entry['command_line'].encode(), entry['replacement_line'].encode(), 1)
                    if entry.get('restore_line'):
                        expected = expected.replace(entry['restore_line'].encode(), entry['restore_replacement_line'].encode(), 1)
                    if entry.get('route_control'):
                        _, _, event, control, _, _, _ = ROUTE_CASES[name]
                        expected = expected.replace(event, control, 1)
                    if entry.get('listener_assertion_control'):
                        expected = expected.replace(LISTENER_ASSERT_EVENT, LISTENER_ASSERT_CONTROL, 1)
                    if entry.get('tfo_permission_control'):
                        for event, control in TFO_PERMISSION_EVENTS[name]:
                            expected = expected.replace(event, control, 1)
                    if entry.get('cache_flush_control'):
                        expected = expected.replace(CACHE_FLUSH_EVENT, CACHE_FLUSH_CONTROL, 1)
                    if entry.get('cookieless_client_control'):
                        expected = expected.replace(COOKIELESS_CLIENT_EVENT, COOKIELESS_CLIENT_CONTROL, 1)
                    if entry.get('timestamp_on_control'):
                        expected = expected.replace(SYNACK_DATA_EVENT, SYNACK_DATA_CONTROL, 1)
                    if entry.get('timestamp_control'):
                        expected = expected.replace(TIMESTAMP_EVENT, TIMESTAMP_CONTROL, 1)
                    # Existing resource-control mapping is independently covered.
                    if not entry.get('resource_control'):
                        self.assertEqual(generated, expected)
                    self.assertEqual(preflight(generated.decode(), entry.get('embedded_tcp_info') is True,
                                               resource_control=entry.get('resource_control') is True,
                                               timestamp_on_control=entry.get('timestamp_on_control') is True,
                                               timestamp_control=entry.get('timestamp_control') is True,
                                               cache_flush_control=entry.get('cache_flush_control') is True,
                                               tfo_permission_control=entry.get('tfo_permission_control') is True,
                                               cookieless_client_control=entry.get('cookieless_client_control') is True,
                                               listener_assertion_control=entry.get('listener_assertion_control') is True,
                                               route_control=entry.get('route_control') is True), [])

    def test_syn_data_setup_cannot_rehash_an_alternate_policy_into_execution(self):
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        for name in SYN_DATA_ACK_SCRIPTS:
            entry = manifest['scripts'][name]
            original = (directory / name).read_bytes()
            generated, _ = adapt_source(directory, name, manifest, entry['adapter_flags'])
            self.assertEqual(generated.count(b'\n'), original.count(b'\n'))
            with tempfile.TemporaryDirectory() as temporary:
                scratch = Path(temporary)
                for relative in (name, entry['setup_path'], *(r['path'] for r in entry['additional_setup_files'])):
                    target = scratch / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((directory / relative).read_bytes())
                altered = original.replace(b'tcp_min_tso_segs=2', b'tcp_min_tso_segs=4')
                (scratch / name).write_bytes(altered)
                changed = copy.deepcopy(manifest)
                row = changed['scripts'][name]
                row['source_sha256'] = hashlib.sha256(altered).hexdigest()
                row['command_line'] = row['command_line'].replace('tcp_min_tso_segs=2', 'tcp_min_tso_segs=4')
                row['command_sha256'] = hashlib.sha256(row['command_line'].encode()).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited setup'):
                    adapt_source(scratch, name, changed, row['adapter_flags'])
