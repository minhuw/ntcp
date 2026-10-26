# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from run import (HERE, PIN, ROUTE_V6_SCRIPT, ROUTE_V6_SETUP, ROUTE_V6_INITIAL,
                 ROUTE_V6_EVENT, ROUTE_V6_CONTROL, ROUTE_RESTORE, ROUTE_RESTORED,
                 adapt_source, variant_setup, execution_variant_flags, preflight,
                 profile_metadata)

class Ipv6RouteMapping(unittest.TestCase):
    def setUp(self):
        self.directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not self.directory.is_dir(): self.skipTest('pinned source unavailable')
        self.manifest = json.loads((HERE / 'adaptations.json').read_text())
        self.entry = self.manifest['scripts'][ROUTE_V6_SCRIPT]
        self.source = (self.directory / ROUTE_V6_SCRIPT).read_bytes()

    def test_exact_mapping_preserves_original_packets_timing_and_probe_lengths(self):
        generated, audit = adapt_source(self.directory, ROUTE_V6_SCRIPT, self.manifest, self.entry['adapter_flags'])
        expected = self.source.replace(ROUTE_V6_SETUP, ROUTE_V6_INITIAL, 1).replace(ROUTE_V6_EVENT, ROUTE_V6_CONTROL, 1).replace(ROUTE_RESTORE, ROUTE_RESTORED, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(generated.replace(ROUTE_V6_INITIAL, ROUTE_V6_SETUP, 1).replace(ROUTE_V6_CONTROL, ROUTE_V6_EVENT, 1).replace(ROUTE_RESTORED, ROUTE_RESTORE, 1), self.source)
        self.assertEqual(generated.count(b'\n'), self.source.count(b'\n'))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(generated).hexdigest())
        self.assertEqual(preflight(generated.decode(), route_control=True), [])
        flags, mapping, reasons = variant_setup(ROUTE_V6_SCRIPT, generated, self.entry['adapter_flags'], 'ipv6')
        self.assertEqual(reasons, [])
        self.assertFalse(mapping['body_rewritten'])
        self.assertEqual(flags, self.entry['adapter_flags'])
        packet_flags = execution_variant_flags(ROUTE_V6_SCRIPT, 'ipv6')
        self.assertIn('--local_ip=fd::1', packet_flags)
        self.assertIn('--remote_ip=2001:db8::1', packet_flags)
        metadata = profile_metadata(flags)
        self.assertEqual(metadata['pmtud_first_hop_mtu'], 1520)
        self.assertFalse(metadata['software_gso'])
        self.assertEqual(metadata['initial_window'], 'Iw10')
        for variant in ['ipv4', 'ipv4-mapped-v6']:
            self.assertTrue(variant_setup(ROUTE_V6_SCRIPT, generated, flags, variant)[2])

    def test_alternate_or_rehashed_setup_cannot_enable_extra_route_controls(self):
        for key, value in [('route_control', False), ('route_event_sha256', 'bad'),
                           ('variant', 'ipv4'), ('restore_sha256', 'bad'),
                           ('expected_command_count', 2), ('audited_shell_commands', [])]:
            bad = copy.deepcopy(self.manifest)
            bad['scripts'][ROUTE_V6_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(self.directory, ROUTE_V6_SCRIPT, bad, self.entry['adapter_flags'])
        for altered in [self.source.replace(b'initcwnd 11', b'initcwnd 12'),
                        self.source.replace(b'tcp_base_mss=512', b'tcp_base_mss=600'),
                        self.source.replace(b'mtu lock 660', b'mtu lock 661'),
                        self.source.replace(b'   +0 `ip -6 route', b' +.01 `ip -6 route')]:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for name in [ROUTE_V6_SCRIPT, self.entry['setup_path'], *(e['path'] for e in self.entry['additional_setup_files'])]:
                    p = root / name; p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(altered if name == ROUTE_V6_SCRIPT else (self.directory / name).read_bytes())
                bad = copy.deepcopy(self.manifest)
                bad['scripts'][ROUTE_V6_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
                with self.assertRaisesRegex(ValueError, 'exact audited route'):
                    adapt_source(root, ROUTE_V6_SCRIPT, bad, self.entry['adapter_flags'])

    def test_only_single_exact_control_pair_is_allowed_and_link_floor_stays_physical(self):
        text = (ROUTE_V6_INITIAL + ROUTE_V6_CONTROL).decode()
        self.assertEqual(preflight(text, route_control=True), [])
        self.assertTrue(preflight(text))
        for changed in [text * 2, text.replace('660', '661'), text.replace('572', '571'),
                        text.replace('2001:db8::1', '2001:db8::2'), text + '+0 `true`\n']:
            self.assertTrue(preflight(changed, route_control=True))
        for flags in ['upstream,local=invalid,link-mtu=1520',
                      'upstream,local=fd::1,link-mtu=660',
                      'upstream,local=fd::1,link-mtu=01520',
                      'upstream,local=fd::1,link-mtu=1520,pmtud1500']:
            self.assertIsNone(profile_metadata(flags)['software_gso'])
