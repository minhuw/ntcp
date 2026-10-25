# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from run import (HERE, PIN, ROUTE_SCRIPT, ROUTE_SETUP, ROUTE_INITIAL, ROUTE_EVENT,
                 ROUTE_CONTROL, ROUTE_RESTORE, ROUTE_RESTORED, adapt_source,
                 preflight, profile_metadata)

class RouteControlMapping(unittest.TestCase):
    def setUp(self):
        self.directory=HERE.parent.parent/'workbench/packetdrill-upstream'/PIN['tcp_tests']
        if not self.directory.is_dir(): self.skipTest('pinned checkout unavailable')
        self.manifest=json.loads((HERE/'adaptations.json').read_text());self.entry=self.manifest['scripts'][ROUTE_SCRIPT];self.source=(self.directory/ROUTE_SCRIPT).read_bytes()

    def test_only_setup_and_route_event_change_original_assertions_survive(self):
        generated,audit=adapt_source(self.directory,ROUTE_SCRIPT,self.manifest,self.entry['adapter_flags'])
        expected=self.source.replace(ROUTE_SETUP,ROUTE_INITIAL,1).replace(ROUTE_EVENT,ROUTE_CONTROL,1).replace(ROUTE_RESTORE,ROUTE_RESTORED,1)
        self.assertEqual(generated,expected);self.assertEqual(generated.count(b'\n'),self.source.count(b'\n'))
        self.assertEqual(generated.replace(ROUTE_INITIAL,ROUTE_SETUP,1).replace(ROUTE_CONTROL,ROUTE_EVENT,1).replace(ROUTE_RESTORED,ROUTE_RESTORE,1),self.source)
        self.assertEqual(audit['generated_sha256'],hashlib.sha256(generated).hexdigest())
        self.assertEqual(preflight(generated.decode(),route_control=True),[]);self.assertTrue(preflight(generated.decode()))
        metadata=profile_metadata(self.entry['adapter_flags']);self.assertFalse(metadata['software_gso']);self.assertEqual(metadata['initial_window'],'Iw10');self.assertEqual(metadata['pmtud_first_hop_mtu'],1500)
        self.assertIn(b'987:1587(600)',generated);self.assertIn(b'3987:4001(14)',generated)

    def test_tampered_audit_or_parameters_fail_closed_even_with_new_hash(self):
        for key,value in [('route_control',False),('route_event_sha256','bad'),('expected_command_count',2),('restore_sha256','bad'),('audited_shell_commands',[])]:
            bad=copy.deepcopy(self.manifest);bad['scripts'][ROUTE_SCRIPT][key]=value
            with self.assertRaises(ValueError):adapt_source(self.directory,ROUTE_SCRIPT,bad,self.entry['adapter_flags'])
        for altered in [self.source.replace(b'initcwnd 11',b'initcwnd 12'),self.source.replace(b'192.0.2.1',b'192.0.2.2'),self.source.replace(b'tcp_base_mss=512',b'tcp_base_mss=600'),self.source.replace(b'   +0 `ip route',b' +.01 `ip route')]:
            with tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp)
                for relative in [ROUTE_SCRIPT,self.entry['setup_path'],*(e['path'] for e in self.entry['additional_setup_files'])]:
                    p=directory/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(altered if relative==ROUTE_SCRIPT else (self.directory/relative).read_bytes())
                bad=copy.deepcopy(self.manifest);bad['scripts'][ROUTE_SCRIPT]['source_sha256']=hashlib.sha256(altered).hexdigest()
                with self.assertRaises(ValueError):adapt_source(directory,ROUTE_SCRIPT,bad,self.entry['adapter_flags'])

    def test_preflight_only_allows_exact_enabled_controls_once(self):
        text=(ROUTE_INITIAL+ROUTE_CONTROL).decode();self.assertEqual(preflight(text,route_control=True),[])
        for altered in [text*2,text.replace('640','641'),text.replace('1500 1460','1500 1461'),text+'+0 `true`\n',text.replace('192.0.2.1','192.0.2.2')]:self.assertTrue(preflight(altered,route_control=True))
        self.assertIsNone(profile_metadata('baseline,local=192.0.2.1,no-gso')['software_gso'])
