# SPDX-License-Identifier: GPL-2.0-or-later
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from run import HERE, PIN, adapt_source, preflight, profile_metadata, runner_provenance

class ReceiveSegmentationMapping(unittest.TestCase):
    def test_original_aggregate_and_both_mss_directions_survive_setup_mapping(self):
        directory=HERE.parent.parent/'workbench/packetdrill-upstream'/PIN['tcp_tests']
        if not directory.is_dir():self.skipTest('pinned source unavailable')
        name='gro/gro-mss-option.pkt';manifest=json.loads((HERE/'adaptations.json').read_text());entry=manifest['scripts'][name];source=(directory/name).read_bytes()
        generated,audit=adapt_source(directory,name,manifest,entry['adapter_flags'])
        self.assertEqual(generated,source.replace(entry['command_line'].encode(),entry['replacement_line'].encode(),1))
        for data in [b'--mss=1000',b'<mss 1100',b'1:10001(10000)',b'assert tcpi_rcv_mss == 1000, tcpi_rcv_mss']:
            self.assertIn(data,generated)
        self.assertEqual(audit['generated_sha256'],hashlib.sha256(generated).hexdigest())
        self.assertEqual(preflight(generated.decode(),embedded_tcp_info=True),[])
        self.assertTrue(profile_metadata(entry['adapter_flags'])['receive_tcp_segmentation_metadata'])
        self.assertFalse(profile_metadata(entry['adapter_flags'])['gro']) # no invented automatic merge

    @unittest.skipUnless(os.environ.get('PACKETDRILL_PATCHED_RUNNER'),'audited runner required')
    def test_actual_runner_ingress_callback_preserves_size_and_fails_closed(self):
        runner=Path(os.environ['PACKETDRILL_PATCHED_RUNNER']);runner_provenance(runner)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'input.c').write_text(INPUT_SOURCE)
            subprocess.run(['cc','-Wall','-Werror','-ffunction-sections','-fdata-sections','-I',str(runner.parent),str(p/'input.c'),'-Wl,--gc-sections','-o',str(p/'input')],check=True)
            subprocess.run([str(p/'input')],check=True,timeout=5)

INPUT_SOURCE=r'''
#include "so_testing.c"
#include <stdarg.h>
void die(char *fmt, ...) { (void)fmt; abort(); }
static int raw_calls, segmented_calls;
static int raw(void *u,const void *p,size_t len) { assert(u==(void *)123); assert(p); assert(len>0);++raw_calls;return 7; }
static int segmented(void *u,const void *p,size_t len,u16 size) { assert(u==(void *)123);assert(p);assert(len==10040);assert(size==1000);++segmented_calls;return 9; }
int main(void) {
 unsigned char bytes[10040]={0};
 struct packetdrill_interface ifc={.userdata=(void *)123,.netdev_send=raw};
 struct so_netdev dev={.ifc=&ifc};
 struct packet p={.buffer=bytes,.buffer_bytes=sizeof(bytes),.ip_bytes=sizeof(bytes),.ipv4=(struct ipv4 *)bytes,.tcp=(struct tcp *)(bytes+20)};
 p.headers[0].h.ptr=bytes;p.tcp->doff=5;
 assert(so_netdev_send(&dev.netdev,&p)==7 && raw_calls==1);
 p.mss=1000;errno=0;
 assert(so_netdev_send(&dev.netdev,&p)==STATUS_ERR && errno==EOPNOTSUPP && raw_calls==1);
 dev.send_segmented=segmented;
 assert(so_netdev_send(&dev.netdev,&p)==9 && segmented_calls==1 && raw_calls==1);
 p.ip_bytes=540;
 assert(so_netdev_send(&dev.netdev,&p)==7 && raw_calls==2 && segmented_calls==1);
 p.ip_bytes=40;
 assert(so_netdev_send(&dev.netdev,&p)==7 && raw_calls==3);
 return 0;
}
'''
