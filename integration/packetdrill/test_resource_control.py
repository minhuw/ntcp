# SPDX-License-Identifier: GPL-2.0-or-later
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from run import (HERE, PIN, RESOURCE_SCRIPT, RESOURCE_SETUP, RESOURCE_EVENT,
                 RESOURCE_CONTROL, adapt_source, preflight, runner_provenance)


class ResourceMappingChecks(unittest.TestCase):
    def test_control_requires_explicit_audited_capability_and_exact_event(self):
        text = RESOURCE_CONTROL.decode()
        self.assertTrue(preflight(text))
        self.assertEqual(preflight(text, resource_control=True), [])
        for changed in (text * 2, text.replace(' +0 ', ' +1 '),
                        text + '+0 `true`\n', text.replace('-on', '-off')):
            self.assertTrue(preflight(changed, resource_control=True))

    def test_exact_source_and_every_nonconfiguration_byte_is_preserved(self):
        directory = HERE.parent.parent / 'workbench/packetdrill-upstream' / PIN['tcp_tests']
        if not directory.is_dir():
            self.skipTest('pinned checkout unavailable')
        manifest = json.loads((HERE / 'adaptations.json').read_text())
        row = manifest['scripts'][RESOURCE_SCRIPT]
        source = (directory / RESOURCE_SCRIPT).read_bytes()
        generated, audit = adapt_source(directory, RESOURCE_SCRIPT, manifest, row['adapter_flags'])
        expected = source.replace(RESOURCE_SETUP, row['replacement_line'].encode(), 1).replace(RESOURCE_EVENT, RESOURCE_CONTROL, 1)
        self.assertEqual(generated, expected)
        self.assertEqual(generated.count(b'\n'), source.count(b'\n'))
        self.assertEqual(preflight(generated.decode(), True, resource_control=True), [])
        self.assertTrue(preflight(generated.decode(), True))
        restored = generated.replace(row['replacement_line'].encode(), RESOURCE_SETUP, 1).replace(RESOURCE_CONTROL, RESOURCE_EVENT, 1)
        self.assertEqual(restored, source)
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(expected).hexdigest())
        for key, value in [('resource_control', False), ('resource_event_sha256', 'bad'),
                           ('expected_command_count', 1), ('command_sha256', 'bad')]:
            bad = copy.deepcopy(manifest)
            bad['scripts'][RESOURCE_SCRIPT][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapt_source(directory, RESOURCE_SCRIPT, bad, row['adapter_flags'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / RESOURCE_SCRIPT
            target.parent.mkdir(parents=True)
            (root / row['setup_path']).parent.mkdir(parents=True)
            (root / row['setup_path']).write_bytes((directory / row['setup_path']).read_bytes())
            altered = source.replace(b'pfifo limit 0', b'pfifo limit 1')
            target.write_bytes(altered)
            bad = copy.deepcopy(manifest)
            bad['scripts'][RESOURCE_SCRIPT]['source_sha256'] = hashlib.sha256(altered).hexdigest()
            with self.assertRaises(ValueError):
                adapt_source(root, RESOURCE_SCRIPT, bad, row['adapter_flags'])


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
