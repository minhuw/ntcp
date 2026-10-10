# SPDX-License-Identifier: GPL-2.0-or-later
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from run import HERE, PIN, check_checkout, preflight, runner_provenance, tcp_info_only


class SelectionChecks(unittest.TestCase):
    def test_only_supported_assertions(self):
        self.assertTrue(tcp_info_only('0 %{ assert tcpi_lost == 0 }%'))
        self.assertTrue(tcp_info_only('0 %{ assert tcpi_snd_cwnd == 10;\\\n }%'))
        for snippet in ('assert SK_MEMINFO_RMEM_ALLOC == 0',
                        'assert bbr_bw == 0', 'assert tcpv_minrtt == 0',
                        'assert tcpi_pacing_rate == 0',
                        'assert globals().get("SK_MEMINFO_RMEM_ALLOC", 0) == 0',
                        'SK_MEMINFO_RMEM_ALLOC = 0; assert SK_MEMINFO_RMEM_ALLOC == 0',
                        'try:\n assert bbr_bw == 0\nexcept NameError:\n pass',
                        'import os', 'assert tcpi_lost == 0 }% %{'):
            with self.subTest(snippet=snippet):
                self.assertTrue(preflight('0 %{ ' + snippet + ' }%', True))

    def test_provenance_is_bound_to_recipe_patch_revision_and_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / 'packetdrill'
            runner.write_bytes(b'executable')
            for name in ('build_runner.py', 'code-sockopt.patch'):
                (root / name).write_bytes(name.encode())
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            data = {'source_revision': PIN['revision'],
                    'executable_sha256': digest(runner),
                    'build_helper_sha256': digest(root / 'build_runner.py'),
                    'patch_sha256': digest(root / 'code-sockopt.patch')}
            sidecar = runner.with_suffix('.provenance.json')
            with patch('run.HERE', root):
                with self.assertRaises(OSError):
                    runner_provenance(runner)
                sidecar.write_text(json.dumps(data))
                self.assertEqual(runner_provenance(runner), data)
                for key in data:
                    sidecar.write_text(json.dumps({**data, key: 'wrong'}))
                    with self.assertRaises(ValueError):
                        runner_provenance(runner)
                sidecar.write_text(json.dumps(data))
                for path in (runner, root / 'build_runner.py', root / 'code-sockopt.patch'):
                    original = path.read_bytes()
                    path.write_bytes(original + b'changed')
                    with self.assertRaises(ValueError):
                        runner_provenance(runner)
                    path.write_bytes(original)


@unittest.skipUnless(os.environ.get('PACKETDRILL_PATCHED_RUNNER'),
                     'set PACKETDRILL_PATCHED_RUNNER and PACKETDRILL_CHECKOUT for C regression')
class CompiledSnapshotChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runner = Path(os.environ['PACKETDRILL_PATCHED_RUNNER']).resolve()
        checkout = Path(os.environ['PACKETDRILL_CHECKOUT']).resolve()
        check_checkout(checkout)
        runner_provenance(runner)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        source = directory / 'gtests/net/packetdrill/code.c'
        source.parent.mkdir(parents=True)
        source.write_bytes(subprocess.check_output(
            ['git', '-C', str(checkout), 'show', PIN['revision'] + ':gtests/net/packetdrill/code.c']))
        subprocess.run(['patch', '-p1', '-i', str(HERE / 'code-sockopt.patch')],
                       cwd=directory, check=True, capture_output=True)
        if source.read_bytes() != (runner.parent / 'code.c').read_bytes():
            raise AssertionError('built source does not match pinned source plus tracked patch')
        cls.binary = directory / 'snapshot-test'
        subprocess.run(['cc', '-g', '-Wall', '-Werror', '-I', str(runner.parent),
                        str(HERE / 'code_sockopt_test.c'), str(source),
                        '-o', str(cls.binary)], check=True)

    def execute(self, selection, fail_option, snippet, expected, message=None):
        result = subprocess.run([str(self.binary), selection, str(fail_option), snippet],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if message:
            self.assertIn(message, result.stderr)

    def test_selection_persists_and_auto_collects_original_set(self):
        # Linux UAPI: TCP_INFO=11, TCP_CC_INFO=26, SO_MEMINFO=55.
        self.execute('TCP_INFO', 55, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('TCP_INFO', 26, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('', 0, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('TCP_CC_INFO', 11, 'assert bbr_bw == 0', 0)
        self.execute('SO_MEMINFO', 11, 'assert SK_MEMINFO_RMEM_ALLOC == 0', 0)

    def test_requested_metric_failure_is_fatal(self):
        for selection, option in (('TCP_INFO', 11), ('TCP_CC_INFO', 26),
                                  ('SO_MEMINFO', 55), ('', 11), ('', 26), ('', 55)):
            self.execute(selection, option, 'assert True', 42, "can't get requested")

    def test_omitted_metrics_and_false_assertions_fail(self):
        for snippet, message in (('assert tcpi_snd_cwnd == 1', 'AssertionError'),
                                 ('assert SK_MEMINFO_RMEM_ALLOC == 0', 'NameError'),
                                 ('assert bbr_bw == 0', 'NameError')):
            self.execute('TCP_INFO', 0, snippet, 1, message)


if __name__ == '__main__':
    unittest.main()
