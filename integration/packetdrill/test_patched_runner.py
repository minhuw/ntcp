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
        with tempfile.TemporaryFile() as archive:
            subprocess.run(['git', '-C', str(checkout), 'archive', PIN['revision']],
                           stdout=archive, check=True)
            archive.seek(0)
            subprocess.run(['tar', '-xf', '-', '-C', str(directory)],
                           stdin=archive, check=True)
        source = directory / 'gtests/net/packetdrill/code.c'
        subprocess.run(['patch', '-p1', '-i', str(HERE / 'code-sockopt.patch')],
                       cwd=directory, check=True, capture_output=True)
        for name in ('code.c', 'code.h', 'packet.h', 'packet.c', 'icmp_packet.c',
                     'parser.y', 'socket.h', 'run_packet.c', 'so_testing.c', 'run_command.c'):
            if (source.parent / name).read_bytes() != (runner.parent / name).read_bytes():
                raise AssertionError(f'built {name} differs from pinned source plus patch')
        cls.binary = directory / 'snapshot-test'
        subprocess.run(['cc', '-g', '-Wall', '-Werror', '-I', str(runner.parent),
                        str(HERE / 'code_sockopt_test.c'), str(source),
                        '-o', str(cls.binary)], check=True)
        cls.icmp_binary = directory / 'icmp-test'
        objects = sorted(str(path) for path in runner.parent.glob('*.o')
                         if path.name not in {'packetdrill.o', 'run_packet.o', 'so_testing.o'}
                         and not path.name.endswith('_test.o'))
        subprocess.run(['cc', '-g', '-Wall', '-Werror', '-I', str(source.parent),
                        str(HERE / 'icmp_runner_test.c'), *objects,
                        '-lpthread', '-lrt', '-ldl', '-o', str(cls.icmp_binary)], check=True)

    def test_icmp_quote_mapping_and_callback_errors(self):
        result = subprocess.run([str(self.icmp_binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = dict(line.split(' ', 1) for line in result.stdout.splitlines())
        def checksum(data):
            words = [int.from_bytes(data[i:i + 2], 'big')
                     for i in range(0, len(data), 2)]
            total = sum(words)
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            return ~total & 65535
        for name, total, sequence in (
                ('omitted', 1060, 0x12345670), ('explicit', 1060, 0x12345670),
                ('override', 1040, 0x12345679), ('override_match', 1060, 0x12345679),
                ('zero', 40, 0x12345670),
                ('different', 1039, 0x12345670), ('port_miss', 1040, 0x12345670),
                ('ip_miss', 1040, 0x12345670), ('sequence_miss', 40, 0x12345670),
                ('no_template', 1040, 0x12345670)):
            with self.subTest(name=name):
                data = bytes.fromhex(rows[name])
                self.assertEqual(len(data), 56)
                self.assertEqual(int.from_bytes(data[30:32], 'big'), total)
                self.assertEqual(int.from_bytes(data[52:56], 'big'), sequence)
                self.assertEqual(data[40:48], bytes.fromhex('c0a80001c0000201'))
                self.assertEqual(data[48:52], bytes.fromhex('9c411f90'))
                for part in (data[:20], data[20:], data[28:48]):
                    self.assertEqual(checksum(part), 0)
        for name in ('bad_checksum', 'zero_checksum', 'bad_length', 'raw'):
            data = bytes.fromhex(rows[name])
            self.assertEqual(checksum(data[:20]), 0)
            self.assertEqual(checksum(data[20:]), 0)
            self.assertNotEqual(checksum(data[28:48]), 0)
        self.assertEqual(bytes.fromhex(rows['bad_checksum'])[38:40], b'\xbe\xef')
        self.assertEqual(bytes.fromhex(rows['bad_length'])[30:32], b'\x00\x11')
        self.assertIn('errno 22: ', rows['error'])
        data = bytes.fromhex(rows['ipv6'])
        self.assertEqual(len(data), 96)
        pseudoheader = data[8:40] + (56).to_bytes(4, 'big') + b'\x00\x00\x00\x3a'
        self.assertEqual(checksum(pseudoheader + data[40:]), 0)

    def execute(self, selection, fail_option, snippet, expected, message=None, env=None):
        result = subprocess.run([str(self.binary), selection, str(fail_option), snippet],
                                capture_output=True, text=True,
                                env={**os.environ, **(env or {})}, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if message:
            self.assertIn(message, result.stderr)
        return result

    def test_selection_persists_and_auto_collects_original_set(self):
        # Linux UAPI: TCP_INFO=11, TCP_CC_INFO=26, SO_MEMINFO=55.
        self.execute('TCP_INFO', 55, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('TCP_INFO', 26, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('', 0, 'assert tcpi_snd_cwnd == 0', 0)
        self.execute('TCP_CC_INFO', 11, 'assert bbr_bw == 0', 0)
        self.execute('SO_MEMINFO', 11, 'assert SK_MEMINFO_RMEM_ALLOC == 0', 0)

    def test_prefix_requests_each_events_fields_without_optional_delivery(self):
        result = self.execute(
            'TCP_INFO_PREFIX', 0,
            'assert (tcpi_options & TCPI_OPT_SYN_DATA) == 0, tcpi_options', 0,
            env={'TCP_INFO_LIMIT': '192', 'TCP_INFO_TRACE': '1',
                 'TCP_INFO_SECOND_SNIPPET': 'assert tcpi_sndbuf_limited == 0'})
        self.assertEqual(result.stderr.splitlines(),
                         ['requested TCP_INFO 6', 'requested TCP_INFO 192'])
        # The prefix shrinks again for a later options-only event.
        result = self.execute('TCP_INFO_PREFIX', 0, 'assert tcpi_delivered == 0', 0,
                              env={'TCP_INFO_TRACE': '1',
                                   'TCP_INFO_SECOND_SNIPPET':
                                   'assert (tcpi_options & TCPI_OPT_SYN_DATA) == 0'})
        self.assertEqual(result.stderr.splitlines(),
                         ['requested TCP_INFO 196', 'requested TCP_INFO 6'])

    def test_prefix_field_layout_matches_audited_fields(self):
        ends = {'tcpi_ca_state': 2, 'tcpi_probes': 4, 'tcpi_backoff': 5, 'tcpi_options': 6, 'tcpi_snd_wscale': 7,
                'tcpi_rcv_wscale': 7, 'tcpi_unacked': 28, 'tcpi_sacked': 32,
                'tcpi_lost': 36, 'tcpi_retrans': 40, 'tcpi_last_data_recv': 56,
                'tcpi_rtt': 72, 'tcpi_snd_ssthresh': 80, 'tcpi_snd_cwnd': 84,
                'tcpi_reordering': 92, 'tcpi_notsent_bytes': 148,
                'tcpi_busy_time': 176, 'tcpi_rwnd_limited': 184,
                'tcpi_sndbuf_limited': 192, 'tcpi_delivered': 196}
        from run import TCP_INFO_FIELDS
        self.assertEqual(set(ends), TCP_INFO_FIELDS)
        for field, end in ends.items():
            with self.subTest(field=field):
                condition = ('(tcpi_options & TCPI_OPT_SYN_DATA)'
                             if field == 'tcpi_options' else field)
                result = self.execute('TCP_INFO_PREFIX', 0,
                                      f'assert {condition} == 0, {field}', 0,
                                      env={'TCP_INFO_TRACE': '1'})
                self.assertEqual(result.stderr.splitlines(),
                                 [f'requested TCP_INFO {end}'] * 2)

    def test_prefix_refuses_unavailable_short_unknown_and_false_values(self):
        for snippet, env, message in (
                ('assert tcpi_delivered == 0', {'TCP_INFO_LIMIT': '192'},
                 "can't get requested"),
                ('assert tcpi_unacked == 0', {'TCP_INFO_RETURN_LEN': '27'},
                 "can't get requested"),
                ('assert tcpi_unacked == 0', {'TCP_INFO_RETURN_LEN': '29'},
                 "can't get requested"),
                ('assert tcpi_pacing_rate == 0', {},
                 'unsupported TCP_INFO prefix field'),
                ('assert tcpi_lost_unknown == 0', {},
                 'unsupported TCP_INFO prefix field')):
            with self.subTest(snippet=snippet, env=env):
                self.execute('TCP_INFO_PREFIX', 0, snippet, 42, message, env)
        self.execute('TCP_INFO_PREFIX', 11, 'assert tcpi_lost == 0', 42,
                     "can't get requested")
        self.execute('TCP_INFO_PREFIX', 0, 'assert tcpi_lost == 1', 1,
                     'AssertionError')
        self.execute('TCP_INFO_PREFIX', 0, 'assert True', 0)

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
