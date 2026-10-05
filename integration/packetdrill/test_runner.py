import signal
import sys
import tempfile
import unittest
from pathlib import Path

from run import invoke, outcome, preflight, variants


class RunnerChecks(unittest.TestCase):
    def test_preflight_does_not_ignore_kernel_setup_or_change_packet_expectations(self):
        self.assertEqual(preflight('0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3'), [])
        self.assertTrue(preflight('`../common/defaults.sh`'))
        self.assertTrue(preflight('0 %{ assert tcpi_snd_cwnd == 10 }%'))
        self.assertTrue(preflight('--init_scripts=/tmp/script'))
        self.assertTrue(preflight('--so_filename=other.so'))
        self.assertTrue(preflight('--wire_server'))
        self.assertTrue(preflight('0 > S. 0:0(0) ack 1 <mss 1460,sackOK>'))
        self.assertEqual(preflight('0 < S 0:0(0) win 1000 <sackOK>'), [])
        self.assertEqual(preflight('--tolerance_usecs=10000\n0 > . 1:1(0) ack 1'), [])

    def test_upstream_variants_preserve_wrapper_parameters(self):
        both = dict(variants(Path('basic.pkt'), True))
        self.assertEqual(set(both), {'ipv4', 'ipv6', 'ipv4-mapped-v6'})
        self.assertIn('TFO_COOKIE=3021b9d889017eeb', both['ipv4'])
        self.assertEqual([name for name, _ in variants(Path('basic-v6.pkt'), True)],
                         ['ipv6'])
        self.assertEqual([name for name, _ in variants(Path('basic-v4.pkt'), True)],
                         ['ipv4', 'ipv4-mapped-v6'])
        self.assertEqual(variants(Path('basic.pkt'), False), [('native-ipv4', [])])

    def test_nonpasses_are_not_silently_promoted(self):
        self.assertEqual(outcome(0, False, ''), 'passed')
        self.assertEqual(outcome(1, False, 'packet mismatch'), 'failed')
        self.assertEqual(outcome(0, False, 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO'),
                         'unsupported')
        self.assertEqual(outcome(-signal.SIGSEGV, False, ''), 'failed')
        self.assertEqual(outcome(-signal.SIGSEGV, False,
                                 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO'), 'failed')
        self.assertEqual(outcome(0, False,
                                 'NTCP_PACKETDRILL_FAILURE: callback panicked'), 'failed')
        self.assertEqual(outcome(1, False,
                                 'NTCP_PACKETDRILL_UNSUPPORTED: TCP_INFO\n'
                                 'NTCP_PACKETDRILL_FAILURE: owner panicked'), 'failed')
        self.assertEqual(outcome(None, False, 'not found'), 'environment_error')
        self.assertEqual(outcome(1, False, 'unshare: unshare failed'), 'environment_error')
        self.assertEqual(outcome(-9, True, ''), 'timeout')

    def test_process_exit_timeout_and_missing_executable(self):
        with tempfile.TemporaryDirectory() as cwd:
            code, expired, log = invoke([sys.executable, '-c', 'print("ok")'], cwd, 5)
            self.assertEqual((code, expired, log.strip()), (0, False, 'ok'))
            code, expired, _ = invoke([sys.executable, '-c', 'import time; time.sleep(10)'],
                                      cwd, 0.1)
            self.assertTrue(expired)
            self.assertEqual(code, -signal.SIGKILL)
            code, expired, _ = invoke([str(Path(cwd) / 'missing')], cwd, 1)
            self.assertIsNone(code)
            self.assertFalse(expired)


if __name__ == '__main__':
    unittest.main()
