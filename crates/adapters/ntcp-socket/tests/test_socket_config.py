"""Fixture checks that need neither a socket adapter build nor namespaces."""
import importlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from socket_config import config_env


class ConfigFixtureTest(unittest.TestCase):
    def test_pacing_variants(self):
        import pacing

        invalid_files, variants = [], []

        def run(args, **kwargs):
            if '--invalid' in args:
                env = kwargs['env']
                self.assertEqual(env['LD_PRELOAD'], str(pacing.LIBRARY))
                path = Path(env['NTCP_SOCKET_CONFIG'])
                invalid_files.append(path)
                self.assertIn('interface=ntcp0\n', path.read_text())
                self.assertIn('address=10.73.0.2\n', path.read_text())
                self.assertTrue(any(f'pacing={value}\n' in path.read_text()
                                    for value in ('', 'TRUE', '01', '2')))
            elif '--isolated' in args:
                self.assertNotIn('NTCP_SOCKET_CONFIG', kwargs['env'])
                variants.append(tuple(args[-2:]))

        with patch.object(sys, 'argv', ['pacing.py']), \
                patch.object(pacing.subprocess, 'run', side_effect=run), \
                patch('builtins.print'):
            pacing.main()
        self.assertEqual(len(invalid_files), 4)
        self.assertTrue(all(not path.exists() for path in invalid_files))
        self.assertEqual(variants, [(backend, value) for backend in ('tun', 'af-packet')
                                    for value in ('unset', 'false', 'true')])

    def test_private_files_and_native_environment(self):
        with tempfile.TemporaryDirectory(prefix='ntcp-config-test-') as directory:
            host = Path(directory) / 'host.conf'
            host.write_text('do not overwrite\n')
            with patch.dict(os.environ, {'NTCP_SOCKET_CONFIG': str(host)}):
                for name, cleaner in (
                    ('redis', 'clean_env'), ('timestamping', 'environment'),
                    ('linux_boundary', 'clean_env'), ('descriptors', 'clean_env'),
                    ('socket_features', 'clean_env'), ('abi_safety', 'clean_env'),
                    ('stream_controls', 'clean_env'),
                ):
                    env = getattr(importlib.import_module(name), cleaner)()
                    self.assertNotIn('NTCP_SOCKET_CONFIG', env)
                    self.assertNotIn('LD_PRELOAD', env)
                paths = []
                for pacing in ('false', 'true', 'invalid'):
                    settings = dict(backend='af-packet', interface='engine0',
                                    address='10.73.0.2', next_hop_mac='02:00:00:00:00:01',
                                    pacing=pacing)
                    config = config_env(directory, **settings)
                    self.assertEqual(list(config), ['NTCP_SOCKET_CONFIG'])
                    path = Path(config['NTCP_SOCKET_CONFIG'])
                    paths.append(path)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    expected = ''.join(f'{key}={value}\n' for key, value in settings.items())
                    # The closed writer leaves its file readable by a fresh child.
                    result = subprocess.check_output([
                        sys.executable, '-c',
                        'import os; print(open(os.environ["NTCP_SOCKET_CONFIG"]).read(), end="")',
                    ], env=env | config, text=True)
                    self.assertEqual(result, expected)
                self.assertEqual(len(set(paths)), 3)
                self.assertEqual(host.read_text(), 'do not overwrite\n')
                self.assertEqual(os.environ['NTCP_SOCKET_CONFIG'], str(host))
        self.assertTrue(all(not path.exists() for path in paths))


if __name__ == '__main__':
    unittest.main()
