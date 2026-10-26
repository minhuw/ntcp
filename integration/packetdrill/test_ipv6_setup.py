import hashlib
import unittest
from run import PIN, profile_metadata, upstream_flags, variant_setup


class Ipv6SetupTests(unittest.TestCase):
    def test_family_parameters_preserve_body_and_common_policy(self):
        name = 'fast_retransmit/fr-4pkt.pkt'
        body = b'// IPv4 example 192.0.2.1\n0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3\n'
        flags = upstream_flags(name)
        resolved, audit, reasons = variant_setup(name, body, flags, 'ipv6')
        self.assertEqual(reasons, [])
        self.assertEqual(resolved, flags.replace('192.168.0.1', 'fd3d:0a0b:17d6::1'))
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(body).hexdigest())
        self.assertFalse(audit['body_rewritten'])
        self.assertEqual(audit['packetdrill_flags'], PIN['variants']['ipv6'])
        expected = profile_metadata(flags)
        actual = profile_metadata(resolved)
        self.assertEqual(set(actual), set(expected))
        # Only the local address may differ in resolved settings.
        differences = [key for key in actual if actual[key] != expected[key]]
        self.assertEqual(differences, ['capture_boundary'])

    def test_unaudited_ipv6_literal_options_stay_blocked(self):
        name = 'fast_retransmit/fr-4pkt.pkt'
        flags = upstream_flags(name)
        for body in (b'bind(3, 192.0.2.1, 16)',
                     b'setsockopt(3, IPPROTO_IP, IP_TOS, [0], 4)',
                     b'struct sockaddr_in peer;',
                     b'+.01 < icmp unreachable frag_needed mtu 800',
                     b'+.01 < icmp unreachable CODE'):
            self.assertTrue(variant_setup(name, body, flags, 'ipv6')[2])
        self.assertTrue(variant_setup(name, b'', flags + ',reno', 'ipv6')[2])
        self.assertTrue(variant_setup(name, b'', flags, 'unknown')[2])
        self.assertEqual(variant_setup(name, b'', flags, 'ipv4'), (flags, None, []))

    def test_freebind_option_alias_is_audited_without_rewriting_body(self):
        for function in ('setsockopt', 'getsockopt'):
            for level in ('SOL_IP', 'IPPROTO_IP'):
                name = 'splice/tcp_splice_loop_test.pkt'
                body = f'+0 {function}(3, {level}, IP_FREEBIND, [1], 4) = 0\n'.encode()
                flags = upstream_flags(name)
                _, audit, reasons = variant_setup(name, body, flags, 'ipv6')
                self.assertEqual(reasons, [])
                self.assertEqual(audit['shared_socket_option_aliases'], [level + '/IP_FREEBIND'])
                self.assertEqual(audit['generated_sha256'], hashlib.sha256(body).hexdigest())
                self.assertFalse(audit['body_rewritten'])
                for extra in (b'\n+0 setsockopt(3, SOL_IP, IP_TOS, [1], 4) = 0',
                              b'\n+0 bind(3, 192.0.2.1, 16) = 0',
                              b'\n+0 setsockopt(3, SOL_IPV6, IP_FREEBIND, [1], 4) = 0'):
                    self.assertTrue(variant_setup(name, body + extra, flags, 'ipv6')[2])
        for body in (b'IP_FREEBIND',
                     b'setsockopt(3, SOL_IP, UNKNOWN_OPTION, [1], 4)',
                     b'setsockopt(192.0.2.1, SOL_IP, IP_FREEBIND, [1], 4)'):
            self.assertTrue(variant_setup(name, body, flags, 'ipv6')[2])

    def test_mapped_variant_preserves_ipv4_addresses_options_and_original_bytes(self):
        name = 'splice/tcp_splice_loop_test.pkt'
        flags = upstream_flags(name)
        body = b'+0 setsockopt(3, SOL_IP, IP_TOS, [4], 1) = 0\n// 192.0.2.1\n'
        resolved, audit, reasons = variant_setup(name, body, flags, 'ipv4-mapped-v6')
        self.assertEqual(reasons, [])
        self.assertEqual(resolved, flags)
        self.assertEqual(audit['packetdrill_flags'], PIN['variants']['ipv4-mapped-v6'])
        self.assertEqual(audit['generated_sha256'], hashlib.sha256(body).hexdigest())
        self.assertFalse(audit['body_rewritten'])
        self.assertTrue(variant_setup(name, body, flags + ',reno', 'ipv4-mapped-v6')[2])
