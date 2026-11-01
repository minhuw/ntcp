# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
import os
import struct
import unittest
from unittest.mock import patch

from bridge import checksum
import icmp
import run


class NamespaceGuard(unittest.TestCase):
    def test_in_namespace_claim_without_inherited_proof_cannot_reach_setup(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(run, "setup") as setup:
            with self.assertRaises(KeyError):
                run.child(dict(family=4, role="client", policy="hmac", scenario="ordinary"))
            setup.assert_not_called()

    def test_real_current_namespace_fd_cannot_authorize_mutation_even_as_root(self):
        fd = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            with patch.dict(os.environ, {"T5_PARENT_NET_FD": str(fd)}, clear=True), patch.object(run, "setup") as setup:
                with self.assertRaisesRegex(AssertionError, "refuse mutation in parent net namespace"):
                    run.child(dict(family=6, role="server", policy="linux", scenario="warm"))
                setup.assert_not_called()
        finally:
            os.close(fd)

    def test_required_matrix_retains_both_roles_families_policies_and_controls(self):
        cases = run.matrix()
        self.assertEqual(len(cases), len({tuple(sorted(c.items())) for c in cases}))
        for family in (4, 6):
            for role, policies in (("client", ("hmac",)), ("server", ("hmac", "linux"))):
                for policy in policies:
                    required = {"ordinary", "warm", "deferred", "disabled", "client-disabled", "strip", "drop", "stale"}
                    required |= {"refused"} if role == "client" else {"expiry", "partial"}
                    if role == "server" and policy == "linux":
                        required.add("expiry-no-issuer")
                    actual = {c["scenario"] for c in cases if (c["family"], c["role"], c["policy"]) == (family, role, policy)}
                    self.assertTrue(required <= actual)


class IcmpScenario(unittest.TestCase):
    def test_icmp_case_without_inherited_proof_cannot_reach_setup(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(icmp, "setup") as setup:
            with self.assertRaises(KeyError):
                run.child(dict(kind="icmp", family=4, scenario="udp-quoted"))
            setup.assert_not_called()

    def test_cases_cover_both_families_both_quoted_transports_the_forged_control_fanout_and_staged_repair(self):
        self.assertEqual({(c["family"], c["scenario"]) for c in icmp.cases()},
                         {(f, s) for f in (4, 6) for s in ("udp-quoted", "tcp-quoted", "forged", "shared-fanout",
                                                            "tcp-staged", "tcp-burst")})
        self.assertFalse(any(c in run.matrix() for c in icmp.cases()))

    def original(self, family):
        payload = bytes(range(200)) * 8
        if family == 4:
            header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0x4000, 64, 17, 0,
                                           bytes([198, 18, 1, 2]), bytes([198, 18, 2, 2])))
            struct.pack_into("!H", header, 10, checksum(bytes(header)))
        else:
            header = bytearray(struct.pack("!IHBB16s16s", 6 << 28, 8 + len(payload), 17, 64,
                                           bytes(15) + b"\2", bytes(15) + b"\3"))
        return bytes(header) + struct.pack("!HHHH", 18080, 18090, 8 + len(payload), 0x1234) + payload

    def test_forged_variants_alter_a_correlated_field_with_well_formed_inner_headers(self):
        for family in (4, 6):
            original = self.original(family)
            exact = icmp.mutate(family, original, "exact")
            self.assertTrue(icmp.quotes(exact, original))
            self.assertEqual(len(exact), 548 if family == 4 else 1232)
            for name in ("udp-checksum", "udp-port", "ip-length", "destination"):
                forged = icmp.mutate(family, original, name)
                self.assertEqual(len(forged), len(exact))
                self.assertFalse(icmp.quotes(forged, original), (family, name))
                if family == 4:
                    self.assertEqual(checksum(forged[:20]), 0, name)
            # Router-mutated TTL/hop limit alone does not break the match.
            routed = bytearray(exact)
            routed[8 if family == 4 else 7] -= 1
            self.assertTrue(icmp.quotes(bytes(routed), original))

    def test_decoder_reports_ptb_mtu_and_quote(self):
        original = self.original(4)
        quote = icmp.mutate(4, original, "exact")
        body = bytearray(struct.pack("!BBHHH", 3, 4, 0, 0, 1280) + quote)
        struct.pack_into("!H", body, 2, checksum(bytes(body)))
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 1, 0,
                                       bytes([198, 18, 1, 1]), bytes([198, 18, 1, 2])))
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        event = icmp.parse(bytes(header + body))
        self.assertTrue(event["ptb"] and event["checksum_valid"] and event["ip_checksum_valid"])
        self.assertEqual((event["mtu"], event["source"], event["quote"]), (1280, "198.18.1.1", quote))

    def tcp(self, options):
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(options), 0, 0x4000, 64, 6, 0,
                             bytes([198, 18, 2, 2]), bytes([198, 18, 1, 2]))
        tcp = bytearray(struct.pack("!HHIIBBHHH", 18082, 18081, 7, 9, (20 + len(options)) // 4 << 4, 0x10,
                                    1000, 0, 0) + options)
        pseudo = header[12:20] + bytes([0, 6]) + struct.pack("!H", len(tcp))
        struct.pack_into("!H", tcp, 16, checksum(pseudo + bytes(tcp)))
        return icmp.parse(header + bytes(tcp))

    def test_decoder_reports_sack_blocks_after_other_options(self):
        # NOP, NOP, timestamps, NOP, NOP, SACK with two blocks.
        options = (b"\1\1" + struct.pack("!BBII", 8, 10, 5, 6) + b"\1\1"
                   + struct.pack("!BBIIII", 5, 18, 100, 200, 0xfffffff0, 16))
        event = self.tcp(options)
        self.assertTrue(event["checksum_valid"])
        self.assertEqual(event["sack"], [(100, 200), (0xfffffff0, 16)])
        self.assertIsNone(self.tcp(b"")["sack"])
        # A truncated or misaligned SACK option yields no blocks.
        self.assertIsNone(self.tcp(struct.pack("!BBI", 5, 10, 1) + b"\0\0")["sack"])
        self.assertIsNone(self.tcp(struct.pack("!BBII", 5, 9, 1, 2) + b"\0\0\0")["sack"])
