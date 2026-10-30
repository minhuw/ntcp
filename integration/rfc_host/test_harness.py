# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
import os
import unittest
from unittest.mock import patch

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
