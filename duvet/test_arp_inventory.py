from collections import Counter
import json
import unittest

import check_annotation_inventory as audit
from historical_rfc import early_memo, identity, legacy_layout, prepare
from rfc_scopes import PREFIX, ROOT, check_registration


TARGET = PREFIX + "826#name-abstract"
# The selected clause set is a review contract: 13 clauses, of which 2 are
# Linux-default departures.
CLAUSES = (13, 0, 2, "cba1a185a1ffbb626712f462c3c09f112e8ca1ee1c073044a2ca0e3f8d82558d")


def entries(name):
    return audit.toml_entries(ROOT / f"duvet/rfc826-{name}.toml")


def clauses_hash():
    keys = sorted(audit.clause_key(row) for kind, row in entries("additions"))
    return audit.digest(json.dumps(keys, separators=(",", ":")).encode())


class ArpInventory(unittest.TestCase):
    def test_registration_is_a_manual_selection(self):
        scope = check_registration()[826]
        self.assertEqual(scope["scope_kind"], "selected-requirements")
        self.assertEqual(scope["extraction"], "manual")
        self.assertEqual(scope["document_status"], "Internet Standard")
        self.assertEqual(scope["inventory"], "duvet/rfc826-additions.toml")
        self.assertTrue(scope["scope"].startswith("SELECTED:"))
        self.assertIn("put on the wire by ntcp-host's neighbor calls and ntcp-native", scope["scope"])
        self.assertIn("ntcp-socket's IPv4 ports still use static neighbours", scope["scope"])

    def test_exact_selected_clauses_and_dispositions(self):
        total, todos, exceptions, digest = CLAUSES
        specs = entries("additions")
        dispositions = entries("todos")
        self.assertEqual(len(specs), total)
        self.assertTrue(all(kind == "SPEC" and row["target"] == TARGET for kind, row in specs))
        self.assertEqual(Counter(kind for kind, _ in dispositions),
                         +Counter(TODO=todos, EXCEPTION=exceptions))
        spec_keys = {audit.clause_key(row) for _, row in specs}
        self.assertTrue({audit.clause_key(row) for _, row in dispositions} <= spec_keys)
        self.assertEqual(clauses_hash(), digest)

    def test_every_open_or_covered_clause_has_source_and_test_copies(self):
        reasons = {audit.clause_key(row): row["reason"] for kind, row in entries("todos") if kind == "TODO"}
        excepted = {audit.clause_key(row) for kind, row in entries("todos") if kind == "EXCEPTION"}
        kinds = {}
        for path in (ROOT / "crates/stacks/ntcp-arp").rglob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                key = audit.clause_key(annotation)
                if annotation["target"] != TARGET:
                    continue
                # A partial copy keeps the canonical TODO reason; a closed one none.
                self.assertEqual(annotation["reason"], reasons.get(key, ""), str(path))
                kinds.setdefault(key, set()).add(annotation["kind"])
                if annotation["kind"] == "TEST":
                    self.assertIn("assert", annotation["attached"])
        expected = {audit.clause_key(row) for _, row in entries("additions")} - excepted
        self.assertEqual(set(kinds), expected)
        self.assertTrue(all(found == {"CITATION", "TEST"} for found in kinds.values()))

    def test_wire_clauses_are_cited_and_asserted_by_the_native_port(self):
        # Putting replies, requests and probes on the wire is ntcp-native's:
        # each such clause has a citation in its driver and an asserting test.
        wire = {"Send the packet to the (new) target hardware address on the same hardware",
                "this packet to be broadcast to all stations on the Ethernet cable",
                "It first sends (with a small number of retransmissions if needed)"}
        clauses = {audit.clause_key(row) for _, row in entries("additions")
                   if any(audit.norm(text) in audit.norm(row["quote"]) for text in wire)}
        self.assertEqual(len(clauses), 3)
        native = ROOT / "crates/adapters/ntcp-native"
        for directory, kind in (("src", "CITATION"), ("tests", "TEST")):
            found = set()
            for path in (native / directory).rglob("*.rs"):
                for annotation in audit.source_annotations(path.read_text()):
                    if annotation["target"] == TARGET and annotation["kind"] == kind:
                        self.assertEqual(annotation["reason"], "")
                        if kind == "TEST":
                            self.assertIn("assert", annotation["attached"])
                        found.add(audit.clause_key(annotation))
            self.assertEqual(found, clauses, directory)


class EarlyMemo(unittest.TestCase):
    def memo(self):
        return (b"Network Working Group                   A. Author \n"
                b"Request For Comments:  826                  (X@Y)\n"
                b"                                    November 1982\n\n"
                b"\t\t\t    Abstract\n\nFirst body paragraph.\n\f\n"
                b"Packet Reception:\n-----------------\n\n"
                b"100 useless entries in a table are substantive.\n")

    def test_identity_layout_and_named_heading(self):
        raw = self.memo()
        self.assertTrue(identity(raw, 826))
        self.assertFalse(identity(raw, 791))
        self.assertTrue(early_memo(raw) and legacy_layout(raw))
        self.assertFalse(early_memo(raw.replace(b"November 1982\n", b"November 1982\nCategory: Standards Track\n")))
        self.assertFalse(early_memo(raw.replace(b"Request For", b"Request for")))
        prepared = prepare(raw).decode()
        self.assertIn("\nAbstract\n", prepared)
        self.assertIn("100 useless entries in a table are substantive.", prepared)
        self.assertEqual(prepare(prepared.encode()), prepared.encode())
        # Body lines beginning with numbers are not sections; the body stays
        # under the named heading Duvet recognizes.
        sections = audit.official_sections(raw)
        self.assertEqual(set(sections), {"preamble", "name-abstract"})
        self.assertIn("Packet Reception: ----------------- 100 useless entries", sections["name-abstract"])
        # An indented word that is not set off by blank lines is body text.
        inline = raw.replace(b"\n\nFirst body", b"\nFirst body")
        self.assertNotIn("\nAbstract\n", prepare(inline).decode())


if __name__ == "__main__":
    unittest.main()
