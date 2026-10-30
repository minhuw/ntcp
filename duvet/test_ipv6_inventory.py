import copy
from collections import Counter
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_annotation_inventory as audit
from rfc_scopes import PREFIX, ROOT, check_registration
from test_annotation_inventory import report_fixture, report_scopes


# Protect every final member independently of the mutable metadata and original
# registration floor. These scoped additions cannot silently replace an old RFC.
FINAL_RFCS = {9293, 2018, 6675, 8985, 9937, 6298, 5681, 6582, 6928, 7323,
              2883, 3168, 5961, 3042, 9406, 9438, 1191, 8201, 4821, 5927,
              7413, 6191, 6429, 791, 1122, 3542, 6864, 8200}
CONTRACT = {
    8200: (9, 9, 0, "Standards Track",
           "371ae3f133d562db5d6385e6def4ca9914c4f831be228ea7779fd28799c2f490",
           "c042188ee7e4e094dae253dc1d3ae8bcf239720d40c070ca0251986c2eba4d34"),
    3542: (7, 7, 0, "Informational",
           "c2b3296882ca580c21a96b3b93dd0a2972809db0ebdf9ec7f55a13602e729ce6",
           "8358cf0828d97e106629cfdb5fec64d8c52e44417ee3bf82695e1308ecfe0cef"),
}


def ledger(n):
    return json.loads((ROOT / f"duvet/rfc{n}-inventory.json").read_text())


class Ipv6Inventory(unittest.TestCase):
    def test_final_registration_and_exact_scoped_clause_contract(self):
        scopes = check_registration()
        self.assertEqual(len(scopes), 28)
        self.assertEqual(set(scopes), FINAL_RFCS)
        for n, (total, covered, todos, status, text_hash, clauses_hash) in CONTRACT.items():
            with self.subTest(rfc=n):
                scope, document = scopes[n], ledger(n)
                self.assertEqual(scope["scope_kind"], "scoped-operative")
                self.assertEqual(scope["extraction"], "manual")
                self.assertEqual(scope["document_status"], status)
                self.assertEqual(scope["inventory"], f"duvet/rfc{n}-inventory.json")
                for field in ("scope", "scope_kind", "document_status", "extraction"):
                    self.assertEqual(document[field], scope[field])
                self.assertTrue(scope["scope"].startswith("SCOPED:"))
                self.assertIn("No full-document or full", scope["scope"])
                self.assertEqual(document["text_sha256"], text_hash)
                rows = document["paragraphs"]
                self.assertEqual(len(rows), len({r["id"] for r in rows}))
                operative = [r for r in rows if r["status"] != "context"]
                self.assertEqual(len(operative), total)
                self.assertEqual(Counter(r["status"] for r in operative),
                                 Counter(covered=covered, TODO=todos))
                keys = sorted((r["section"], audit.norm(r["quote"])) for r in operative)
                self.assertEqual(audit.digest(json.dumps(keys, separators=(",", ":")).encode()), clauses_hash)
                specs = audit.toml_entries(ROOT / f"duvet/rfc{n}-additions.toml")
                dispositions = audit.toml_entries(ROOT / f"duvet/rfc{n}-todos.toml")
                self.assertEqual(Counter(audit.clause_key(r) for r in operative),
                                 Counter(audit.clause_key(r) for kind, r in specs if kind == "SPEC"))
                self.assertEqual(Counter((r["status"].upper(), audit.clause_key(r), r["reason"])
                                         for r in operative if r["status"] in ("TODO", "exception")),
                                 Counter((kind, audit.clause_key(r), r["reason"]) for kind, r in dispositions))

    def test_whole_clause_annotations_bind_actual_source_and_assertions(self):
        for n in CONTRACT:
            for row in ledger(n)["paragraphs"]:
                if row["status"] == "context":
                    self.assertFalse(row.get("evidence"))
                    continue
                self.assertEqual(len(row["evidence"]), 2, row["id"])
                for index, evidence in enumerate(row["evidence"]):
                    path, anchor = evidence.split("::", 1)
                    matches = [a for a in audit.source_annotations((ROOT / path).read_text())
                               if audit.clause_key(a) == audit.clause_key(row) and anchor in a["attached"]]
                    self.assertTrue(matches, (row["id"], evidence))
                    self.assertTrue(any(a["kind"] == ("CITATION" if index == 0 else "TEST") for a in matches))
                    if row["status"] == "TODO":
                        self.assertTrue(any(a["reason"] == row["reason"] for a in matches))
                    if index == 1:
                        self.assertTrue(any("assert" in a["attached"] for a in matches))

    def test_selected_gaps_and_unselected_capabilities_remain_distinct(self):
        ip = {r["id"]: r for r in ledger(8200)["paragraphs"]}
        for name in ("8200-hop", "8200-length", "8200-no-next"):
            self.assertEqual(ip[name]["status"], "covered")
            self.assertTrue(ip[name]["evidence"])
        self.assertIn("A node that is the destination", ip["8200-hop"]["quote"])
        self.assertIn("it should process the packet normally", ip["8200-hop"]["quote"])
        self.assertIn("including zero", ip["8200-length"]["reason"])
        self.assertIn("any extension headers", ip["8200-length"]["quote"])
        self.assertIn("those octets must be ignored", ip["8200-no-next"]["quote"])
        self.assertEqual(ip["8200-extension-boundary"]["status"], "context")
        self.assertIn("if a Routing header is present", ip["8200-destination"]["quote"])
        socket = {r["id"]: r for r in ledger(3542)["paragraphs"]}
        default, default_parent = socket["3542-default"], socket["3542-default-parent"]
        self.assertEqual(default["parent"], default_parent["id"])
        self.assertEqual(default_parent["status"], "context")
        self.assertIn(audit.norm(default["quote"]), audit.norm(default_parent["quote"]))
        self.assertIn("ancillary data", default_parent["quote"])
        parent, outgoing = socket["3542-ecn-parent"], socket["3542-ecn"]
        self.assertEqual(parent["status"], "context")
        self.assertEqual(outgoing["status"], "covered")
        self.assertEqual(outgoing["parent"], parent["id"])
        self.assertIn(audit.norm(outgoing["quote"]), audit.norm(parent["quote"]))
        self.assertIn("On the incoming traffic", parent["quote"])
        self.assertNotIn("On the incoming traffic", outgoing["quote"])
        self.assertIn("should override the user-specified value", outgoing["quote"])
        sticky = socket["3542-get-sticky"]
        self.assertEqual(sticky["status"], "covered")
        self.assertEqual(sticky["quote"], "Issuing getsockopt() for the above options will return the sticky option value i.e., the value set with setsockopt().")
        self.assertIn("exact accepted sticky integer including both user ECN bits", sticky["reason"])
        self.assertIn("six DSCP bits", outgoing["reason"])
        self.assertIn("runtime.rs::(IPPROTO_IP, IP_TOS) | (IPPROTO_IPV6, IPV6_TCLASS) => {", outgoing["evidence"][0])
        # Every complete source/test quotation must shed the obsolete TODO reason,
        # even when the ledger does not select that particular copy as evidence.
        for path in (ROOT / "crates/adapters/ntcp-socket/src").glob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                if audit.clause_key(annotation) == audit.clause_key(sticky):
                    self.assertFalse(annotation["reason"], path)
        for name in ("3542-range", "3542-reset", "3542-live", "3542-default", "3542-get-default"):
            self.assertEqual(socket[name]["status"], "covered")
        self.assertIn("ancillary sendmsg overrides", ledger(3542)["scope"])
        self.assertIn("jumbograms", ledger(8200)["scope"])

    def temporary_root(self):
        (ROOT / "workbench").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / "workbench")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "duvet").mkdir()
        return root

    def test_new_members_keep_config_inventory_and_schema_guards(self):
        root = self.temporary_root()
        for path in (ROOT / "duvet").iterdir():
            if path.is_file():
                shutil.copyfile(path, root / "duvet" / path.name)
        for n in CONTRACT:
            inventory = root / f"duvet/rfc{n}-inventory.json"
            original = inventory.read_text()
            inventory.unlink()
            with self.subTest(rfc=n), self.assertRaisesRegex(ValueError, "missing or invalid inventory"):
                check_registration(root)
            inventory.write_text(original)
            config = root / "duvet/duvet.toml"
            original_config = config.read_text()
            config.write_text(original_config.replace(f'rfc{n}"', 'rfc99999"'))
            with self.assertRaisesRegex(ValueError, "membership mismatch"):
                check_registration(root)
            config.write_text(original_config)
            metadata = root / "duvet/rfc-scopes.toml"
            original_metadata = metadata.read_text()
            metadata.write_text(original_metadata.replace(
                f'id = {n}\ndocument_status = "{CONTRACT[n][3]}"',
                f'id = {n}\ndocument_status = "Conformant"'))
            with self.assertRaises(ValueError):
                check_registration(root)
            metadata.write_text(original_metadata)
        self.assertEqual(set(check_registration(root)), FINAL_RFCS)

    def test_new_rfc_report_provenance_cannot_drop_full_section_or_fuzz_evidence(self):
        root = self.temporary_root()
        report, entries, texts = report_fixture(root)
        scopes = report_scopes()
        source = root / "source.rs"
        original = source.read_text()
        for n in CONTRACT:
            key = PREFIX + str(n)
            # Full-section provenance checks must retain unannotated context too.
            texts[n] += b"\nUnselected context must remain in the report.\n"
            report["specifications"][key]["sections"][0]["lines"].append(
                "Unselected context must remain in the report.")
            audit.validate_report(report, scopes, entries, texts, root=root)
            broken = copy.deepcopy(report)
            broken["specifications"][key]["sections"][0]["lines"].pop()
            with self.subTest(rfc=n), self.assertRaises(ValueError):
                audit.validate_report(broken, scopes, entries, texts, root=root)
            for kind in ("CITATION", "TEST"):
                annotation = next(a for a in report["annotations"] if a["target_path"] == key and a["type"] == kind)
                lines = original.splitlines()
                lines[annotation["line"] + 1] = "//# Required behavioX."
                source.write_text("\n".join(lines) + "\n")
                with self.subTest(rfc=n, kind=kind), self.assertRaises(ValueError):
                    audit.validate_report(report, scopes, entries, texts, root=root)
                source.write_text(original)
            changed = [e for e in entries if not (e[1] == "SPEC" and e[2]["target"] == key + "#section-1")]
            with self.assertRaises(ValueError):
                audit.validate_report(report, scopes, changed, texts, root=root)


if __name__ == "__main__":
    unittest.main()
