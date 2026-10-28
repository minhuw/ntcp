import copy
from collections import Counter
import io
import json
from pathlib import Path
import tempfile
import unittest

import check_annotation_inventory as audit
from historical_rfc import identity, prepare
from rfc_scopes import ORIGINAL_RFCS, PREFIX, ROOT, check_registration
from test_annotation_inventory import report_fixture, report_scopes


# Exact selected clauses are a review contract: synchronously narrowing a ledger,
# additions and source/test quotes cannot silently shrink the audited capability.
CONTRACT = {
    791: (19, 17, 2, "6cfb387fcecfc1b72f2f69343c5b6951b5d263d708162e2b5c66ab8f394f6265",
          "823132a1638cd0fc39160740de5ecd34c696a65f03fbb863122ffffaaf961e8d"),
    1122: (16, 13, 3, "9f526e6bebc868324fedb90aebbcf6e5b15c53fd373ca5d5ce1c2cdcd264e04f",
           "140d6afa98dde87d39941c1863076d8fa41864673c357689e1d81f343880960d"),
    6864: (4, 4, 0, "e00ff443857166e5b26deecfdc77a0a1c5ff17fc87a6a8c50b020ce7f4d516d9",
           "586eabdc924e7104e828cf54cbeddfcdd85f11c2e2ac5e1cc48e5379eba9e772"),
}


def ledger(n):
    return json.loads((ROOT / f"duvet/rfc{n}-inventory.json").read_text())


class Ipv4Inventory(unittest.TestCase):
    def test_registration_scoped_status_and_exact_clause_contract(self):
        scopes = check_registration()
        self.assertEqual(set(scopes), set(ORIGINAL_RFCS) | {6191, 6429, 791, 1122, 6864, 3542, 8200})
        for n, (total, covered, todos, text_hash, clauses_hash) in CONTRACT.items():
            with self.subTest(rfc=n):
                document, scope = ledger(n), scopes[n]
                self.assertEqual(scope["scope_kind"], "scoped-operative")
                self.assertEqual(scope["extraction"], "manual")
                self.assertEqual(scope["inventory"], f"duvet/rfc{n}-inventory.json")
                self.assertEqual(scope["document_status"], "Standards Track" if n == 6864 else "Internet Standard")
                for field in ("scope", "scope_kind", "document_status"):
                    self.assertEqual(document[field], scope[field])
                self.assertTrue(scope["scope"].startswith("SCOPED:"))
                self.assertIn("No full-document or full IPv4 host conformance", scope["scope"])
                self.assertIn("fragmentation/reassembly", scope["scope"])
                self.assertEqual(document["text_sha256"], text_hash)
                rows = [r for r in document["paragraphs"] if r["status"] != "context"]
                self.assertEqual(len(rows), total)
                self.assertEqual(Counter(r["status"] for r in rows), Counter(covered=covered, TODO=todos))
                keys = sorted((r["section"], audit.norm(r["quote"])) for r in rows)
                self.assertEqual(audit.digest(json.dumps(keys, separators=(",", ":")).encode()), clauses_hash)
                specs = audit.toml_entries(ROOT / f"duvet/rfc{n}-additions.toml")
                dispositions = audit.toml_entries(ROOT / f"duvet/rfc{n}-todos.toml")
                self.assertEqual(Counter(audit.clause_key(r) for r in rows),
                                 Counter(audit.clause_key(r) for kind, r in specs if kind == "SPEC"))
                self.assertEqual(Counter((r["status"].upper(), audit.clause_key(r), r["reason"])
                                         for r in rows if r["status"] in ("TODO", "exception")),
                                 Counter((kind, audit.clause_key(r), r["reason"]) for kind, r in dispositions))

    def test_evidence_attaches_full_clauses_to_real_source_and_assertions(self):
        for n in CONTRACT:
            for row in ledger(n)["paragraphs"]:
                if row["status"] == "covered":
                    self.assertEqual(len(row["evidence"]), 2, row["id"])
                for index, evidence in enumerate(row.get("evidence", [])):
                    path, anchor = evidence.split("::", 1)
                    matches = [a for a in audit.source_annotations((ROOT / path).read_text())
                               if audit.clause_key(a) == audit.clause_key(row) and anchor in a["attached"]]
                    self.assertTrue(matches, (row["id"], evidence))
                    self.assertTrue(any(a["kind"] == ("CITATION" if index == 0 else "TEST") for a in matches))
                    if row["status"] == "TODO":
                        self.assertTrue(any(a["reason"] == row["reason"] for a in matches))
                    if index == 1:
                        self.assertTrue(any("assert" in a["attached"] for a in matches))

    def test_atomic_id_amendment_and_selected_gaps_are_explicit(self):
        for n in (791, 1122):
            row = next(r for r in ledger(n)["paragraphs"] if r["id"] == f"{n}-id-amendment")
            self.assertEqual(row["status"], "context")
            self.assertIn("RFC6864", row["reason"])
            self.assertIn("atomic", row["reason"])
        rows = {r["id"]: r for r in ledger(6864)["paragraphs"]}
        self.assertEqual(rows["6864-atomic-definition"]["quote"],
                         "Atomic datagrams: (DF==1)&&(MF==0)&&(frag_offset==0)")
        self.assertEqual(rows["6864-nonatomic-boundary"]["status"], "context")
        self.assertEqual(next(r for r in ledger(1122)["paragraphs"]
                              if r["id"] == "1122-ttl-receive")["status"], "covered")
        for id in ("1122-options-pass", "1122-timestamp-destination", "1122-timestamp-value"):
            self.assertEqual(next(r for r in ledger(1122)["paragraphs"] if r["id"] == id)["status"], "TODO")
        parent = next(r for r in ledger(791)["paragraphs"] if r["id"] == "791-total-context")
        child = next(r for r in ledger(791)["paragraphs"] if r["id"] == "791-total")
        self.assertEqual(child["parent"], parent["id"])
        self.assertIn(audit.norm(child["quote"]), audit.norm(parent["quote"]))
        self.assertIn("whether they arrive whole or in fragments", parent["quote"])
        timebase = next(r for r in ledger(791)["paragraphs"] if r["id"] == "791-timestamp-timebase")
        self.assertIn("high order bit", timebase["quote"])
        self.assertEqual(timebase["status"], "covered")
        value = next(r for r in ledger(1122)["paragraphs"] if r["id"] == "1122-timestamp-value")
        self.assertIn("15 updates/second", value["reason"])
        self.assertIn("accuracy within a few minutes", value["reason"])
        for id in ("791-record-capacity", "791-timestamp-capacity"):
            self.assertEqual(next(r for r in ledger(791)["paragraphs"] if r["id"] == id)["status"], "TODO")

    def test_all_partial_ipv4_source_and_test_copies_keep_canonical_reasons(self):
        partial = {audit.clause_key(row): row for row in ledger(1122)["paragraphs"]
                   if row["status"] == "TODO"}
        seen = Counter()
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                key = audit.clause_key(annotation)
                if key in partial:
                    self.assertEqual(annotation["reason"], partial[key]["reason"], str(path))
                    seen[key] += 1
        self.assertEqual(set(seen), set(partial))
        self.assertTrue(all(count >= 2 for count in seen.values()))


class HistoricalPublication(unittest.TestCase):
    def setUp(self):
        (ROOT / "workbench").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / "workbench")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "duvet").mkdir()

    def book(self):
        return (b"RFC: 791\n\n              INTERNET PROTOCOL\n\n              September 1981\n"
                b"\f\nSeptember 1981\n              Internet Protocol\n\n"
                b"              1. INTRODUCTION\n\nBody must remain.\n\n     [Page i]  \n"
                b"\f\nSeptember 1981\n              Internet Protocol\nIntroduction\n\n"
                b"1.1. Motivation\n\nRequired behavior and its qualification.\n"
                b"\nInternet Protocol\nSeptember 1981\nIntroduction\n"
                b"Substantive body [Page iii]\n     [Page 1]  \n")

    def metadata(self):
        return {"doc_id": "RFC791", "source": "Legacy", "doi": "10.17487/RFC791",
                "title": "Internet Protocol", "pub_date": "September 1981",
                "pub_status": "INTERNET STANDARD", "status": "INTERNET STANDARD"}

    def test_legacy_identity_and_metadata_are_independently_bound(self):
        raw, metadata = self.book(), self.metadata()
        self.assertTrue(identity(raw, 791))
        self.assertFalse(identity(raw, 1122))
        self.assertEqual(audit.validate_legacy_metadata(791, raw, metadata), "Internet Standard")
        for key, value in (("doc_id", "RFC1122"), ("doi", "10.17487/RFC1122"),
                           ("source", "unknown"), ("title", "Different publication"),
                           ("pub_date", "October 1989"), ("pub_date", ""), ("pub_status", "EXPERIMENTAL"),
                           ("status", "EXPERIMENTAL")):
            changed = {**metadata, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.validate_legacy_metadata(791, raw, changed)
        self.assertFalse(identity(raw + b"\nRFC1122             Other document\n", 791))
        self.assertFalse(identity(raw + b"\nRFC: 1122\n", 791))
        self.assertFalse(identity(b"RFC1122             Missing publication identity\n", 1122))
        with self.assertRaises(ValueError):
            audit.validate_legacy_metadata(791, raw.replace(b"RFC: 791", b"RFC: 1122"), metadata)

    def test_book_furniture_and_heading_whitespace_preserve_substantive_text(self):
        raw = self.book()
        prepared = prepare(raw).decode()
        self.assertIn("\n1. INTRODUCTION\n", prepared)
        self.assertNotIn("[Page i]", prepared)
        self.assertNotIn("[Page 1]", prepared)
        self.assertIn("Substantive body [Page iii]", prepared)
        # Identical words inside the body are substantive, not page furniture.
        self.assertIn("Internet Protocol\nSeptember 1981\nIntroduction", prepared)
        sections = audit.official_sections(raw)
        self.assertEqual(sections["section-1"], "Body must remain.")
        self.assertIn("Required behavior and its qualification.", sections["section-1.1"])
        # A title at a page edge without the publication header pair survives.
        no_header = raw + b"\f\nIntroduction\n\nThis is substantive.\n"
        self.assertIn("Introduction\n\nThis is substantive.", prepare(no_header).decode())
        self.assertEqual(prepare(prepare(raw)), prepare(raw))

    def test_indented_hierarchy_does_not_promote_references_or_toc(self):
        raw = (b"Request for Comments: 1122\nOctober 1989\n\n1. INTRODUCTION\n\n"
               b"\f\nRFC1122             INTRODUCTION       October 1989\n\n"
               b"   1.1  Architecture\n\n      1.1.1  Hosts\n\n"
               b"            See Section\n            3.3.4 below.\n\n"
               b"            IEEE\n            802.3 frames are substantive.\n\n"
               b"   2.1  Contents ............ 21\n\n"
               b"2. LINK LAYER\n\n   2.1  Introduction\n\nRequired clause.\n")
        sections = audit.official_sections(raw)
        self.assertEqual({s for s in sections if s.startswith("section-")},
                         {"section-1", "section-1.1", "section-1.1.1", "section-2", "section-2.1"})
        self.assertIn("3.3.4 below.", sections["section-1.1.1"])
        self.assertIn("802.3 frames are substantive.", sections["section-1.1.1"])
        self.assertNotIn("RFC1122", sections["section-1.1.1"])

    def test_historical_fetch_records_raw_text_and_metadata_provenance(self):
        raw, metadata = self.book(), self.metadata()
        calls = []
        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            payload = json.dumps(metadata).encode() if request.full_url.endswith(".json") else raw
            response = io.BytesIO(payload)
            response.geturl = lambda: request.full_url
            response.headers = {}
            return response
        audit.fetch_official(791, self.root, opener)
        provenance = json.loads((self.root / "rfc791.provenance.json").read_text())
        self.assertEqual((self.root / "rfc791.txt").read_bytes(), raw)
        self.assertEqual(provenance["sha256"], audit.digest(raw))
        self.assertEqual(provenance["publication_metadata"]["sha256"], audit.digest(json.dumps(metadata).encode()))
        self.assertEqual(calls, [(PREFIX + "791.txt", 30), (PREFIX + "791.json", 30)])
        metadata["doc_id"] = "RFC1122"
        with self.assertRaisesRegex(ValueError, "3 bounded requests"):
            audit.fetch_official(791, self.root, opener)
        raw = raw.replace(b"RFC: 791", b"RFC: 1122")
        with self.assertRaisesRegex(ValueError, "requested official text"):
            audit.fetch_official(791, self.root, opener)

    def test_historical_report_retains_full_sections_and_rejects_erased_text(self):
        report, entries, texts = report_fixture(self.root)
        raw = self.book().replace(b"Required behavior and its qualification.", b"Required behavior.")
        texts[791] = raw
        spec = report["specifications"][PREFIX + "791"]
        required = spec["sections"][0]["lines"][0]
        # Existing synthetic evidence points at section 1; retain its full text
        # and add all the historical section's other substantive text.
        raw = raw.replace(b"Body must remain.", b"Required behavior. Body must remain.")
        texts[791] = raw
        sections = audit.official_sections(raw)
        spec["sections"] = [{"id": "section-1", "lines": [required, "Body must remain."]},
                            {"id": "section-1.1", "lines": [sections["section-1.1"]]}]
        audit.validate_report(report, report_scopes(), entries, texts, root=self.root)
        for mutate in (lambda s: s["sections"].pop(),
                       lambda s: s["sections"][0]["lines"].pop(),
                       lambda s: s["sections"][1].update(lines=["Required behavior."])):
            broken = copy.deepcopy(report)
            mutate(broken["specifications"][PREFIX + "791"])
            with self.assertRaises(ValueError):
                audit.validate_report(broken, report_scopes(), entries, texts, root=self.root)

    def test_missing_or_narrowed_selected_requirement_fails(self):
        report, entries, texts = report_fixture(self.root)
        scopes = report_scopes()
        for n in CONTRACT:
            index = next(i for i, (_, _, row) in enumerate(entries) if row["target"] == PREFIX + str(n) + "#section-1")
            for change in ("missing", "narrowed"):
                changed = copy.deepcopy(entries)
                if change == "missing":
                    changed.pop(index)
                else:
                    changed[index][2]["quote"] = "Required"
                with self.subTest(rfc=n, change=change), self.assertRaises(ValueError):
                    audit.validate_report(report, scopes, changed, texts, root=self.root)
            document = ledger(n)
            rows = document["paragraphs"]
            row = next(r for r in rows if r["status"] != "context")
            row["quote"] = row["quote"].rsplit(" ", 1)[0]
            keys = sorted((r["section"], audit.norm(r["quote"])) for r in rows if r["status"] != "context")
            self.assertNotEqual(audit.digest(json.dumps(keys, separators=(",", ":")).encode()), CONTRACT[n][4])

    def test_changed_ipv4_source_and_test_quotes_cannot_use_fuzzy_report_mapping(self):
        report, entries, texts = report_fixture(self.root)
        source = self.root / "source.rs"
        original = source.read_text()
        for kind in ("CITATION", "TEST"):
            annotation = next(a for a in report["annotations"]
                              if a["target_path"] == PREFIX + "791" and a["type"] == kind)
            for changed in ("Required behavioX.", "Required"):
                lines = original.splitlines()
                lines[annotation["line"] + 1] = "//# " + changed
                source.write_text("\n".join(lines) + "\n")
                with self.subTest(kind=kind, quote=changed), self.assertRaises(ValueError):
                    audit.validate_report(report, report_scopes(), entries, texts, root=self.root)
        source.write_text(original)


if __name__ == "__main__":
    unittest.main()
