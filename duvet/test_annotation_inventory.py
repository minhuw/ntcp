import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_annotation_inventory as audit
from rfc_scopes import ORIGINAL_RFCS, PREFIX, ROOT, check_registration, load_scopes


def report_scopes():
    scopes = copy.deepcopy(load_scopes())
    # The synthetic report uses section 1 in every document. Real RFC9293's
    # section-3 policy is independently guarded by registration tests.
    scopes[9293]["extraction"] = "all"
    return scopes


def report_fixture(root):
    annotations, specifications, entries, texts = [], {}, [], {}
    source_lines = []
    manifest = {"schema_version": 1, "rfcs": {}}
    for n, scope in report_scopes().items():
        target = f"{PREFIX}{n}"
        index = len(annotations)
        path = (f"workbench/duvet/requirements/rfc{n}/section-1.toml"
                if scope["extraction"] != "manual" else "requirements.toml")
        row = {"target": target + "#section-1", "quote": "Required behavior."}
        annotations.append({"source": path, "line": 1, "target_path": target,
                            "target_section": "section-1", "type": "SPEC"})
        for kind in ("CITATION", "TEST"):
            annotations.append({"source": "source.rs", "line": len(source_lines) + 1,
                                "target_path": target, "target_section": "section-1", "type": kind})
            source_lines.extend([f"//= {target}#section-1", f"//= type={kind.lower()}",
                                 "//# Required behavior.", "fn evidence() {}"])
        specifications[target] = {"requirements": [index], "sections": [
            {"id": "section-1", "lines": [[[[index, index + 1, index + 2], 0, "Required behavior."]]]}]}
        entries.append((path, "SPEC", row))
        texts[n] = b"1. Introduction\n\n   Required behavior.\n"
        if scope["extraction"] != "manual":
            manifest["rfcs"][str(n)] = {"text_sha256": audit.digest(texts[n]), "requirements": [row]}
    (root / "source.rs").write_text("\n".join(source_lines) + "\n")
    (root / "duvet/extracted-requirements.json").write_text(json.dumps(manifest))
    return {"annotations": annotations, "specifications": specifications,
            "refs": [{"spec": True, "citation": True, "test": True}]}, entries, texts


class InventoryAudit(unittest.TestCase):
    def setUp(self):
        (ROOT / "workbench").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / "workbench")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "duvet").mkdir()

    def validate_report(self, report, scopes, entries, texts):
        return audit.validate_report(report, scopes, entries, texts, root=self.root)

    def copy_registry(self):
        for path in (ROOT / "duvet").iterdir():
            if path.is_file():
                shutil.copyfile(path, self.root / "duvet" / path.name)

    def test_registration_cannot_drop_originals_or_drift_from_config(self):
        self.copy_registry()
        self.assertEqual(set(check_registration(self.root)), set(load_scopes()))
        path = self.root / "duvet/rfc-scopes.toml"
        original = path.read_text()
        for changed in (original.replace("id = 7413", "id = 6191"),
                        original.replace("id = 7413", "id = 9293"),
                        original.replace('extraction = "section-3"', 'extraction = "all"'),
                        original.replace('scope_kind = "selected-requirements"', 'scope_kind = "full-operative"'),
                        original.replace('document_status = "Experimental"', 'document_status = "Conformant"')):
            with self.subTest(change=changed[-200:]):
                path.write_text(changed)
                with self.assertRaises(ValueError):
                    check_registration(self.root)
        path.write_text(original)
        config = self.root / "duvet/duvet.toml"
        config.write_text(config.read_text().replace("rfc7413\"", "rfc6191\""))
        with self.assertRaisesRegex(ValueError, "membership mismatch"):
            check_registration(self.root)

    def test_missing_inventory_and_wrong_extraction_fail(self):
        self.copy_registry()
        inv = self.root / "duvet/rfc7413-additions.toml"
        original = inv.read_text()
        inv.unlink()
        with self.assertRaisesRegex(ValueError, "missing or invalid inventory"):
            check_registration(self.root)
        inv.write_text(original)
        config = self.root / "duvet/duvet.toml"
        config.write_text(config.read_text().replace("rfc9293/section-3*", "rfc9293/*"))
        with self.assertRaisesRegex(ValueError, "extraction mismatch"):
            check_registration(self.root)

    def ledger_fixture(self):
        target = PREFIX + "7413#section-1"
        raw = b"Request for Comments: 7413\nCategory: Experimental\n\n1. Introduction\n\n   Required behavior.\n\n   Background context.\n"
        scope = {"id": 7413, "scope_kind": "scoped-operative", "scope": "Selected behavior only",
                 "document_status": "Experimental", "inventory": "duvet/rfc7413-inventory.json"}
        row = {"id": "7413-001", "section": "1", "target": target, "quote": "Required behavior.",
               "status": "covered", "reason": "Source and assertion implement this behavior.",
               "evidence": ["crates/source.rs::fn source()", "crates/test.rs::fn test()"]}
        ledger = {"rfc": 7413, "scope_kind": "scoped-operative", "scope": scope["scope"],
                  "document_status": "Experimental", "text_sha256": audit.digest(raw), "paragraphs": [row]}
        (self.root / "crates").mkdir()
        for name, kind in (("source", ""), ("test", "//= type=test\n")):
            (self.root / f"crates/{name}.rs").write_text(f"//= {target}\n{kind}//# Required behavior.\nfn {name}() {{}}\n")
        (self.root / "duvet/rfc7413-additions.toml").write_text(f'[[spec]]\ntarget = "{target}"\nquote = "Required behavior."\n')
        (self.root / "duvet/rfc7413-todos.toml").write_text("")
        return scope, ledger, raw

    def validate_ledger(self, scope, ledger, raw):
        (self.root / scope["inventory"]).write_text(json.dumps(ledger))
        return audit.validate_inventories(self.root, {7413: scope}, {7413: raw})

    def test_exact_provenance_metadata_and_evidence_are_required(self):
        scope, ledger, raw = self.ledger_fixture()
        self.assertEqual(len(self.validate_ledger(scope, ledger, raw)), 1)
        mutations = [lambda d: d.update(text_sha256="0" * 64),
                     lambda d: d.update(document_status="Standards Track"),
                     lambda d: d["paragraphs"][0].update(quote="Required behavior!"),
                     lambda d: d["paragraphs"][0].update(section="2"),
                     lambda d: d["paragraphs"][0].update(target=PREFIX + "7413#section-2"),
                     lambda d: d["paragraphs"].append(copy.deepcopy(d["paragraphs"][0])),
                     lambda d: d["paragraphs"][0].update(evidence=["crates/source.rs::fn test()", "crates/test.rs::fn test()"]),
                     lambda d: d["paragraphs"][0].update(evidence=["crates/source.rs::fn source()", "crates/source.rs::fn source()"]),
                     lambda d: d["paragraphs"][0].update(evidence=["missing.rs::fn source()", "crates/test.rs::fn test()"])]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                broken = copy.deepcopy(ledger)
                mutate(broken)
                with self.assertRaises((ValueError, KeyError)):
                    self.validate_ledger(scope, broken, raw)
        source = self.root / "crates/source.rs"
        source.write_text(source.read_text().replace("Required behavior.", "Required behavior!"))
        with self.assertRaisesRegex(ValueError, "evidence target/quote/anchor mismatch"):
            self.validate_ledger(scope, ledger, raw)

    def test_partial_evidence_retains_todo_reason_and_strict_failure(self):
        scope, ledger, raw = self.ledger_fixture()
        row = ledger["paragraphs"][0]
        row.update(status="TODO", reason="Missing assertion.", evidence=[row["evidence"][0]])
        target = row["target"]
        (self.root / "duvet/rfc7413-todos.toml").write_text(f'[[TODO]]\ntarget = "{target}"\nquote = "Required behavior."\nreason = "Missing assertion."\n')
        with self.assertRaisesRegex(ValueError, "partial evidence reason mismatch"):
            self.validate_ledger(scope, ledger, raw)
        source = self.root / "crates/source.rs"
        source.write_text(source.read_text().replace("//#", "//= reason=Missing assertion.\n//#"))
        self.validate_ledger(scope, ledger, raw)

    def test_scoped_inventory_does_not_imply_full_document_audit(self):
        scope, ledger, raw = self.ledger_fixture()
        self.validate_ledger(scope, ledger, raw)
        scope["scope_kind"] = "full-operative"
        with self.assertRaisesRegex(ValueError, "scope claim mismatch"):
            self.validate_ledger(scope, ledger, raw)
        ledger["scope_kind"] = "full-operative"
        with self.assertRaisesRegex(ValueError, "omits document text"):
            self.validate_ledger(scope, ledger, raw)
        ledger["paragraphs"].append({"id": "7413-002", "section": "1", "quote": "Background context.",
                                     "status": "context", "reason": "Background only."})
        self.validate_ledger(scope, ledger, raw)

    def test_furniture_and_hyphen_whitespace_never_change_operative_text(self):
        raw = b"1. Intro\n\n   Must retain per-service-\n\nAuthor [Page 1]\n\f\nRFC 7413  TCP Fast Open\n\n   port punctuation.\n   W (t) = C * t\n"
        text = audit.norm("\n".join(audit.official_lines(raw)))
        self.assertIn("per-service-port punctuation.", text)
        self.assertNotIn("Author", text)
        self.assertIn("W (t) = C * t", audit.official_sections(raw)["section-1"])
        self.assertNotIn("per service port", text)
        self.assertEqual(audit.norm("x <-\n y"), "x <- y")
        self.assertEqual(audit.norm("a - b"), "a - b")
        self.assertEqual(audit.norm("(SHLD-\n 13)."), "(SHLD-13).")
        self.assertNotEqual(audit.norm("(SHLD-\n 13)."), "(SHLD13).")

    def test_report_requires_full_spans_and_consistent_evidence_flags(self):
        report, entries, texts = report_fixture(self.root)
        scopes = report_scopes()
        self.assertEqual(self.validate_report(report, scopes, entries, texts)[1], [])
        mutations = [lambda r: r["specifications"].pop(PREFIX + "7413"),
                     lambda r: r["specifications"][PREFIX + "7413"].update(requirements=[]),
                     lambda r: r["specifications"][PREFIX + "7413"].update(sections=[]),
                     lambda r: r["refs"][0].update(test=False),
                     lambda r: r["specifications"][PREFIX + "7413"]["sections"][0]["lines"][0][0].__setitem__(2, "Required behavior!"),
                     lambda r: r["specifications"][PREFIX + "7413"]["sections"][0]["lines"][0][0][0].remove(
                         r["specifications"][PREFIX + "7413"]["requirements"][0])]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                broken = copy.deepcopy(report)
                mutate(broken)
                with self.assertRaises(ValueError):
                    self.validate_report(broken, scopes, entries, texts)

    def test_report_cannot_omit_unannotated_document_sections(self):
        report, entries, texts = report_fixture(self.root)
        target = PREFIX + "7413"
        texts[7413] += b"\n2. Unselected capability\n\n   Other behavior.\n"
        report["specifications"][target]["sections"].append({"id": "section-2", "lines": ["   Other behavior."]})
        self.validate_report(report, report_scopes(), entries, texts)
        report["specifications"][target]["sections"].pop()
        with self.assertRaisesRegex(ValueError, "omits official document sections"):
            self.validate_report(report, report_scopes(), entries, texts)

    def test_todo_cannot_hide_an_untracked_fragment_of_the_same_span(self):
        report, entries, texts = report_fixture(self.root)
        todo_id = len(report["annotations"])
        report["annotations"].append({"source": "todos.toml", "line": 1, "type": "TODO",
                                       "target_path": PREFIX + "9293", "target_section": "section-1"})
        report["refs"].extend([{"spec": True, "todo": True}, {"spec": True}])
        section = report["specifications"][PREFIX + "9293"]["sections"][0]
        section["lines"] = [[[[0, todo_id], 1, "Required "], [[0], 2, "behavior."]]]
        entries.append(("todos.toml", "TODO", {"target": PREFIX + "9293#section-1", "quote": "Required"}))
        with self.assertRaisesRegex(ValueError, "untracked in-scope requirement fragment"):
            self.validate_report(report, report_scopes(), entries, texts)

    def test_complete_tracking_can_pass_while_strict_coverage_fails(self):
        report, entries, texts = report_fixture(self.root)
        todo_id = len(report["annotations"])
        report["annotations"].append({"source": "todos.toml", "line": 1, "type": "TODO",
                                       "target_path": PREFIX + "9293", "target_section": "section-1",
                                       "comment": "Missing assertion."})
        report["refs"].append({"spec": True, "todo": True, "citation": True, "test": True})
        report["specifications"][PREFIX + "9293"]["sections"][0]["lines"] = [[[[0, 1, 2, todo_id], 1, "Required behavior."]]]
        entries.append(("todos.toml", "TODO", {"target": PREFIX + "9293#section-1", "quote": "Required behavior."}))
        summaries, errors, omitted = self.validate_report(report, report_scopes(), entries, texts)
        self.assertEqual((summaries["9293"]["uncovered"], summaries["9293"]["untracked"], omitted), (1, 0, 0))
        self.assertTrue(any("Missing assertion." in e for e in errors))

    def test_mixed_exception_closure_is_not_claimed_as_full_source_and_test(self):
        report, entries, texts = report_fixture(self.root)
        exception_id = len(report["annotations"])
        report["annotations"].append({"source": "exceptions.toml", "line": 1, "type": "EXCEPTION",
                                       "target_path": PREFIX + "9293", "target_section": "section-1"})
        report["refs"].append({"spec": True, "exception": True})
        report["specifications"][PREFIX + "9293"]["sections"][0]["lines"] = [
            [[[0, 1, 2], 0, "Required "], [[0, exception_id], 1, "behavior."]]]
        entries.append(("exceptions.toml", "EXCEPTION", {"target": PREFIX + "9293#section-1", "quote": "behavior."}))
        source = self.root / "source.rs"
        source.write_text(source.read_text().replace("//# Required behavior.", "//# Required", 2))
        self.assertEqual(self.validate_report(report, report_scopes(), entries, texts)[1], [])
        self.assertEqual(audit.closure_counts(report), {"source_and_test_closed": len(load_scopes()) - 1, "mixed_closure": 1})

    def test_original_extracted_obligations_are_preserved_independently(self):
        manifest = json.loads((ROOT / "duvet/extracted-requirements.json").read_text())
        self.assertEqual(manifest["base_commit"], "5817f38acc6b351525a167e72de90eb38294d881")
        keys = sorted((row["target"], " ".join(row["quote"].split())) for n in ORIGINAL_RFCS if n != 7413
                      for row in manifest["rfcs"][str(n)]["requirements"])
        self.assertEqual(len(keys), 569)
        # Original target/full-quotation keys are a permanent floor. Future
        # registrations may extend the manifest without revising this digest.
        self.assertEqual(audit.digest(json.dumps(keys, ensure_ascii=True, separators=(",", ":")).encode()),
                         "1ca031a4e8bc3206bf685feafa8e36a10f3983486de3de973761fa3e386ea151")
        self.assertEqual(manifest["rfcs"]["8201"]["requirements"], [])
        self.assertTrue(manifest["rfcs"]["8201"]["empty_reason"])

    def test_missing_extraction_file_or_entire_rfc_cannot_erase_obligations(self):
        report, entries, texts = report_fixture(self.root)
        target = PREFIX + "9293"
        manual_id = len(report["annotations"])
        manual_row = {"target": target + "#section-1", "quote": "Required"}
        entries.append(("manual9293.toml", "SPEC", manual_row))
        report["annotations"].append({"source": "manual9293.toml", "line": 1, "type": "SPEC",
                                       "target_path": target, "target_section": "section-1"})
        report["specifications"][target]["requirements"].append(manual_id)
        extra = {"target": target + "#section-1", "quote": "behavior."}
        path = "workbench/duvet/requirements/rfc9293/second.toml"
        entries.append((path, "SPEC", extra))
        manifest_path = self.root / "duvet/extracted-requirements.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["rfcs"]["9293"]["requirements"].append(extra)
        manifest_path.write_text(json.dumps(manifest))
        index = len(report["annotations"])
        report["annotations"].append({"source": path, "line": 1, "type": "SPEC",
                                       "target_path": target, "target_section": "section-1"})
        report["specifications"][target]["requirements"].append(index)
        report["specifications"][target]["sections"][0]["lines"] = [
            [[[0, 1, 2, manual_id], 0, "Required "], [[0, 1, 2, index], 0, "behavior."]]]
        patterns = []
        for n, scope in report_scopes().items():
            if scope["extraction"] != "manual":
                patterns.append({"pattern": f"workbench/duvet/requirements/rfc{n}/*.toml"})
        (self.root / "duvet/duvet.toml").write_text("\n".join(
            '[[requirement]]\npattern = ' + json.dumps(p["pattern"]) for p in patterns))
        manual = []
        for filename, kind, row in entries:
            if not filename.startswith("workbench/"):
                manual.append((filename, kind, row))
                continue
            inventory = self.root / filename
            inventory.parent.mkdir(parents=True, exist_ok=True)
            inventory.write_text('[[spec]]\ntarget = ' + json.dumps(row["target"])
                                 + '\nquote = ' + json.dumps(row["quote"]) + '\n')
        complete = manual + list(audit.extraction_entries(self.root))
        self.validate_report(report, report_scopes(), complete, texts)
        (self.root / path).unlink()
        partial = manual + list(audit.extraction_entries(self.root))
        with self.assertRaisesRegex(ValueError, "extracted obligation set mismatch"):
            self.validate_report(report, report_scopes(), partial, texts)
        # Also remove the omitted requirement from the report, reproducing a
        # self-consistent truncated generator output. The independent keys win.
        report["annotations"].pop()
        report["specifications"][target]["requirements"].pop()
        report["specifications"][target]["sections"][0]["lines"][0][1][0].remove(index)
        with self.assertRaisesRegex(ValueError, "extracted obligation set mismatch"):
            self.validate_report(report, report_scopes(), partial, texts)
        # Strip all generated SPEC rows for this RFC from a self-consistent
        # report while preserving its nonempty manual inventory and evidence.
        stripped = copy.deepcopy(report)
        stripped["annotations"].pop(0)
        for spec in stripped["specifications"].values():
            spec["requirements"] = [i - 1 for i in spec["requirements"] if i != 0]
            for section in spec["sections"]:
                for line in section["lines"]:
                    if isinstance(line, list):
                        for fragment in line:
                            fragment[0] = [i - 1 for i in fragment[0] if i != 0]
        remaining = [e for e in partial if "/rfc9293/" not in e[0]]
        self.assertTrue(stripped["specifications"][target]["requirements"])
        with self.assertRaisesRegex(ValueError, "extracted obligation set mismatch"):
            self.validate_report(stripped, report_scopes(), remaining, texts)
        shutil.rmtree(self.root / "workbench/duvet/requirements/rfc9293")
        with self.assertRaisesRegex(ValueError, "missing extraction files"):
            list(audit.extraction_entries(self.root))
        with self.assertRaisesRegex(ValueError, "extracted obligation set mismatch"):
            self.validate_report(report, report_scopes(), manual, texts)

    def test_extraction_contract_rejects_invalid_provenance_and_membership(self):
        report, entries, texts = report_fixture(self.root)
        path = self.root / "duvet/extracted-requirements.json"
        original = json.loads(path.read_text())
        mutations = [lambda m: m["rfcs"].pop("9293"),
                     lambda m: m["rfcs"]["9293"].update(text_sha256="0" * 64),
                     lambda m: m["rfcs"]["9293"]["requirements"][0].update(quote="Required behavior!"),
                     lambda m: m["rfcs"]["9293"].update(requirements=[])]
        for mutate in mutations:
            broken = copy.deepcopy(original)
            mutate(broken)
            path.write_text(json.dumps(broken))
            with self.assertRaises(ValueError):
                self.validate_report(report, report_scopes(), entries, texts)

    def test_toml_source_and_test_quotes_reject_fuzzy_matches_and_partial_spans(self):
        report, entries, texts = report_fixture(self.root)
        scopes = report_scopes()
        self.assertTrue(scopes[7413]["inventory"].endswith(".toml"))
        with patch.object(audit, "source_annotations", wraps=audit.source_annotations) as parser:
            self.validate_report(report, scopes, entries, texts)
            parser.assert_called()
        source = self.root / "source.rs"
        original = source.read_text()
        for kind in ("CITATION", "TEST"):
            annotation = next(a for a in report["annotations"]
                              if a["target_path"] == PREFIX + "7413" and a["type"] == kind)
            for typo in ("Required behavioX.", "Required behavior!"):
                lines = original.splitlines()
                # One character changed; the report still maps the official
                # quote, as Duvet's fuzzy fallback can do in a real generation.
                lines[annotation["line"] + 1] = "//# " + typo
                source.write_text("\n".join(lines) + "\n")
                with self.subTest(kind=kind, typo=typo), self.assertRaisesRegex(ValueError, "exact official provenance"):
                    self.validate_report(report, scopes, entries, texts)
            source.write_text(original)
        broken = copy.deepcopy(report)
        spec = broken["specifications"][PREFIX + "7413"]
        index = spec["requirements"][0]
        spec["sections"][0]["lines"] = [
            [[[index, index + 1, index + 2], 0, "Required "], [[index], 1, "behavior."]]]
        broken["refs"].append({"spec": True, "exception": True})
        # Supply a valid exception so the failure specifically exposes partial
        # source/test mapping, rather than untracked requirement coverage.
        exception_id = len(broken["annotations"])
        broken["annotations"].append({"source": "exceptions.toml", "line": 1, "type": "EXCEPTION",
                                       "target_path": PREFIX + "7413", "target_section": "section-1"})
        spec["sections"][0]["lines"][0][1][0].append(exception_id)
        entries.append(("exceptions.toml", "EXCEPTION", {"target": PREFIX + "7413#section-1", "quote": "behavior."}))
        with self.assertRaisesRegex(ValueError, "partial or mismatched full quotation span"):
            self.validate_report(broken, scopes, entries, texts)

    def test_empty_source_annotations_cannot_contribute_closure(self):
        report, entries, texts = report_fixture(self.root)
        source = self.root / "source.rs"
        empty_id = len(report["annotations"])
        line = len(source.read_text().splitlines()) + 1
        target = PREFIX + "7413"
        report["annotations"].append({"source": "source.rs", "line": line, "target_path": target,
                                       "target_section": "section-1", "type": "CITATION"})
        source.write_text(source.read_text() + f"//= {target}#section-1\n"
                          "// Ordinary comments separate Duvet annotations.\n//# Required behavior.\n")
        self.assertEqual(audit.source_annotations(source.read_text())[-1]["quote"], "")
        self.validate_report(report, report_scopes(), entries, texts)
        report["specifications"][target]["sections"][0]["lines"][0][0][0].append(empty_id)
        with self.assertRaisesRegex(ValueError, "empty source/test quotation claims evidence"):
            self.validate_report(report, report_scopes(), entries, texts)

    def test_historical_rfc1191_status_cannot_be_changed_in_both_registry_and_ledger(self):
        scope, ledger, raw = self.ledger_fixture()
        scope = json.loads(json.dumps(scope).replace("7413", "1191"))
        ledger = json.loads(json.dumps(ledger).replace("7413", "1191"))
        raw = raw.replace(b"7413", b"1191").replace(b"Category: Experimental", b"IAB Standards Track")
        scope["document_status"] = ledger["document_status"] = "Standards Track"
        ledger["text_sha256"] = audit.digest(raw)
        for name in ("source", "test"):
            path = self.root / f"crates/{name}.rs"
            path.write_text(path.read_text().replace("7413", "1191"))
        (self.root / "duvet/rfc1191-additions.toml").write_text(
            (self.root / "duvet/rfc7413-additions.toml").read_text().replace("7413", "1191"))
        inventory = self.root / scope["inventory"]
        inventory.write_text(json.dumps(ledger))
        audit.validate_inventories(self.root, {1191: scope}, {1191: raw})
        scope["document_status"] = ledger["document_status"] = "Informational"
        inventory.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(ValueError, "official document status mismatch"):
            audit.validate_inventories(self.root, {1191: scope}, {1191: raw})

    def test_generate_fetches_all_inputs_and_never_falls_back_to_cached_provenance(self):
        self.copy_registry()
        output = self.root / audit.ARTIFACTS / "current"
        output.mkdir(parents=True)
        (output / "receipt.json").write_text('{"stale": true}')
        (output / "outcome.json").write_text('{"complete": true}')
        with patch.object(audit, "fetch_official", side_effect=lambda n, directory: (n, b"fresh official")) as fetch:
            with patch.object(audit, "validate_inventories", side_effect=ValueError("invalid fresh provenance")):
                with patch.object(audit, "generate") as generator:
                    with self.assertRaisesRegex(ValueError, "invalid fresh provenance"):
                        audit.audit(self.root, generate_report=True)
                    generator.assert_not_called()
            self.assertEqual({c.args[0] for c in fetch.call_args_list}, set(load_scopes()))
        self.assertFalse((output / "receipt.json").exists())
        self.assertFalse((output / "outcome.json").exists())

    def test_known_singleton_mapping_loss_is_explicit_and_does_not_allow_truncation(self):
        section = {"lines": [[[[0], 0, "if (x) {"]], "}"]}
        projected, omitted = audit.section_projection(section, "if (x) { }", 0)
        self.assertEqual((projected, omitted), ("if (x) {", 1))
        section["lines"][0] = [[[], 0, "if ("], [[0], 0, "x) {"]]
        with self.assertRaises(ValueError):
            audit.section_projection(section, "if (x) { }", 0)
        section = {"lines": [[[[0], 0, "Clause"], [[], 0, "."]]]}
        with self.assertRaises(ValueError):
            audit.section_projection(section, "Clause.", 0)
        # Duvet's same singleton bug also applies to the annotation view. The
        # full official/source quote must still include the original character.
        section = {"lines": [[[[], 0, "A "], [[0], 0, "complete requirement."]]]}
        self.assertEqual(audit.section_projection(section, "A\ncomplete requirement.", 0),
                         ("complete requirement.", 1))
        for quote in ("A complete requirement.", "B\ncomplete requirement.", "A\nincomplete requirement."):
            with self.subTest(quote=quote), self.assertRaises(ValueError):
                audit.section_projection(section, quote, 0)

    def test_generation_rejects_any_nonzero_exit_even_with_a_report(self):
        output = self.root / audit.REPORT
        output.parent.mkdir(parents=True)
        for code in (1, 2, 101):
            output.write_text('{"old": true}')
            def runner(*args, **kwargs):
                self.assertFalse(output.exists())
                output.write_text('{"new": true}')
                return subprocess.CompletedProcess(args[0], code, b"generator output", b"arbitrary fault")
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "generator failed"):
                audit.generate(self.root, {}, runner=runner)
            self.assertEqual((self.root / audit.ARTIFACTS / "current/generation.exit").read_text().strip(), str(code))

    def test_generation_requires_new_report_and_clears_extraction(self):
        output = self.root / audit.REPORT
        output.parent.mkdir(parents=True)
        output.write_text('{"old": true}')
        extracted = output.parent / "requirements/stale.toml"
        extracted.parent.mkdir()
        extracted.write_text("stale")
        def no_report(*args, **kwargs):
            self.assertFalse(output.exists())
            self.assertFalse(extracted.exists())
            self.assertEqual(args[0][-3:], ["--generate-only", "--ci", "false"])
            return subprocess.CompletedProcess(args[0], 0, b"", b"")
        with self.assertRaisesRegex(ValueError, "fresh report"):
            audit.generate(self.root, {}, runner=no_report)
        def fresh_report(*args, **kwargs):
            output.write_text('{"fresh": true}')
            return subprocess.CompletedProcess(args[0], 0, b"", b"")
        self.assertEqual(audit.generate(self.root, {}, runner=fresh_report), {"fresh": True})
        def stale_report(*args, **kwargs):
            output.write_text('{"old": true}')
            os.utime(output, (1, 1))
            return subprocess.CompletedProcess(args[0], 0, b"", b"")
        with self.assertRaisesRegex(ValueError, "fresh report"):
            audit.generate(self.root, {}, runner=stale_report)
        def malformed(*args, **kwargs):
            output.write_text('{"truncated":')
            return subprocess.CompletedProcess(args[0], 0, b"", b"")
        with self.assertRaises(json.JSONDecodeError):
            audit.generate(self.root, {}, runner=malformed)

    def test_official_fetch_is_bounded_and_rejects_wrong_inputs(self):
        calls = []
        def opener(request, timeout):
            calls.append(timeout)
            response = io.BytesIO(b"<html>not an RFC</html>")
            response.geturl = lambda: request.full_url
            response.headers = {}
            return response
        with self.assertRaisesRegex(ValueError, "after 3 bounded requests"):
            audit.fetch_official(7413, self.root / "official", opener)
        self.assertEqual(calls, [30, 30, 30])
        def valid(request, timeout):
            response = io.BytesIO(b"Request for Comments: 7413\nCategory: Experimental\n")
            response.geturl = lambda: request.full_url
            response.headers = {}
            return response
        n, raw = audit.fetch_official(7413, self.root / "official", valid)
        provenance = json.loads((self.root / "official/rfc7413.provenance.json").read_text())
        self.assertEqual((n, audit.digest(raw)), (7413, provenance["sha256"]))
        self.assertEqual(provenance["url"], PREFIX + "7413.txt")

    def test_read_only_audit_requires_current_input_and_report_receipt(self):
        self.copy_registry()
        output = self.root / audit.ARTIFACTS / "current"
        output.mkdir(parents=True)
        report = self.root / audit.REPORT
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("{}")
        receipt = {"inputs": audit.input_hashes(self.root), "report_sha256": audit.digest(b"{}")}
        (output / "receipt.json").write_text(json.dumps(receipt))
        report.write_text('{"changed": true}')
        with self.assertRaisesRegex(ValueError, "stale report/inputs"):
            audit.audit(self.root)
        report.write_text("{}")
        (self.root / "duvet/rfc7413-todos.toml").write_text("# changed\n")
        with self.assertRaisesRegex(ValueError, "stale report/inputs"):
            audit.audit(self.root)


if __name__ == "__main__":
    unittest.main()
