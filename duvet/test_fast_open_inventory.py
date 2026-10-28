"""Full-operative RFC7413 ledger contracts, including original evidence floors.

The section commitment was computed from the complete official published text,
removing only the auditor's documented page furniture/whitespace. Reconstruction
checks overlapping parent/child spans as well as prose without BCP14 keywords.
Fresh generation independently validates the raw official hash and report links.
These structural tests do not replace independent source/assertion review.
"""
from collections import Counter, defaultdict
import copy
import json
import unittest

import check_annotation_inventory as audit
from rfc_scopes import ORIGINAL_RFCS, PREFIX, ROOT, check_registration


RAW_SHA256 = "ea094553d58f53df919071b597d3dd0ac1ab512e297271a89463101f8bf6eb16"
SECTIONS_SHA256 = "daf21f22d879c1bdac61af922286c8c39479b1b119fc022c65e817833236439b"
ORIGINAL_KEYS_SHA256 = "0dc7e9fe2158e45bda2fa3d230943a71a65a602da159a3a9d715487fe29c50dc"
ORIGINAL_EVIDENCE = {
    "connection.rs": [(5, "CITATION"), (6, "CITATION"), (8, "CITATION"), (7, "CITATION")],
    "endpoint.rs": [(3, "CITATION"), (1, "CITATION"), (2, "CITATION"), (4, "CITATION"), (9, "CITATION")],
    "fast_open_early_data_policy_tests.rs": [(1, "TEST"), (2, "TEST"), (4, "TEST"), (3, "TEST"), (5, "TEST")],
    "fast_open_server_cookie_tests.rs": [(6, "TEST"), (7, "TEST"), (8, "TEST"), (9, "TEST")],
    "fast_open_client_policy_tests.rs": [(4, "TEST")],
}


def ledger():
    return json.loads((ROOT / "duvet/rfc7413-inventory.json").read_text())


def reconstruct(rows):
    """Reconstruct every normalized section with exact overlapping offsets."""
    sections = defaultdict(list)
    for row in rows:
        section = ("section-" if row["section"][0].isdigit() else "appendix-") + row["section"]
        text = sections[section]
        quote, offset = row["quote"], row["offset"]
        if quote != audit.norm(quote) or offset < 0:
            raise ValueError("invalid normalized quote/offset")
        text.extend([None] * max(0, offset + len(quote) - len(text)))
        for i, c in enumerate(quote, offset):
            if text[i] is not None and text[i] != c:
                raise ValueError("overlapping quotations disagree")
            text[i] = c
    return {s: "".join(c if c is not None else " " for c in chars) for s, chars in sections.items()}


class FastOpenInventory(unittest.TestCase):
    def test_full_operative_registration_and_official_commitment(self):
        scopes, document = check_registration(), ledger()
        self.assertEqual(set(scopes), set(ORIGINAL_RFCS) | {6191, 6429, 791, 1122, 6864, 3542, 8200})
        scope = scopes[7413]
        self.assertEqual(scope["scope_kind"], "full-operative")
        self.assertEqual(scope["extraction"], "manual")
        self.assertEqual(scope["inventory"], "duvet/rfc7413-inventory.json")
        self.assertEqual(document["rfc"], 7413)
        self.assertEqual(document["document_status"], "Experimental")
        self.assertEqual(document["text_sha256"], RAW_SHA256)
        for field in ("scope", "scope_kind", "document_status"):
            self.assertEqual(document[field], scope[field])
        self.assertEqual(audit.digest(json.dumps(document["section_sha256"], sort_keys=True).encode()),
                         SECTIONS_SHA256)
        sections = reconstruct(document["paragraphs"])
        self.assertEqual({s: audit.digest(text.encode()) for s, text in sections.items()},
                         document["section_sha256"])
        audit.validate_full_document(7413, sections, document["paragraphs"])

    def test_omitted_or_changed_prose_and_appendix_text_fail(self):
        document = ledger()
        sections = reconstruct(document["paragraphs"])
        for id in ("7413-mac-expiration", "7413-api-nonblock-miss", "7413-1-context-1",
                   "7413-reset-monitor", "7413-server-final-ack"):
            with self.subTest(row=id):
                broken = [r for r in document["paragraphs"] if r["id"] != id]
                with self.assertRaisesRegex(ValueError, "omits document text"):
                    audit.validate_full_document(7413, sections, broken)
        broken = copy.deepcopy(document["paragraphs"])
        original = next(r for r in broken if r["id"] == "7413-original-7")
        original["quote"] = original["quote"].replace("536", "1220")
        with self.assertRaisesRegex(ValueError, "overlapping quotations disagree"):
            # Add an exact overlapping original to make disagreement explicit.
            reconstruct(broken + [next(r for r in document["paragraphs"]
                                      if r["id"] == "7413-original-7")])

    def test_original_nine_keys_and_all_existing_evidence_survive(self):
        document = ledger()
        originals = {r["id"]: r for r in document["paragraphs"] if r.get("original")}
        self.assertEqual(len(originals), 9)
        keys = sorted((r["id"], *audit.clause_key(r)) for r in originals.values())
        self.assertEqual(audit.digest(json.dumps(keys).encode()), ORIGINAL_KEYS_SHA256)
        specs = {audit.clause_key(r) for kind, r in audit.toml_entries(ROOT / "duvet/rfc7413-additions.toml")
                 if kind == "SPEC"}
        self.assertTrue({audit.clause_key(r) for r in originals.values()} <= specs)
        for file, expected in ORIGINAL_EVIDENCE.items():
            annotations = audit.source_annotations((ROOT / "crates/stacks/ntcp/src" / file).read_text())
            for number, kind in expected:
                row = originals[f"7413-original-{number}"]
                matches = [a for a in annotations if a["kind"] == kind
                           and audit.clause_key(a) == audit.clause_key(row)]
                self.assertTrue(matches, (file, number, kind))
                if row["status"] == "TODO":
                    self.assertTrue(all(a["reason"] == row["reason"] for a in matches),
                                    (file, number, kind))
        # Full auditing may expose a qualifier previously hidden by selected
        # scope. Preserve the full original obligation and evidence as a TODO.
        self.assertEqual(originals["7413-original-7"]["status"], "TODO")
        self.assertIn("Held for Document Update", originals["7413-original-7"]["reason"])
        self.assertEqual(originals["7413-original-7"]["evidence"], [
            "crates/stacks/ntcp/src/connection.rs::if let Some(cookie) = fast_open_option {",
            "crates/stacks/ntcp/src/fast_open_server_cookie_tests.rs::fn supplied_cookie_cold_limits_options_and_real_mss_learning()",
        ])

    def test_ack_repair_limits_retain_complete_clause_as_todo(self):
        rows = {r["id"]: r for r in ledger()["paragraphs"]}
        repair = rows["7413-perform-ack-repair"]
        self.assertEqual(repair["status"], "TODO")
        self.assertEqual(repair["reason"], rows["7413-first-ack-all-repair"]["reason"])
        self.assertEqual(repair["evidence"], [
            "crates/stacks/ntcp/src/connection.rs::fn establish(",
            "crates/stacks/ntcp/src/fast_open_connection_tests.rs::fn syn_data_ack_bounds_wrap_partial_retry_and_flush()",
            "crates/stacks/ntcp/src/fast_open_connection_tests.rs::fn scalar_fast_open_repair_stops_at_negotiated_cwnd()",
            "crates/stacks/ntcp/src/fast_open_connection_tests.rs::fn reserved_fast_open_repair_stops_at_negotiated_cwnd()",
        ])

    def test_synack_timeout_attaches_selected_early_response_evidence(self):
        row = next(r for r in ledger()["paragraphs"] if r["id"] == "7413-synack-timeout")
        self.assertEqual(row["status"], "covered")
        self.assertEqual(row["evidence"][1],
                         "crates/stacks/ntcp/src/connection_early_response_tests.rs::fn early_response_actual_syn_retry_anchor_and_ack_handoff()")
        # Preserve the cold cookie-request assertions as additional evidence.
        annotations = audit.source_annotations((ROOT / "crates/stacks/ntcp/src/fast_open_tests.rs").read_text())
        self.assertTrue(any(a["kind"] == "TEST" and audit.clause_key(a) == audit.clause_key(row)
                            and "fn rfc7413_cookie_request_length_and_both_timeout_fallbacks()" in a["attached"]
                            for a in annotations))

    def test_every_operative_has_exact_spec_disposition_and_attached_evidence(self):
        rows = ledger()["paragraphs"]
        self.assertEqual(len(rows), len({r["id"] for r in rows}))
        manual = [entry for suffix in ("additions", "todos")
                  for entry in audit.toml_entries(ROOT / f"duvet/rfc7413-{suffix}.toml")]
        self.assertEqual(Counter(audit.clause_key(r) for r in rows if r["status"] != "context"),
                         Counter(audit.clause_key(r) for kind, r in manual if kind == "SPEC"))
        for row in rows:
            self.assertTrue(row["reason"].strip())
            self.assertNotIn("level", row)
            if row["status"] == "context":
                self.assertNotIn("evidence", row)
                continue
            self.assertEqual(row["target"], f"{PREFIX}7413#" +
                             ("section-" if row["section"][0].isdigit() else "appendix-") + row["section"])
            dispositions = [(kind, r["reason"]) for kind, r in manual
                            if kind != "SPEC" and audit.clause_key(r) == audit.clause_key(row)]
            if row["status"] in ("TODO", "exception"):
                self.assertEqual(dispositions, [(row["status"].upper(), row["reason"])])
            else:
                self.assertEqual(row["status"], "covered")
                self.assertEqual(dispositions, [])
                self.assertEqual(len(row["evidence"]), 2)
            for i, evidence in enumerate(row.get("evidence", [])):
                path, anchor = evidence.split("::", 1)
                if i > 0:
                    self.assertTrue(anchor.startswith("fn "), row["id"])
                annotations = audit.source_annotations((ROOT / path).read_text())
                matches = [a for a in annotations if audit.clause_key(a) == audit.clause_key(row)
                           and anchor in a["attached"]]
                self.assertTrue(any(a["kind"] == ("CITATION" if i == 0 else "TEST") for a in matches), row["id"])
                if row["status"] == "TODO":
                    self.assertTrue(any(a["reason"] == row["reason"] for a in matches), row["id"])

    def test_nonkeyword_procedures_and_real_policy_gaps_cannot_be_context_or_exceptions(self):
        rows = {r["id"].removeprefix("7413-"): r for r in ledger()["paragraphs"]}
        groups = {
            "wire": ["option-layout", "minimum-nonempty-cookie", "unaligned-cookie", "ignore-invalid-and-nonsyn"],
            "cookies": ["mac-address", "mac-secret", "mac-cost", "mac-expiration", "is-cookie-valid", "cookie-cache-pair", "mss-cache"],
            "negative": ["negative-cache", "negative-causes", "negative-scope", "request-timeout-fallback", "request-retry-period"],
            "client": ["send-syn", "option-space-fallback", "send-state-sequence", "client-cache-update", "client-ack", "client-established", "first-ack-all-repair"],
            "server": ["server-disabled", "server-limit", "server-invalid", "server-notify-pending", "server-synack-ack", "server-synreceived", "server-iw", "synack-timeout", "server-final-ack", "reset-monitor"],
            "api": ["api-implicit-connect", "api-blocking", "api-nonblock-hit", "api-nonblock-miss", "api-connect-errno", "api-passive-enable", "api-threshold-cookie", "api-early-accept"],
        }
        for group, ids in groups.items():
            for id in ids:
                with self.subTest(group=group, row=id):
                    self.assertIn(rows[id]["status"], ("covered", "TODO"))
        for id in ("mac-cost", "mac-expiration", "is-cookie-valid", "ignore-invalid-and-nonsyn",
                   "request-cache-spurious", "request-retry-period", "first-ack-all-repair", "server-iw",
                   "simultaneous", "api-connect-errno", "api-threshold-cookie"):
            self.assertEqual(rows[id]["status"], "TODO")
        self.assertIn("LinuxSipHash24", rows["mac-expiration"]["reason"])
        self.assertIn("no enforced timed", rows["mac-expiration"]["reason"])
        for id in ("replay-app", "app-reuse", "farm-key", "nat-timestamp-cookie", "aes-example",
                   "cross-connection-cc-disable", "synack-payload-delay", "api-active-option-alternative"):
            self.assertEqual(rows[id]["status"], "exception")
        self.assertIn("crates/adapters/ntcp-socket/", rows["api-early-accept"]["evidence"][0])

    def test_verified_errata_are_explicit_without_rewriting_published_quotes(self):
        document = ledger()
        rows = {r["id"].removeprefix("7413-"): r for r in document["paragraphs"]}
        review = document["errata_review"]
        self.assertEqual(review["verified"], [4238, 4239, 5373, 8013, 8016])
        self.assertEqual(review["held_for_document_update"], [8014, 8015, 8017])
        self.assertEqual(review["rejected"], [6239])
        for id, erratum in (("option-layout", 4238), ("length-erratum", 4239), ("negative-scope", 5373)):
            row = rows[id]
            self.assertEqual(row["status"], "covered")
            self.assertEqual(row["errata"], [erratum])
            self.assertIn("Verified erratum", row["interpretation"])
            self.assertTrue(row["evidence"])
        self.assertIn("Length field of 0", rows["length-erratum"]["quote"])
        self.assertIn("Length 2", rows["length-erratum"]["interpretation"])
        self.assertIn("range 6 to 18", rows["option-layout"]["quote"])
        self.assertIn("source and destination IP addresses and ports", rows["negative-scope"]["quote"])
        self.assertIn("536 bytes", rows["original-7"]["quote"])
        self.assertEqual(rows["original-7"]["status"], "TODO")
        self.assertIn("Rejected erratum 6239 is not applied", rows["withhold-response-defense"]["reason"])


if __name__ == "__main__":
    unittest.main()
