"""Regression contracts for the two full operative T2 inventories.

Section hashes pin all normalized, page-furniture-free official section text,
including prose without BCP14 keywords. Fresh raw provenance is independently
checked by check_annotation_inventory.py --generate. Semantic closure still
requires reviewing the implementation and complete executable assertions.
"""
from collections import Counter, defaultdict
import json
import unittest

import check_annotation_inventory as audit
from rfc_scopes import ORIGINAL_RFCS, PREFIX, ROOT, check_registration


SECTION_HASHES = {
    6191: {
        "1": "39e80917fed1a1291d69549f65feb2996ffc58160abb80d864835b5b2ffa5b25",
        "2": "c449294c28855e254345f9dfc3a83154b98e725c7a51e7fd7734a252f92685ce",
        "3": "8884f20ff784e857defb79fe5f5b5174ddbc0b00ed730e40de90093ab5888633",
        "4": "b20fbd01b9aa72385ec97e2683b7c1c44c6168607166610c1a9c5f5eb07fbdf9",
        "5": "8f32b82dfc9b1879c9eec389ee5e55ae7fae60fa59f0d58c145ee53e7aba9247",
        "6": "60a6a298e21d13393a9d84e917a085599dde800416047147cb20762dbc6d94c3",
        "7.1": "18a8177f412f2366f77c71f48fcb738162bf339064ea438e184a0f4cc66fa7d1",
        "7.2": "c6b8162224a763de4a3b9792c1ad2c8d215eaa9cd3a35c143d5a97685a4e4731",
        "A.1": "b8b07599e45c92ca31f8a35a07e584ad802ac2175633eea75b628c17422839ed",
    },
    6429: {
        "1": "05755e6a35629ff640db2985348585c33b8c400a0938d04371f912dbe6f18cc2",
        "1.1": "e57a1dc78a9cf2cb7d01f77a3f42485e64f731ded2d392ca9effd599dc2e6f6f",
        "2": "2632ff970a10f52ac94cd269b33b47bcd75677adc035d50af8614a91cf8e7ab9",
        "3": "b6c5a1b74e4655eeda094a84932c7f602732e3b3588118372eabd0895cfbca4e",
        "4": "e3d294adb0124a3fd97bc6e80ab1da2b9a7b97dfbc093c2eb31653cf306f7113",
        "5": "b84e9c76b05e16aa7ae89998e9403987b63c24029bcb78a88ff9aba83257f824",
        "6": "1127935ac6e7fea03849ae88c036ea812162905eebed9a23e2796f1a97d10cf8",
        "7.1": "f7af69feae5802ef01ba3f31ad372ea97eeffed1062b744ccc3ecbdb9c86c817",
        "7.2": "49b1ce91448d7d027c8c193239c0baa72bcb35a88f834c7b8fd208b4d2fca54e",
    },
}


def ledger(n):
    return json.loads((ROOT / f"duvet/rfc{n}-inventory.json").read_text())


class TimeWaitPersistInventories(unittest.TestCase):
    def test_registration_status_and_manual_full_operative_scope(self):
        scopes = check_registration()
        self.assertEqual(set(scopes), set(ORIGINAL_RFCS) | {6191, 6429, 791, 1122, 6864, 3542, 8200, 826})
        for n, status, sha in (
            (6191, "Best Current Practice", "974f45f076be09e8be66ef8b12e9b5a99ba95b43251502b08539fc53d9347211"),
            (6429, "Informational", "f2d371ecfeb49168b72a86e863a88fb3593fa90a2548b07fa2ead6cff68b6fcf"),
        ):
            with self.subTest(rfc=n):
                scope, document = scopes[n], ledger(n)
                self.assertEqual(scope["extraction"], "manual")
                self.assertEqual(scope["scope_kind"], "full-operative")
                for field in ("scope", "scope_kind", "document_status"):
                    self.assertEqual(document[field], scope[field])
                self.assertEqual(document["document_status"], status)
                self.assertEqual(document["text_sha256"], sha)

    def test_every_section_body_is_preserved_without_keyword_extraction(self):
        for n, expected in SECTION_HASHES.items():
            sections = defaultdict(list)
            rows = ledger(n)["paragraphs"]
            fallback = next((r for r in rows if r["id"] == "6191-otherwise-drop"), None)
            for row in rows:
                if row["id"] == "6429-receive-window-permission":
                    # The source has no space between the opening quotation
                    # mark in the attribution and the quoted "A TCP" sentence.
                    sections[row["section"]][-1] += row["quote"]
                else:
                    sections[row["section"]].append(row["quote"])
                # The identical drop clause occurs twice but has one SPEC key.
                # Restore its second occurrence in official document order.
                if row["id"] == "6191-no-old-ts-no-new-ts":
                    self.assertEqual(fallback["occurrences"], 2)
                    sections[row["section"]].append(fallback["quote"])
            actual = {s: audit.digest(audit.norm(" ".join(parts)).encode())
                      for s, parts in sections.items()}
            self.assertEqual(actual, expected, f"RFC{n}: omitted or altered complete section text")

    def test_all_seven_reuse_branches_and_literal_gaps_remain_explicit(self):
        rows = {r["id"].removeprefix("6191-"): r for r in ledger(6191)["paragraphs"]}
        expected = {
            "old-ts-newer-ts": "covered", "old-ts-equal-ts": "covered",
            "old-ts-no-new-ts": "covered", "otherwise-drop": "covered",
            "no-old-ts-new-ts": "covered", "no-old-ts-no-new-ts": "covered",
            "bilateral-definition": "covered", "fin-definition": "covered",
            "paws-monotonic": "covered", "processing-boundary": "covered",
            "stale-ts-fallback": "covered", "isn-independence": "covered",
            "boot-quiet-time": "exception",
        }
        self.assertEqual({key: r["status"] for key, r in rows.items() if r["status"] != "context"}, expected)
        self.assertEqual(rows["otherwise-drop"]["branches"],
                         ["old-timestamps-otherwise", "no-old-timestamps-otherwise"])
        self.assertEqual(rows["otherwise-drop"]["occurrences"], 2)
        branches = ("old-ts-newer-ts", "old-ts-equal-ts", "old-ts-no-new-ts",
                    "otherwise-drop", "no-old-ts-new-ts", "no-old-ts-no-new-ts",
                    "stale-ts-fallback", "isn-independence")
        for key in branches:
            with self.subTest(clause=key):
                self.assertEqual(rows[key]["evidence"][1],
                                 "crates/stacks/ntcp/src/endpoint_tests.rs::fn rfc6191_data_bearing_syn_uses_freshness_and_passive_authorization()")
        self.assertIn("strict serial comparison is against FIN itself", rows["fin-definition"]["reason"])
        self.assertTrue(any("rfc6191_sequence_reuse_uses_peer_fin_serial_frontier" in e
                            for e in rows["fin-definition"]["evidence"]))
        # T20 closes the PAWS prerequisite and the processing boundary, each
        # with its whole quote and a source/test pair.
        for key, (facts, evidence) in {
            "paws-monotonic": (
                ("CLOCK_BOOTTIME provider", "rejects decreasing samples", "Endpoint::check_clock",
                 "constant per-connection offset", "inherits the old incarnation's offset"),
                ["crates/stacks/ntcp/src/endpoint.rs::fn check_clock(",
                 "crates/stacks/ntcp/src/endpoint_time_wait_tests.rs::fn timestamps_sent_on_a_connection_and_its_reincarnation_never_decrease()"]),
            "processing-boundary": (
                ("reopen_time_wait", "reuse_syn", "Timestamps option", "CLOSED, LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK and CLOSING",
                 "timestamp and sequence variants"),
                ["crates/stacks/ntcp/src/endpoint.rs::if self.config.reuse_time_wait",
                 "crates/stacks/ntcp/src/endpoint_time_wait_tests.rs::fn reuse_toggle_preserves_non_time_wait_states_and_non_request_flags()"]),
        }.items():
            with self.subTest(clause=key):
                for fact in facts:
                    self.assertIn(fact, rows[key]["reason"])
                self.assertNotIn("T20", rows[key]["reason"])
                self.assertEqual(rows[key]["evidence"], evidence)
        # The boot quiet time is a deliberate Linux-compatible deviation: no
        # evidence is claimed and no source or test annotation cites it.
        quiet = rows["boot-quiet-time"]
        self.assertIn("2*MSL", quiet["quote"])
        self.assertNotIn("evidence", quiet)
        for fact in ("Linux-compatible", "no startup quiet time", "no earlier incarnation",
                     "RFC 9293 section 3.4.1", "timestamp offsets (PAWS)", "TIME-WAIT"):
            self.assertIn(fact, quiet["reason"])
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                self.assertNotEqual(audit.clause_key(annotation), audit.clause_key(quiet), str(path))
        # Monotonicity also has the provider's own decreasing-sample tests.
        for path, anchor, key in (
            ("crates/adapters/ntcp-clock/src/transport_tests.rs",
             "fn decreasing_samples_are_rejected_and_the_reference_stays()", "paws-monotonic"),
        ):
            self.assertTrue(any(a["kind"] == "TEST" and audit.clause_key(a) == audit.clause_key(rows[key])
                                and anchor in a["attached"]
                                for a in audit.source_annotations((ROOT / path).read_text())), path)
        # Check every full-quote copy, including annotations not selected as the
        # ledger's primary evidence. Repaired behavior must not retain old gaps.
        closed = {audit.clause_key(rows[key]) for key, status in expected.items() if status == "covered"}
        for path in (ROOT / "crates/stacks/ntcp/src").glob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                if audit.clause_key(annotation) in closed:
                    reason = annotation.get("reason", "")
                    for obsolete in ("rejecting FIN+1", "bypasses reopen_time_wait",
                                     "SYNs without payload", "complete clause remains TODO"):
                        self.assertNotIn(obsolete, reason, str(path))
        persist = ledger(6429)["paragraphs"]
        self.assertEqual(Counter(r["status"] for r in persist),
                         Counter(context=16, covered=9, exception=2))
        self.assertEqual({r["id"] for r in persist if r["status"] == "exception"},
                         {"6429-resource-manager-action", "6429-application-attack-detection"})
        termination = next(r for r in persist if r["id"] == "6429-allow-requested-termination")
        self.assertIn("rfc6429_explicit_abort_of_responsive_zero_window_connection", termination["evidence"][1])

    def test_operatives_dispositions_and_attached_evidence_match(self):
        for n in (6191, 6429):
            rows = [r for r in ledger(n)["paragraphs"] if r["status"] != "context"]
            manual = [entry for suffix in ("additions", "todos")
                      for entry in audit.toml_entries(ROOT / f"duvet/rfc{n}-{suffix}.toml")]
            self.assertEqual(Counter(audit.clause_key(r) for r in rows),
                             Counter(audit.clause_key(r) for kind, r in manual if kind == "SPEC"))
            for row in rows:
                self.assertTrue(row["target"].startswith(f"{PREFIX}{n}#"))
                self.assertNotIn("level", row)
                if row["status"] in ("TODO", "exception"):
                    dispositions = [r for kind, r in manual if kind == row["status"].upper()
                                    and audit.clause_key(r) == audit.clause_key(row)]
                    self.assertEqual([r["reason"] for r in dispositions], [row["reason"]])
                if row["status"] == "covered":
                    self.assertEqual(len(row["evidence"]), 2)
                for i, evidence in enumerate(row.get("evidence", [])):
                    path, anchor = evidence.split("::", 1)
                    matches = [a for a in audit.source_annotations((ROOT / path).read_text())
                               if audit.clause_key(a) == audit.clause_key(row) and anchor in a["attached"]]
                    self.assertTrue(any(a["kind"] == ("CITATION" if i == 0 else "TEST") for a in matches), row["id"])
                    if row["status"] == "TODO":
                        self.assertTrue(any(a["reason"] == row["reason"] for a in matches), row["id"])

    def test_rfc9293_time_wait_duration_is_a_recorded_exception(self):
        # TIME-WAIT lasts the configured duration, 120 s by default and 60 s
        # with Linux's defaults, rather than 2xMSL: an extracted requirement
        # closed only by its exception, which no source or test annotation
        # cites.
        manifest = json.loads((ROOT / "duvet/extracted-requirements.json").read_text())
        must = [r for r in manifest["rfcs"]["9293"]["requirements"] if "(MUST-13)" in r["quote"]]
        self.assertEqual(len(must), 1)
        key = audit.clause_key(must[0])
        exceptions = [r for kind, r in audit.toml_entries(ROOT / "duvet/rfc9293-todos.toml")
                      if kind == "EXCEPTION" and audit.clause_key(r) == key]
        self.assertEqual(len(exceptions), 1)
        for fact in ("ConnectionConfig::time_wait_us", "120 s by default", "MSL of 60 s",
                     "for example for benchmarks", "TCP_TIMEWAIT_LEN",
                     "ntcp_native::NetworkConfig::new", "zero is refused",
                     "RFC 6191 timestamp-based TIME-WAIT reuse is unchanged"):
            self.assertIn(fact, exceptions[0]["reason"])
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                self.assertNotEqual(audit.clause_key(annotation), key, str(path))

    def test_rfc9293_time_wait_reopen_is_a_recorded_exception(self):
        # A reopening SYN ends the old TIME-WAIT at once, as Linux does, so
        # condition (2) of MAY-2 (return to TIME-WAIT after an old duplicate)
        # is not met: an extracted requirement closed only by its exception,
        # which no source or test annotation cites.
        manifest = json.loads((ROOT / "duvet/extracted-requirements.json").read_text())
        may = [r for r in manifest["rfcs"]["9293"]["requirements"] if "(MAY-2)" in r["quote"]]
        self.assertEqual(len(may), 1)
        key = audit.clause_key(may[0])
        exceptions = [r for kind, r in audit.toml_entries(ROOT / "duvet/rfc9293-todos.toml")
                      if kind == "EXCEPTION" and audit.clause_key(r) == key]
        self.assertEqual(len(exceptions), 1)
        for fact in ("EndpointConfig::reuse_time_wait", "RFC 6191", "condition (1)",
                     "TCP_TW_SYN", "Condition (2) is not met",
                     "leaves the TIME-WAIT unchanged"):
            self.assertIn(fact, exceptions[0]["reason"])
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in audit.source_annotations(path.read_text()):
                self.assertNotEqual(audit.clause_key(annotation), key, str(path))


if __name__ == "__main__":
    unittest.main()
