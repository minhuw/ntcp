"""Original TCP gap identities, retained gaps and complete closure evidence.

These are inventory regressions, not whole-clause conformance tests. The keys
pin the original target + newline + whitespace-normalized complete quotation.
The canonical reasons live in the TODO TOML; every full-quote reason copy is
checked, including copies outside the explicitly required evidence links.
"""
from copy import deepcopy
import json
import unittest

import check_annotation_inventory as audit
from rfc_scopes import ROOT


TCP = "crates/stacks/ntcp/"
OBLIGATIONS = (
    {
        "rfc": 3168,
        "original_key": "ddd588df16af14ad026b5a10e3035f6be80107b07362bdc9893c92c0119ead35",
        "target": "https://www.rfc-editor.org/rfc/rfc3168#section-6.1.1",
        "quote": "If the TCP connection does not wish to use ECN notification for a particular packet, the sending TCP sets the ECN codepoint to not-ECT, and the TCP receiver ignores the CE codepoint in the received packet.",
        "links": (
            (TCP + "src/connection.rs", "CITATION", "let ece = self.ecn_feedback()"),
            (TCP + "src/connection.rs", "CITATION", "let ecn = if fresh_data && self.ecn_send()"),
            (TCP + "src/endpoint_tests.rs", "TEST", "fn classic_ecn_opt_out_and_syn_timeout_fallback()"),
        ),
        "reason_fragments": (
            "no implicit enablement or echo", "section 6.1.6", "Sender Not-ECT outputs",
            "cannot recover an overwritten original Not-ECT from CE alone",
            "universal per-packet ignore applicability is not proven",
            "Rejected errata 3636/3680 do not waive the original text",
        ),
    },
    {
        "rfc": 5681,
        "original_key": "5c3bd9cca729b33883dffd55253947a7469861d9ff0366f3daa1b0d292348234",
        "target": "https://www.rfc-editor.org/rfc/rfc5681#section-4.3",
        "quote": "Second, until all lost segments in the window of data in question are repaired, the number of segments transmitted in each RTT MUST be no more than half the number of outstanding segments when the loss was detected.",
        "links": (
            (TCP + "src/connection.rs", "CITATION", "&& let Some(recovery) = self.sack_recovery"),
            (TCP + "src/connection_output_tests.rs", "TEST", "fn half_flight_segment_output_observations()"),
        ),
        "reason_fragments": (
            "NewReno emits one full-SMSS retry in each of the first two recovery RTTs",
            "without duplex SACK output emits five full-SMSS retries",
            "12-byte outgoing SACK option", "budget33/SMSS13 emits 53 one-byte retries",
            "before any retry RTT completes", "budget148/SMSS128 emits nine packets",
            "while holes remain", "do not prove RFC5681 section4.3 literal half-flight packet count",
            "RFC8985 section9.3 does not waive congestion control",
            "General small-flight/lost-copy multi-RTT packet-count proof remains unestablished",
        ),
    },
    {
        "rfc": 7323,
        "original_key": "c337fd1595ffe79ed8d458c6811337919922c1a3592b455096360e166bbb1834",
        "target": "https://www.rfc-editor.org/rfc/rfc7323#section-5.7",
        "quote": "Setting the DF bit implies the use of Path MTU Discovery as described\nin [RFC1191], [RFC1981], and [RFC4821]; thus, any TCP implementation\nthat implements PAWS MUST also implement Path MTU Discovery.",
        "closed": True,
        "links": (
            (TCP + "examples/tun_echo.rs", "CITATION", "fn runtime_config("),
            (TCP + "examples/tun_echo.rs", "CITATION", "fn input_frame("),
            (TCP + "examples/support/tun_echo_pmtu_tests.rs", "TEST", "fn runtime_mtu_and_option_selection()"),
            (TCP + "examples/support/tun_echo_pmtu_tests.rs", "TEST", "fn runtime_ptb_repairs_and_receiver_ack_progress()"),
            (TCP + "examples/support/tun_echo_pmtu_tests.rs", "TEST", "fn runtime_icmp_blackhole_falls_back_with_paws_and_congestion_response()"),
            (TCP + "examples/support/tun_echo_pmtu_tests.rs", "TEST", "fn runtime_dispatch_rejects_uncorrelated_or_malformed_feedback()"),
            (TCP + "examples/support/tun_echo_pmtu_tests.rs", "TEST", "fn runtime_ptb_does_not_overwrite_a_committed_blocked_frame()"),
        ),
        "reason_fragments": (
            "queries and validates the real backend MTU", "enables PMTUD with or without PAWS",
            "dispatches checksummed ICMP PTB", "live tuple/sequence/exact-packet validation",
            "timestamp negotiation, IPv4 DF", "bounded IPv4/IPv6 repairs",
            "receiver/ACK byte progress", "rejected feedback", "committed-output retention",
            "ICMP-blackhole R1 fallback with ordinary congestion response",
            "subsequent ACK-confirmed probing", "not arbitrary external embeddings",
            "native IPv6 sockets or a full host ICMP service",
        ),
    },
)


def inventory_records():
    records = []
    extracted = json.loads((ROOT / "duvet/extracted-requirements.json").read_text())
    for document in extracted["rfcs"].values():
        for row in document["requirements"]:
            records.append({**row, "kind": "SPEC", "path": "duvet/extracted-requirements.json", "attached": ""})
    # Inspect all annotation files, not just the required links: an additional
    # full-quote copy must not retain a stale reason unnoticed.
    for path in sorted((ROOT / "duvet").glob("*.toml")):
        for kind, row in audit.toml_entries(path):
            records.append({**row, "kind": kind, "path": path.relative_to(ROOT).as_posix(), "attached": ""})
    for path in sorted((ROOT / "duvet").glob("rfc*-inventory.json")):
        for row in json.loads(path.read_text())["paragraphs"]:
            records.append({**row, "kind": row["status"].upper(),
                            "path": path.relative_to(ROOT).as_posix(), "attached": ""})
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        for row in audit.source_annotations(path.read_text()):
            records.append({**row, "path": path.relative_to(ROOT).as_posix()})
    return records


class RemainingTcpGaps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = inventory_records()

    def assert_retained_contract(self, records):
        for obligation in OBLIGATIONS:
            key = audit.clause_key(obligation)
            self.assertEqual(audit.digest((key[0] + "\n" + key[1]).encode()), obligation["original_key"])
            todos = [r for r in records if r["kind"] == "TODO"
                     and r["path"] == f"duvet/rfc{obligation['rfc']}-todos.toml"
                     and audit.clause_key(r) == key]
            closed = obligation.get("closed", False)
            self.assertEqual(len(todos), 0 if closed else 1,
                             f"{obligation['original_key']}: original disposition changed")
            citations = [r for r in records if r["kind"] == "CITATION" and audit.clause_key(r) == key]
            reason = citations[0].get("reason", "") if closed else todos[0]["reason"]
            for fragment in obligation["reason_fragments"]:
                self.assertIn(fragment, reason)
            spec_path = ("duvet/rfc3168-additions.toml" if obligation["rfc"] == 3168
                         else "duvet/extracted-requirements.json")
            specs = [r for r in records if r["kind"] == "SPEC"
                     and r["path"] == spec_path and audit.clause_key(r) == key]
            self.assertEqual(len(specs), 1, "original complete SPEC must survive")
            # Match on the full quote even if somebody changes its target.
            copies = [r for r in records if audit.norm(r["quote"]) == key[1]]
            if closed:
                self.assertEqual([r["path"] for r in copies if r["kind"] == "SPEC"], [spec_path],
                                 "closure must preserve exactly the original SPEC location")
                self.assertTrue(all(r["kind"] in ("SPEC", "CITATION", "TEST") for r in copies),
                                "complete closure cannot retain TODO or introduce an exception")
                for stale in ("ConnectionConfig retains default pmtud=None",
                              "input_frame dispatches TCP only", "lacks discovery in its PAWS/DF profile"):
                    self.assertNotIn(stale, reason)
            for row in copies:
                self.assertEqual(row.get("target"), key[0], row["path"])
                self.assertNotEqual(row["kind"], "EXCEPTION", "retained gap cannot become an exception")
                if row["kind"] != "SPEC":
                    self.assertEqual(row.get("reason"), reason, f"stale/missing full-quote reason: {row['path']}")
            for path, kind, anchor in obligation["links"]:
                self.assertTrue(any(r["path"] == path and r["kind"] == kind
                                    and anchor in r["attached"] for r in copies),
                                f"missing complete-quote partial {kind}: {path}::{anchor}")

    def test_three_original_keys_dispositions_and_all_reason_copies(self):
        self.assertEqual({o["rfc"] for o in OBLIGATIONS}, {3168, 5681, 7323})
        self.assert_retained_contract(self.records)

    def test_removed_narrowed_or_excepted_todo_is_rejected(self):
        for obligation in OBLIGATIONS:
            if obligation.get("closed"):
                continue
            key = audit.clause_key(obligation)
            for mutation in ("remove", "narrow", "exception"):
                with self.subTest(rfc=obligation["rfc"], mutation=mutation):
                    records = deepcopy(self.records)
                    row = next(r for r in records if r["kind"] == "TODO" and audit.clause_key(r) == key)
                    if mutation == "remove":
                        records.remove(row)
                    elif mutation == "narrow":
                        row["quote"] = row["quote"].split(",", 1)[0]
                    else:
                        row["kind"] = "EXCEPTION"
                    with self.assertRaises(AssertionError):
                        self.assert_retained_contract(records)

    def test_closed_original_spec_and_complete_evidence_are_required(self):
        obligation = next(o for o in OBLIGATIONS if o.get("closed"))
        key = audit.clause_key(obligation)
        for mutation in ("remove SPEC", "narrow SPEC", "move SPEC", "duplicate SPEC", "TODO", "stale reason"):
            with self.subTest(mutation=mutation):
                records = deepcopy(self.records)
                spec = next(r for r in records if r["kind"] == "SPEC" and audit.clause_key(r) == key)
                if mutation == "remove SPEC":
                    records.remove(spec)
                elif mutation == "narrow SPEC":
                    spec["quote"] = spec["quote"].split(";", 1)[0]
                elif mutation == "move SPEC":
                    spec["path"] = "duvet/rfc7323-additions.toml"
                elif mutation == "duplicate SPEC":
                    records.append(dict(spec))
                elif mutation == "TODO":
                    records.append({**spec, "kind": "TODO", "path": "duvet/rfc7323-todos.toml"})
                else:
                    for row in records:
                        if row["kind"] != "SPEC" and row.get("target") == key[0] and audit.norm(row["quote"]) == key[1]:
                            row["reason"] = "ConnectionConfig retains default pmtud=None"
                with self.assertRaises(AssertionError):
                    self.assert_retained_contract(records)

    def test_missing_or_narrowed_partial_link_is_rejected(self):
        for obligation in OBLIGATIONS:
            key = audit.clause_key(obligation)
            for path, kind, anchor in obligation["links"]:
                for mutation in ("remove", "narrow", "detach"):
                    with self.subTest(rfc=obligation["rfc"], anchor=anchor, mutation=mutation):
                        records = deepcopy(self.records)
                        row = next(r for r in records if r["path"] == path and r["kind"] == kind
                                   and audit.clause_key(r) == key and anchor in r["attached"])
                        if mutation == "remove":
                            records.remove(row)
                        elif mutation == "narrow":
                            row["quote"] = row["quote"].split(",", 1)[0]
                        else:
                            row["attached"] = ""
                        with self.assertRaises(AssertionError):
                            self.assert_retained_contract(records)

    def test_unlisted_full_quote_copy_cannot_have_missing_or_stale_reason(self):
        # Reproduce the missed-fourth-copy failure class without a disk fixture.
        for obligation in OBLIGATIONS:
            key = audit.clause_key(obligation)
            for mutation in ("stale", "missing", "target", "exception"):
                with self.subTest(rfc=obligation["rfc"], mutation=mutation):
                    extra = dict(next(r for r in self.records if r["kind"] == "CITATION"
                                      and audit.clause_key(r) == key))
                    extra.update(path="crates/unlisted_partial.rs", attached="fn other_evidence() {}")
                    if mutation == "stale":
                        extra["reason"] = "Byte credit proves the whole obligation."
                    elif mutation == "missing":
                        extra.pop("reason")
                    elif mutation == "target":
                        extra["target"] += ".1"
                    else:
                        extra["kind"] = "EXCEPTION"
                    with self.assertRaises(AssertionError):
                        self.assert_retained_contract([*self.records, extra])


if __name__ == "__main__":
    unittest.main()
