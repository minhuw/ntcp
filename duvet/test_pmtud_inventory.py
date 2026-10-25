import hashlib
import json
from pathlib import Path
import re
import tomllib
import unittest

from check_rfc_coverage import PREFIX, check
from test_rfc_coverage import complete_report

ROOT = Path(__file__).resolve().parent.parent
RFCS = (1191, 8201, 4821, 5927)


def normalize(text):
    # Published text page furniture is not part of a clause. Do not fix spelling,
    # hyphens, numbers or punctuation when checking exact quotations.
    lines = [line for line in text.splitlines()
             if not re.match(r"^(Mogul & Deering|McCann, et al\.|Mathis & Heffner|Gont)\s", line)
             and not re.match(r"^RFC (1191|8201|4821|5927)\s", line)]
    return " ".join("\n".join(lines).split())


class PmtudInventory(unittest.TestCase):
    def inventory(self, rfc):
        return json.loads((ROOT / f"duvet/rfc{rfc}-inventory.json").read_text())

    def test_registration_and_document_status(self):
        config = tomllib.loads((ROOT / "duvet/duvet.toml").read_text())
        sources = {s["source"] for s in config["specification"]}
        self.assertTrue({f"{PREFIX}{n}" for n in RFCS} <= sources)
        self.assertNotIn(f"{PREFIX}1981", sources)
        self.assertNotIn(f"{PREFIX}8899", sources)
        self.assertIn("obsoletes RFC1981", self.inventory(8201)["scope"])
        self.assertEqual(self.inventory(5927)["document_status"], "Informational")
        summaries, errors = check(complete_report())
        self.assertFalse(errors)
        self.assertEqual(summaries["5927"]["document_status"], "Informational")
        for n in (1191, 8201, 4821):
            self.assertEqual(self.inventory(n)["document_status"], "Standards Track")

    def test_inventory_dispositions_match_exact_additions_and_todos(self):
        # Counts pin the reviewed inventory, including prose without BCP14 words.
        expected = {1191: (126, 80), 8201: (114, 54),
                    4821: (215, 104), 5927: (257, 55)}
        for n in RFCS:
            inv = self.inventory(n)
            rows = inv["paragraphs"]
            operative = [p for p in rows if p["status"] != "context"]
            self.assertEqual((len(rows), len(operative)), expected[n], n)
            self.assertEqual(len({p["id"] for p in rows}), len(rows))
            additions = tomllib.loads((ROOT / f"duvet/rfc{n}-additions.toml").read_text())["spec"]
            todos = tomllib.loads((ROOT / f"duvet/rfc{n}-todos.toml").read_text())
            key = lambda p: (p["target"], " ".join(p["quote"].split()))
            self.assertEqual({key(p) for p in operative}, {key(p) for p in additions})
            self.assertTrue(all("level" not in p for p in additions))
            for status in ("TODO", "exception"):
                self.assertEqual({key(p) for p in operative if p["status"] == status},
                                 {key(p) for p in todos.get(status, [])})
            by_id = {p["id"]: p for p in rows}
            for p in rows:
                if "parent" in p:
                    parent = by_id[p["parent"]]
                    self.assertEqual(parent["status"], "context", p["id"])
                    self.assertIn(p["quote"], parent["quote"], p["id"])
                    self.assertEqual(p["section"], parent["section"], p["id"])
                self.assertIn(p["status"], ("context", "covered", "TODO", "exception"))
                self.assertTrue(p["reason"].strip(), p["id"])
                if p["status"] == "covered":
                    self.assertEqual(len(p["evidence"]), 2)
                    for is_test, evidence in enumerate(p["evidence"]):
                        path, anchor = evidence.split("::", 1)
                        source = (ROOT / path).read_text()
                        self.assertIn(anchor, source, p["id"])
                        blocks = re.split(r"(?m)^\s*//= (?=https://)", source)[1:]
                        matching = []
                        for block in blocks:
                            if block.splitlines()[0].strip() != p["target"]:
                                continue
                            quote = " ".join(re.findall(r"(?m)^\s*//# ?(.*)$", block))
                            if " ".join(quote.split()) == " ".join(p["quote"].split()):
                                matching.append(block)
                        self.assertTrue(matching, p["id"])
                        self.assertTrue(any(("//= type=test" in b) == bool(is_test)
                                            for b in matching), p["id"])

    def test_lowercase_algorithm_and_security_spans_cannot_disappear(self):
        required = {
            1191: ("576 octets unless", "Header Length field", "greatest plateau value",
                   "MUST not retransmit datagrams", "PMTU Discovery does not affect"),
            8201: ("must discard it", "must not increase", "less than 5 minutes",
                   "including IPv6 extension headers", "must not be considered as a congestion"),
            4821: ("implicit probe", "search_low SHOULD be raised", "SHOULD be configurable",
                   "same-sized probe", "R1 timeout threshold", "search_high to the probe size minus one",
                   "Data in the probe gap", "The saved value of eff_pmtu SHOULD be restored"),
            5927: ("SND.UNA =< SEG.SEQ < SND.NXT", "maxsizesent", "maxsizeacked",
                   '"pending error" condition is cleared', "sequence number arithmetic",
                   "claimedmtu <= MINIMUM_MTU"),
        }
        for n, fragments in required.items():
            spans = [p["quote"] for p in self.inventory(n)["paragraphs"]
                     if p["status"] != "context"]
            for fragment in fragments:
                self.assertTrue(any(fragment in q for q in spans), (n, fragment))
        # Known implementation gaps must not silently become scope exceptions.
        for n, numbers in {8201: (76,)}.items():
            rows = {p["id"]: p for p in self.inventory(n)["paragraphs"]}
            for i in numbers:
                self.assertEqual(rows[f"{n}-{i:03}"]["status"], "TODO")
        for number in (71, 119):
            row = {p["id"]: p for p in self.inventory(4821)["paragraphs"]}[f"4821-{number:03}"]
            self.assertEqual(row["status"], "covered")
            self.assertIn("destination-policy", row["reason"])
            self.assertEqual(len(row["evidence"]), 2)
        # RFC5927 documents nonstandard mitigations, not a mandatory historical
        # algorithm. Keep each selected policy deviation explicit and quoted.
        rows = {p["id"]: p for p in self.inventory(5927)["paragraphs"]}
        for i in (103, 104, 106, 108, 109):
            row = rows[f"5927-{i:03}"]
            self.assertEqual(row["status"], "exception")
            self.assertIn("Selected Informational policy deviation:", row["reason"])
            self.assertIn("historical algorithm is deliberately not selected", row["reason"])

    def test_classical_operative_closures_and_selected_alternatives(self):
        rows = {p["id"]: p for n in (1191, 8201)
                for p in self.inventory(n)["paragraphs"]}
        alternatives = tuple(f"1191-{i:03}" for i in (70, 71, 72, 73, 102, 103, 104, 107))
        expected = {
            "covered": ("1191-005a", "1191-005b", "1191-005d", "1191-006b",
                        "1191-014a", "1191-013a", "1191-013c", "1191-013e",
                        "8201-003", "8201-035", "8201-051", "8201-058",
                        "8201-068", "8201-086", "1191-069", "1191-068", "8201-069"),
            "context": ("1191-015", "1191-029", "1191-060", "1191-066"),
            "exception": ("1191-005c", "1191-006a", "1191-007", "1191-013d",
                          "1191-013f", "1191-063", "8201-025b", "8201-065",
                          *alternatives),
            # These are open obligations/evidence gaps, not expected runtime failures.
            "TODO": ("8201-004", "8201-060", "8201-076"),
        }
        for status, ids in expected.items():
            for id in ids:
                with self.subTest(id=id):
                    self.assertEqual(rows[id]["status"], status)
        for id in (*alternatives, "1191-013d", "1191-013f"):
            self.assertIn("RFC4821 section1", rows[id]["reason"], id)
        for fragment in ("set_path_mss", "retx_pending", "remaining flight"):
            self.assertIn(fragment, rows["1191-069"]["reason"])

    def test_reviewed_growth_and_ipv6_evidence_closures(self):
        rows = {p["id"]: p for n in RFCS for p in self.inventory(n)["paragraphs"]}
        scopes = {
            "1191-069": ("742e320", "only on decreases", "remaining flight", "timers"),
            "4821-111": ("742e320", "unambiguous", "path bounds", "partial ACK",
                         "Ordinary loss", "probe timeout"),
            "4821-067": ("742e320", "no-ACK", "real data RTO", "Reno and CUBIC",
                         "not full CUBIC trajectory", "allowed ACK growth"),
            "8201-033": ("819b8f2", "checksum", "stale quotes", "not authentication"),
            "8201-037": ("819b8f2", "selected security policy", "progress clearing",
                         "quoted-head RTO", "receiver ACK"),
            "8201-039": ("819b8f2", "equal/larger", "accepted 1400 decrease"),
            "8201-059": ("819b8f2", "quoted outbound tuple", "distinct local addresses",
                         "does not establish same-address per-interface isolation"),
            "8201-087": ("819b8f2", "strictly-decreasing", "before and after"),
        }
        for id, fragments in scopes.items():
            with self.subTest(id=id):
                self.assertEqual(rows[id]["status"], "covered")
                for fragment in fragments:
                    self.assertIn(fragment, rows[id]["reason"])
        # The simulation does not establish an actual on-link/ND decision
        # or same-address per-interface identity.
        for id in ("8201-031", "8201-052"):
            self.assertEqual(rows[id]["status"], "TODO")

    def test_reviewed_policy_and_isolated_cc_closures_preserve_partial_gaps(self):
        rows = {p["id"]: p for n in RFCS for p in self.inventory(n)["paragraphs"]}
        self.assertEqual({n: sum(p["status"] == "TODO"
                                 for p in self.inventory(n)["paragraphs"])
                          for n in RFCS}, {1191: 23, 8201: 16, 4821: 17, 5927: 2})
        for id in ("1191-068", "1191-095", "8201-069", "8201-084"):
            self.assertEqual(rows[id]["status"], "covered")
            for fragment in ("0030a96", "Infinity", ">=300", "Endpoint::set_pmtud_policy",
                             "independent mandatory 600-second PTB hold"):
                self.assertIn(fragment, rows[id]["reason"], id)
        expected = {
            "4821-113": ("initial_search_low", "Destination policy configuration"),
            "4821-066": ("logical window", "PRR admission", "strict extra", "deadline"),
            "4821-143": ("actual TCP RTO", "one-MSS cwnd", "five times cooldown"),
            "8201-075": ("two successively smaller router PTBs", "wrapping sequences",
                         "PTB cancellation commits"),
        }
        for id, fragments in expected.items():
            self.assertEqual(rows[id]["status"], "covered", id)
            for fragment in fragments:
                self.assertIn(fragment, rows[id]["reason"], id)
        partials = {
            "1191-099": ("runtime", "912cf80", "up-to-date reference"),
            "4821-011": ("apply_ptb cancels", "committed normal congestion response"),
            "4821-012": ("fivefold timeout hold", "integrated next-probe assertion"),
            "4821-136": ("suppression", "same-sized next probe"),
        }
        for id, fragments in partials.items():
            self.assertEqual(rows[id]["status"], "TODO", id)
            for fragment in fragments:
                self.assertIn(fragment, rows[id]["reason"], id)
        for id in ("1191-082", "8201-076", "4821-144"):
            self.assertEqual(rows[id]["status"], "TODO", id)

    def test_matching_ptb_keeps_isolated_suppression_spans_partial(self):
        rows = {p["id"]: p for p in self.inventory(4821)["paragraphs"]}
        todos = tomllib.loads((ROOT / "duvet/rfc4821-todos.toml").read_text())["TODO"]
        partial_evidence = {
            "4821-065": ("a4b9a0c", "finite preloss", "recovery/PRR exit", "nonempty flight"),
            "4821-139": ("finite preloss", "probe size minus one", "MSS decrease scaling"),
            "4821-142": ("logical window", "independent of configurable periodic aging"),
        }
        for id, fragments in partial_evidence.items():
            row = rows[id]
            for fragment in fragments:
                self.assertIn(fragment, row["reason"], id)
            self.assertEqual(row["status"], "TODO", id)
            for fragment in ("Partial no-PTB evidence", "with or without matching PTB",
                             "apply_ptb cancels", "resolve_probe_response commits",
                             "only the probe is lost", "trailing packets are delivered",
                             "IPv6 two-PTB fixture", "does not close this full span"):
                self.assertIn(fragment, row["reason"], id)
            self.assertEqual([p["reason"] for p in todos
                              if " ".join(p["quote"].split()) == row["quote"]],
                             [row["reason"]])
            # Keep the proven source/test evidence explicitly partial, not deleted.
            for evidence in row["evidence"]:
                source = (ROOT / evidence.split("::", 1)[0]).read_text()
                self.assertIn("//= reason=" + row["reason"], source)
        self.assertEqual(rows["4821-011"]["status"], "TODO")
        # 066 only requires rate limiting when suppression occurs; unlike 142,
        # it does not also require suppression for every isolated probe failure.
        self.assertEqual(rows["4821-066"]["status"], "covered")
        self.assertIn("strict extra interval/tick", rows["4821-066"]["reason"])
        counts = {n: len(tomllib.loads((ROOT / f"duvet/rfc{n}-todos.toml").read_text())
                         .get("TODO", [])) for n in RFCS}
        self.assertEqual(sum(counts.values()), 58)
        self.assertEqual(sum(len(tomllib.loads(p.read_text()).get("TODO", []))
                             for p in (ROOT / "duvet").glob("rfc*-todos.toml")), 61)

    def test_paws_discovery_gap_names_concrete_supplied_embedding(self):
        todos = tomllib.loads((ROOT / "duvet/rfc7323-todos.toml").read_text())["TODO"]
        matching = [p for p in todos if p["target"] == f"{PREFIX}7323#section-5.7"]
        self.assertEqual(len(matching), 1)
        reason = matching[0]["reason"]
        for fragment in ("crates/stacks/ntcp/examples/tun_echo.rs", "NTCP_TIMESTAMPS=1",
                         "DF", "pmtud=None", "input_frame", "TCP only", "ICMP PTB"):
            self.assertIn(fragment, reason)

    def test_all_inventory_quotes_match_official_text_when_cached(self):
        for n in RFCS:
            with self.subTest(rfc=n):
                path = ROOT / f"workbench/pmtud/rfcs/rfc{n}.txt"
                if not path.exists():
                    self.skipTest("Official RFC cache is agent-local; fetch RFC Editor texts to run provenance check")
                raw = path.read_bytes()
                inv = self.inventory(n)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), inv["text_sha256"])
                official = normalize(raw.decode("utf-8-sig"))
                for p in inv["paragraphs"]:
                    self.assertIn(" ".join(p["quote"].split()), official, p["id"])

    def test_errata_dispositions_are_not_silently_applied_as_new_norms(self):
        expected = {1191: [(9093, "Verified")], 8201: [],
                    4821: [(907, "Rejected")], 5927: [(8323, "Verified")]}
        for n in RFCS:
            self.assertEqual([(e["id"], e["status"]) for e in self.inventory(n)["errata"]], expected[n])


if __name__ == "__main__":
    unittest.main()
