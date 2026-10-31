import hashlib
import json
from pathlib import Path
import re
import tomllib
import unittest

from check_annotation_inventory import source_annotations
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

    def test_todo_reasons_match_todo_entries_and_partial_evidence(self):
        # A TODO row has one reason: its todos.toml entry and any partial
        # source/test evidence annotation must carry the same text.
        for n in RFCS:
            todos = tomllib.loads((ROOT / f"duvet/rfc{n}-todos.toml").read_text())
            key = lambda p: (p["target"], " ".join(p["quote"].split()))
            for p in self.inventory(n)["paragraphs"]:
                if p["status"] != "TODO":
                    continue
                self.assertEqual([t["reason"] for t in todos.get("TODO", []) if key(t) == key(p)],
                                 [p["reason"]], p["id"])
                # Keep the proven source/test evidence explicitly partial, not deleted.
                for evidence in p.get("evidence", []):
                    source = (ROOT / evidence.split("::", 1)[0]).read_text()
                    self.assertIn("//= reason=" + p["reason"], source, p["id"])

    def test_lowercase_algorithm_and_security_spans_cannot_disappear(self):
        required = {
            1191: ("576 octets unless", "Header Length field", "greatest plateau value",
                   "MUST not retransmit datagrams", "PMTU Discovery does not affect"),
            8201: ("must discard it", "must not increase", "less than 5 minutes",
                   "including IPv6 extension headers", "must not be considered as a congestion"),
            4821: ("implicit probe", "search_low SHOULD be raised", "SHOULD be configurable",
                   "same-sized probe", "R1 timeout threshold", "search_high to the probe size minus one",
                   "Data in the probe gap", "The saved value of eff_pmtu SHOULD be restored"),
            5927: ("Increasing the port number range", "randomize the ephemeral ports",
                   "SND.UNA =< SEG.SEQ < SND.NXT", "maxsizesent", "maxsizeacked",
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
        for i in (49, 50):
            row = rows[f"5927-{i:03}"]
            self.assertEqual(row["status"], "covered")
            self.assertIn("Selected Informational security policy:", row["reason"])
            self.assertIn("1024..65535", row["reason"])
            self.assertIn("occupied-cluster bias", row["reason"])
            self.assertEqual(row["evidence"], [
                "crates/adapters/ntcp-socket/src/runtime.rs::    fn port(",
                "crates/adapters/ntcp-socket/src/runtime_port_tests.rs::fn native_auto_ports_bind_listen_connect_and_deferred_fast_open(",
            ])
        for i in (103, 104, 106, 108, 109):
            row = rows[f"5927-{i:03}"]
            self.assertEqual(row["status"], "exception")
            self.assertIn("Selected Informational policy deviation:", row["reason"])
            self.assertIn("historical algorithm is deliberately not selected", row["reason"])

    def test_disabled_ipv6_safety_does_not_close_the_administrative_path_interface(self):
        rows = {p["id"]: p for p in self.inventory(8201)["paragraphs"]}
        disabled = rows["8201-004"]
        self.assertEqual(disabled["status"], "covered")
        self.assertEqual(disabled["quote"],
                         "Nodes not implementing Path MTU Discovery must use the IPv6 minimum link MTU defined in [RFC8200] as the maximum packet size. In most cases, this will result in the use of smaller packets than necessary, because most paths have a PMTU greater than the IPv6 minimum link MTU. A node sending packets much smaller than the Path MTU allows is wasting network resources and probably getting suboptimal throughput.")
        self.assertEqual(disabled["evidence"], [
            "crates/stacks/ntcp/src/connection.rs::    pub(crate) fn active_with_receive_path(",
            "crates/stacks/ntcp-ip6/tests/disabled_pmtud.rs::fn disabled_ipv6_codec_peer_boundaries_options_loss_and_output_modes()",
        ])
        path = rows["8201-082"]
        self.assertEqual(path["status"], "TODO")
        self.assertEqual(path["quote"],
                         "The former can be accomplished by associating a flag with the path; when a packet is sent on a path with this flag set, the IP layer does not send packets larger than the IPv6 minimum link MTU.")
        self.assertIn("No administrative per-path discovery-disable flag", path["reason"])
        self.assertIn("Connections configured with PMTUD disabled enforce", path["reason"])
        self.assertEqual(rows["8201-080"]["status"], "TODO")

    def test_matching_ptb_closures_keep_full_quotes_and_all_canonical_copies(self):
        quotes = {
            "4821-011": "The isolated loss of a probe packet (with or without an ICMP Packet Too Big message) is treated as an indication of an MTU limit, and not as a congestion indicator. In this case alone, the Packetization Protocol is permitted to retransmit any missing data without adjusting the congestion window.",
            "4821-065": "Normal congestion control algorithms MUST remain in effect under all conditions except when only an isolated probe packet is detected as lost. In this case alone, the normal congestion (window or data rate) reduction SHOULD be suppressed. If any other data loss is detected, standard congestion control MUST take place.",
            "4821-136": "When a probe has completed, the result SHOULD be processed as follows, categorized by the probe's result type.",
            "4821-139": "When only the probe is lost, it is treated as an indication that the Path MTU is smaller than the probe size. In this case alone, the loss SHOULD NOT be interpreted as congestion signal.",
            "4821-142": "A probe failure event is the one situation under which the Packetization Layer SHOULD ignore loss as a congestion signal. Because there is some small risk that suppressing congestion control might have unanticipated consequences (even for one isolated loss), it is REQUIRED that probe failure events be less frequent than the normal period for losses under standard congestion control. Specifically, after a probe failure event and suppressed congestion control, PLPMTUD MUST NOT probe again until an interval that is larger than the expected interval between congestion control events. See Section 4 for details. The simplest estimate of the interval to the next congestion event is the same number of round trips as the current congestion window in packets.",
        }
        rows = {p["id"]: p for n in (4821, 8201) for p in self.inventory(n)["paragraphs"]}
        affected = [rows[key] for key in (*quotes, "8201-075")]
        for key, quote in quotes.items():
            self.assertEqual(rows[key]["quote"], quote, key)
            self.assertEqual(rows[key]["status"], "covered", key)
            self.assertEqual(len(rows[key]["evidence"]), 2, key)
        # Check even unlisted source/test copies, not just the ledger's two anchors.
        canonical = {(p["target"], normalize(p["quote"])): p for p in affected}
        counts = {key: 0 for key in canonical}
        for path in (ROOT / "crates/stacks/ntcp/src").glob("*.rs"):
            for annotation in source_annotations(path.read_text()):
                key = (annotation["target"], normalize(annotation["quote"]))
                if key in canonical:
                    self.assertEqual(annotation["reason"], canonical[key]["reason"],
                                     (canonical[key]["id"], path.name, annotation["line"]))
                    counts[key] += 1
        self.assertTrue(all(count >= 2 for count in counts.values()))
        for key in ("4821-012", "4821-137", "4821-138", "4821-143", "4821-144"):
            self.assertEqual(rows[key]["status"], "covered", key)
        # Literal unchanged-cwnd conflicts and the independent black-hole reset
        # obligation remain unresolved; PTB classification must not close them.
        for n, key in ((1191, "1191-082"), (8201, "8201-076"), (4821, "4821-147")):
            row = next(p for p in self.inventory(n)["paragraphs"] if p["id"] == key)
            self.assertEqual(row["status"], "TODO", key)

    def test_final_bounded_evidence_keeps_full_keys_and_partial_dispositions(self):
        # Hash the full original target + quote, not a narrowed test assertion.
        # Locality closes only023; topology, fragmentation, detector robustness
        # and literal unchanged-cwnd obligations retain their separate identity.
        expected = {
            "1191-023": ("covered", "b707ab63ef804beb967fd98fc590e0fb3d32b388bd1714383cd69ed4b81b7540"),
            "1191-024": ("TODO", "aa85eaa493b1e0f480f7bdc7bc423f41afc5aac20a1993d6803b519bab927308"),
            "1191-025": ("TODO", "54660db94e505f213213e1d4b163e451f8089853f3b60ffc06d70dd157593f11"),
            "4821-062": ("TODO", "e4351333b58527eb5fcd9a6fc58a08ba600816aeada37c9cb0fc871163134f55"),
            "4821-090": ("TODO", "a0cad509ac88cfb5c86207ba33c9b552ef2d4edfbc4e442ac29f4020a6ae980e"),
            "8201-076": ("TODO", "1c249737ce83c551636bf21eea5e111f11011d4cd800c80e2f2d05e4f08effc0"),
        }
        rows = {p["id"]: p for n in (1191, 8201, 4821)
                for p in self.inventory(n)["paragraphs"] if p["id"] in expected}
        for key, (status, full_key_hash) in expected.items():
            row = rows[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), full_key_hash, key)
            self.assertEqual(row["status"], status, key)
            if key != "1191-025":
                self.assertEqual(len(row["evidence"]), 2, key)
        self.assertIn("MMS_R-40", rows["1191-024"]["reason"])
        self.assertIn("topology contract", rows["1191-024"]["reason"])
        self.assertIn("Host source fragmentation/reassembly", rows["4821-062"]["reason"])
        self.assertIn("beyond these detector conditions", rows["4821-090"]["reason"])
        self.assertIn("rescaling the byte congestion window", rows["8201-076"]["reason"])
        self.assertIn("receive_mss_locality.rs::", rows["1191-023"]["evidence"][1])
        self.assertIn("reordered_leading_receiver_delivery_and_loss", rows["4821-090"]["evidence"][1])
        self.assertIn("tun_echo_pmtu_tests.rs::", rows["4821-062"]["evidence"][1])
        # Include ordinary Rust copies outside the core's src directory, even
        # ones omitted from the ledger's two preferred evidence links.
        canonical = {(p["target"], normalize(p["quote"])): p for p in rows.values()}
        counts = {key: 0 for key in canonical}
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in source_annotations(path.read_text()):
                key = (annotation["target"], normalize(annotation["quote"]))
                if key in canonical:
                    self.assertEqual(annotation["reason"], canonical[key]["reason"],
                                     (canonical[key]["id"], str(path), annotation["line"]))
                    counts[key] += 1
        for key, row in canonical.items():
            if row["id"] != "1191-025":
                self.assertGreaterEqual(counts[key], 2, row["id"])

    def test_contemporary_policy_keeps_whole_quote_and_host_integration_gaps(self):
        rows = {p["id"]: p for p in self.inventory(1191)["paragraphs"]}
        plateau = rows["1191-099"]
        full_key = plateau["target"] + "\n" + " ".join(plateau["quote"].split())
        self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(),
                         "925511a597fd044370716a667751ee20e22334a330af0ba11a848c9a30732bf5")
        self.assertEqual(plateau["status"], "covered")
        self.assertEqual(plateau["evidence"], [
            "crates/stacks/ntcp-path/src/service.rs::    pub fn set_ipv4_plateaus(",
            "crates/stacks/ntcp-path/tests/lifecycle.rs::fn live_policy_replacement_notifies_ipv4_only_and_preserves_all_learned_estimates(",
        ])
        self.assertIn("AWS EC2 and Google VPC", plateau["reason"])
        self.assertIn("historical defaults and Error compatibility", plateau["reason"])
        # Table policy does not establish validated ICMP dispatch, fragmentation
        # or actual cross-protocol consumers at the managed host boundary.
        self.assertEqual(rows["1191-050"]["status"], "TODO")
        self.assertIn("T9", rows["1191-050"]["reason"])
        self.assertIn("T13", rows["1191-050"]["reason"])
        self.assertEqual(rows["1191-059"]["status"], "covered")
        self.assertEqual(rows["1191-060"]["status"], "context")
        self.assertEqual(rows["1191-060"]["quote"], "path.")

    def test_shared_path_interface_closures_keep_exact_keys_and_partial_runtime_obligations(self):
        rows = {p["id"]: p for p in self.inventory(1191)["paragraphs"]}
        for key, digest in {
            "1191-052": "2d4c2d93d53134f45bbc4f1b1ee8626b7285919f186119e1c326dca29afdaff6",
            "1191-053": "97fb5f346af4c744925251b2dacd00b184658c991039343f86d4ab6ab4725b9e",
            "1191-055": "e6185f5b761aaad8bbd9830d175b96794b28694eddeccdeae2abb88458db1a61",
        }.items():
            row = rows[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), digest, key)
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(len(row["evidence"]), 2, key)
            self.assertIn("ntcp-path/src/service/cache.rs::", row["evidence"][0])
            self.assertIn("ntcp-path/tests/lifecycle.rs::", row["evidence"][1])
        for key in ("1191-021", "1191-056"):
            self.assertEqual(rows[key]["status"], "covered", key)
            self.assertIn("ntcp-host/src/lib.rs::", rows[key]["evidence"][0])
            self.assertIn("ntcp-host/src/tests.rs::", rows[key]["evidence"][1])
            self.assertIn("before TCP construction", rows[key]["reason"])
        for key, dependencies in {
            "1191-050": ("T8", "T9", "T10", "Remaining T13"),
            "1191-074": ("T8", "T9", "T10", "Remaining T18", "T19"),
        }.items():
            self.assertEqual(rows[key]["status"], "TODO", key)
            self.assertNotIn("T7 phase2", rows[key]["reason"], key)
            for dependency in dependencies:
                self.assertIn(dependency, rows[key]["reason"], key)
        for key in ("1191-056", "1191-057", "1191-058", "1191-074"):
            self.assertEqual(len(rows[key]["evidence"]), 2, key)
        rows6 = {p["id"]: p for p in self.inventory(8201)["paragraphs"]}
        for key in ("8201-050", "8201-052"):
            self.assertEqual(rows6[key]["status"], "TODO", key)
            self.assertIn("T7 PathService", rows6[key]["reason"], key)
        # T10 closes whole notification, UDP-quoted, MMS_S, deferred-report
        # and shared-cache obligations with Host change-service evidence.
        rows4821 = {p["id"]: p for p in self.inventory(4821)["paragraphs"]}
        for key, row in {**{k: rows[k] for k in ("1191-057", "1191-058", "1191-059")},
                         **{k: rows6[k] for k in ("8201-049", "8201-062", "8201-063")},
                         "4821-079": rows4821["4821-079"]}.items():
            self.assertEqual(row["status"], "covered", key)
            self.assertRegex(row["evidence"][0], r"^crates/stacks/ntcp-(host|path)/src/", key)
            self.assertIn("ntcp-host/src/tests/fanout.rs::", row["evidence"][1], key)
            self.assertNotRegex(row["reason"], r"\bRemaining\b|T9/T10", key)
        for key in ("1191-058", "8201-062"):
            self.assertIn("Host::service_changes", rows.get(key, rows6.get(key))["reason"], key)
        # TCP reads and updates the cache and UDP reads it, but no datagram
        # PLPMTUD writes probe-confirmed sizes, so 4821-019 stays open with
        # owners: T13 the datagram probe send mode, T12 outcome reporting
        # whose shared writes need Host-owner authority.
        reason019 = rows4821["4821-019"]["reason"]
        self.assertEqual(rows4821["4821-019"]["status"], "TODO")
        self.assertIn("Host::service_changes", reason019)
        self.assertIn("below proven delivery is deferred whatever", reason019)
        self.assertIn("T13 adds the RFC 4821 section 9 datagram probe send mode", reason019)
        self.assertIn("T12 adds probe-outcome reporting", reason019)
        self.assertIn("authority granted by the Host owner", reason019)
        self.assertNotIn("no planned task", reason019)
        self.assertNotIn("Unchanged-for-TCP", reason019)
        for key in ("4821-019", "4821-076", "4821-195"):
            self.assertNotRegex(rows4821[key]["reason"], r"udp_send_probe|udp_confirm_delivery", key)
        # Exceptions about sharing describe the shared cache that now exists.
        for key in ("4821-069", "4821-076", "4821-077", "4821-080", "4821-081", "4821-083", "4821-195"):
            row = rows4821[key]
            self.assertEqual(row["status"], "exception", key)
            self.assertIn("PathService", row["reason"], key)
            self.assertNotRegex(row["reason"], r"independently TODO|remains TODO at 079|no sessions share|no cross-protocol", key)
        # T9 closes only the whole distinct-notification clause; the drop
        # notifications themselves still await exact T11 repair.
        self.assertEqual(rows6["8201-066"]["status"], "covered")
        self.assertIn("ntcp-host/src/lib.rs::", rows6["8201-066"]["evidence"][0])
        self.assertIn("next service pass", rows6["8201-066"]["reason"])
        self.assertNotIn("next egress refresh", rows6["8201-066"]["reason"])
        for key, dependency in (("1191-061", "T11"), ("8201-064", "T11")):
            row = (rows6 if key.startswith("8201") else rows)[key]
            self.assertEqual(row["status"], "TODO", key)
            self.assertIn(dependency, row["reason"], key)

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
