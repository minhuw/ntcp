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

    def test_disabled_ipv6_safety_and_the_administrative_path_flag_are_separate_controls(self):
        rows = {p["id"]: p for p in self.inventory(8201)["paragraphs"]}
        disabled = rows["8201-004"]
        self.assertEqual(disabled["status"], "covered")
        self.assertEqual(disabled["quote"],
                         "Nodes not implementing Path MTU Discovery must use the IPv6 minimum link MTU defined in [RFC8200] as the maximum packet size. In most cases, this will result in the use of smaller packets than necessary, because most paths have a PMTU greater than the IPv6 minimum link MTU. A node sending packets much smaller than the Path MTU allows is wasting network resources and probably getting suboptimal throughput.")
        self.assertEqual(disabled["evidence"], [
            "crates/stacks/ntcp/src/connection.rs::    pub(crate) fn active_with_receive_path(",
            "crates/stacks/ntcp-ip6/tests/disabled_pmtud.rs::fn disabled_ipv6_codec_peer_boundaries_options_loss_and_output_modes()",
        ])
        # The creation profile is not the path control: the owner's flag on
        # a path closes 8201-082 with its own source and test evidence.
        path = rows["8201-082"]
        self.assertEqual(path["status"], "covered")
        self.assertEqual(path["quote"],
                         "The former can be accomplished by associating a flag with the path; when a packet is sent on a path with this flag set, the IP layer does not send packets larger than the IPv6 minimum link MTU.")
        self.assertEqual(path["evidence"], [
            "crates/stacks/ntcp-path/src/service/cache.rs::    pub fn ip_packet_budget(",
            "crates/stacks/ntcp-host/src/tests/admin.rs::fn ipv6_discovery_disable_caps_existing_and_future_tcp_at_1280()",
        ])
        for fragment in ("caps that path's IPv6 packet budget at the IPv6 minimum link MTU of 1280 octets",
                         "set through Host::administration and by the ntcp-pathctl utility",
                         "Connections created with PMTUD disabled enforce the same ceiling on their own (8201-004)",
                         "each physical software-GSO segment", "integration/rfc_host admin and native-admin cases"):
            self.assertIn(fragment, path["reason"])
        self.assertEqual(rows["8201-080"]["status"], "covered")

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
        # Locality closes 023; T16's Host receive derivation, its embeddings
        # and the two-link captures close 024, and with the recorded 65495
        # disposition 025, on managed (not legacy locality) evidence; the
        # rounded send space closes 083 with its two recorded dispositions.
        # Detector robustness and literal unchanged-cwnd obligations retain
        # their separate identity. T13's host fragmentation closes the whole
        # 062 recommendation, with the recorded IP_PMTUDISC_DONT disposition.
        expected = {
            "1191-023": ("covered", "b707ab63ef804beb967fd98fc590e0fb3d32b388bd1714383cd69ed4b81b7540"),
            "1191-024": ("covered", "aa85eaa493b1e0f480f7bdc7bc423f41afc5aac20a1993d6803b519bab927308"),
            "1191-025": ("covered", "54660db94e505f213213e1d4b163e451f8089853f3b60ffc06d70dd157593f11"),
            "1191-083": ("covered", "0024f3d005f34caa42b7f3d606589fda32c6680be34c654ae447a1a34af85b40"),
            "4821-062": ("covered", "e4351333b58527eb5fcd9a6fc58a08ba600816aeada37c9cb0fc871163134f55"),
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
            self.assertEqual(len(row["evidence"]), 2, key)
        for fragment in ("MMS_R-40", "Host::reassembly_capacity", "EMTU_R", "Host::receive_ip_capability",
                         "every Host factory transaction", "src/tests/receive_capability.rs",
                         "keep no static receive sizing", "src/bin/two_link.rs", "two TUNs of unequal MTU",
                         "captured SYN-ACK and SYN offers", "explicit legacy contract, on which this closure does not rest"):
            self.assertIn(fragment, rows["1191-024"]["reason"])
        for fragment in ("User disposition (decision A, 2026-11-04, recorded)", "65535-octet IPv4 link",
                         "no 65494 or other substitute ceiling", "capability-backed use", "No sign-bit bug is alleged"):
            self.assertIn(fragment, rows["1191-025"]["reason"])
        for fragment in ("greatest multiple of Q", "is this paragraph's segment size (PMTU - 40)",
                         "C = 18824, the literal formula 18980", "below one segment C = B", "no credit is invented",
                         "snd_wnd, max_snd_wnd and cwnd are unchanged", "integration/rfc_host mss send-space case",
                         "Raw Endpoints keep B"):
            self.assertIn(fragment, rows["1191-083"]["reason"])
        self.assertEqual(rows["1191-083"]["reason"].count("User disposition (decision A, 2026-11-04, recorded)"), 2)
        for key in ("1191-024", "1191-025", "1191-083"):
            self.assertNotRegex(rows[key]["reason"], r"\bRemaining\b|\bTODO\b|T19", key)
        # Managed closure rests on the Host derivation and its factory tests,
        # not on the legacy raw-Endpoint locality evidence.
        for key, test in (("1191-024", "offer_is_largest_family_link_capped_by_physical_reassembly_and_wire_limits"),
                          ("1191-025", "ipv4_65535_link_with_matching_reassembly_offers_65495_and_smaller_caps_do_not")):
            self.assertEqual(rows[key]["evidence"], [
                "crates/stacks/ntcp-host/src/lib.rs::    pub fn receive_ip_capability(",
                f"crates/stacks/ntcp-host/src/tests/receive_capability.rs::fn {test}()",
            ], key)
        self.assertEqual(rows["1191-083"]["evidence"], [
            "crates/stacks/ntcp/src/connection.rs::    pub(crate) fn send_space(",
            "crates/stacks/ntcp/src/connection_send_space_tests.rs::fn managed_boundary_buffers_admit_c_and_deliver_to_completion()",
        ])
        self.assertIn("covered separately at1191-024/025", rows["1191-023"]["reason"])
        self.assertNotIn("TODO", rows["1191-023"]["reason"])
        for fragment in ("ntcp_ip::Fragmenter, which sets DF on every fragment", "TCP never enters source fragmentation",
                         "User disposition of the SHOULD (recorded)", "IP_PMTUDISC_DONT", "its PLPMTUD probes keep DF"):
            self.assertIn(fragment, rows["4821-062"]["reason"])
        self.assertNotIn("not implemented yet", rows["4821-062"]["reason"])
        self.assertIn("beyond these detector conditions", rows["4821-090"]["reason"])
        self.assertIn("rescaling the byte congestion window", rows["8201-076"]["reason"])
        self.assertIn("receive_mss_locality.rs::", rows["1191-023"]["evidence"][1])
        self.assertIn("reordered_leading_receiver_delivery_and_loss", rows["4821-090"]["evidence"][1])
        self.assertEqual(rows["4821-062"]["evidence"], [
            "crates/stacks/ntcp-host/src/emitter.rs::    pub(crate) fn transmit(",
            "crates/stacks/ntcp-host/src/tests/emitter.rs::fn fragment_mode_cuts_to_the_effective_size_with_df_and_one_checksum()",
        ])
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
        self.assertIn("Host::admin_set_ipv4_plateaus", plateau["reason"])
        self.assertIn("ntcp-pathctl utility's plateaus command", plateau["reason"])
        self.assertNotIn("independently T12", plateau["reason"])
        # Table policy alone does not close 1191-050: it closes with validated
        # ICMP dispatch, fragmentation and the owner route flag (T9-T13, T12).
        self.assertEqual(rows["1191-050"]["status"], "covered")
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
            "1191-050": ("T8", "T9", "T10", "T13", "integration/rfc_host admin cases",
                         "nonzero leased Identification",
                         "every Host::udp_send and Host::udp_send_datagram UDP datagram and source fragment",
                         "with DF except on an owner-flagged route", "integration/rfc_host admin refuse case"),
            "1191-074": ("T8", "T9", "T10", "Remaining T18", "T19"),
        }.items():
            self.assertEqual(rows[key]["status"], "covered" if key == "1191-050" else "TODO", key)
            self.assertNotIn("T7 phase2", rows[key]["reason"], key)
            for dependency in dependencies:
                self.assertIn(dependency, rows[key]["reason"], key)
        for key in ("1191-056", "1191-057", "1191-058", "1191-074"):
            self.assertEqual(len(rows[key]["evidence"]), 2, key)
        rows6 = {p["id"]: p for p in self.inventory(8201)["paragraphs"]}
        # 8201-052 stays TODO: zone propagation and multi-link ND are T18's.
        self.assertEqual(rows6["8201-052"]["status"], "TODO")
        for fragment in ("T7 PathService", "remain T18"):
            self.assertIn(fragment, rows6["8201-052"]["reason"])
        # 8201-050 closes with T17's complete header length (pinned below).
        self.assertEqual(rows6["8201-050"]["status"], "covered")
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
        # TCP reads and updates the cache, UDP reads it and the Host's Echo
        # adjunct is a Host-trusted writer. T13 supplies the datagram probe
        # send mode and T12 the outcome report, whose shared writes need the
        # Host owner's flow-scoped grant; with both, 4821-019 closes.
        reason019 = rows4821["4821-019"]["reason"]
        self.assertEqual(rows4821["4821-019"]["status"], "covered")
        self.assertEqual(rows4821["4821-019"]["evidence"], [
            "crates/stacks/ntcp-host/src/udp/receipts.rs::    pub fn udp_report_probe(",
            "crates/stacks/ntcp-host/src/tests/probe_receipts.rs::fn owner_granted_writer_offers_success_to_the_shared_estimate_separately()",
        ])
        self.assertIn("Each packetization protocol therefore has its own PLPMTUD", reason019)
        self.assertNotRegex(reason019, r"\bRemaining\b")
        self.assertIn("Host::service_changes", reason019)
        self.assertIn("below proven delivery is deferred whatever", reason019)
        self.assertIn("T13's Probe mode (Host::udp_send_datagram with UdpSendMode::Probe)", reason019)
        self.assertIn("ICMP Echo adjunct is a Host-trusted writer", reason019)
        self.assertNotIn("applications still have no shared-cache writer", reason019)
        self.assertIn("Host::udp_report_probe", reason019)
        self.assertIn("owner-granted, flow-scoped UdpSharedWriter", reason019)
        self.assertIn("owner-trusted application evidence", reason019)
        self.assertIn("The integration/rfc_host probe-report case reports outcomes observed by a real receiver (4821-160)",
                      reason019)
        self.assertIn("authority granted by the Host owner", reason019)
        # Only an owner grant lets an application write shared state.
        reason195 = rows4821["4821-195"]["reason"]
        self.assertIn("Host::udp_grant_shared_writer", reason195)
        self.assertIn("never as Host-observed proof", reason195)
        self.assertNotIn("its Probe-mode sends write nothing shared), so", reason195)
        self.assertNotIn("Host UDP has no datagram PLPMTUD", reason019)
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
        # T9 closes the whole distinct-notification clause.
        self.assertEqual(rows6["8201-066"]["status"], "covered")
        self.assertIn("ntcp-host/src/lib.rs::", rows6["8201-066"]["evidence"][0])
        self.assertIn("next service pass", rows6["8201-066"]["reason"])
        self.assertNotIn("next egress refresh", rows6["8201-066"]["reason"])
        # T11 closes the whole drop-notification, prompt exact-range and
        # non-amplification obligations; the unchanged-cwnd pair keeps only
        # the T23 AC-27 standards decision on MSS-decrease rescaling.
        closed = {
            "1191-061": ("a488096526729f741570456d2e7c4bb71c0c66641a88485d11bcd6c5cfe30c3d",
                         "connection.rs::    fn accept_pmtu_report(", "connection_ptb_scheduler_tests.rs::"),
            "8201-064": ("63fdcfe2d5b9350b570797c4cd67f3d367904fcb3f4b17702bf2b7ed54003ecf",
                         "connection.rs::    fn accept_pmtu_report(", "connection_ptb_scheduler_tests.rs::"),
            "1191-064": ("3acf5bab03a3e2a46b282244619c2ec627af02f5a89e151ab02cb569d5f8cad8",
                         "connection_ptb.rs::    pub(super) fn note_ptb_drop(", "ntcp-host/src/tests/repair.rs::"),
            "1191-080": ("5dc1d51f767d1166c39060ad2db110746af28014f6904a76fa2246f5db18cf72",
                         "connection_ptb.rs::    pub(super) fn ptb_segment(", "connection_ptb_scheduler_tests.rs::"),
        }
        for key, (digest, source, test) in closed.items():
            row = (rows6 if key.startswith("8201") else rows)[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), digest, key)
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(len(row["evidence"]), 2, key)
            self.assertIn(source, row["evidence"][0], key)
            self.assertIn(test, row["evidence"][1], key)
            self.assertNotRegex(row["reason"], r"\bRemaining\b|\bT11\b|head retry from|are rejected", key)
        for key in ("1191-061", "8201-064"):
            reason = (rows6 if key.startswith("8201") else rows)[key]["reason"]
            self.assertIn("whether or not the estimate falls", reason)
            self.assertIn("tcp-burst", reason)
        self.assertIn("tcp-staged", rows["1191-064"]["reason"])
        self.assertIn("one accepted physical repair packet until useful ACK progress", rows["1191-080"]["reason"])
        for key in ("1191-082", "8201-076"):
            row = (rows6 if key.startswith("8201") else rows)[key]
            self.assertEqual(row["status"], "TODO", key)
            remainder = row["reason"].split("Remaining (T23, AC-27): ", 1)
            self.assertEqual(len(remainder), 2, key)
            self.assertIn("Implemented operative behavior", remainder[0], key)
            self.assertIn("MSS", remainder[1], key)
            self.assertNotRegex(row["reason"], r"\bT11\b|head retry", key)
        # Host-correlated derived sizes are independent of the local estimate,
        # including the legacy RFC 1191 section 5 correction.
        for key, row in {"1191-057": rows["1191-057"],
                         **{k: rows4821[k] for k in ("4821-019", "4821-069", "4821-079", "4821-195")}}.items():
            self.assertIn("corrected against the Host's shared path estimate, RFC 1191 section 5's current PMTU estimate, never the connection's estimate", row["reason"], key)

    def test_t13_fragmentation_probe_and_adjunct_dispositions_keep_full_keys(self):
        rows = {p["id"]: p for n in (1191, 8201, 4821, 5927) for p in self.inventory(n)["paragraphs"]}
        # Whole-obligation closures: the original full target + quote, the
        # Host source and test evidence, and every annotation copy's reason.
        closed = {
            "4821-062": ("e4351333b58527eb5fcd9a6fc58a08ba600816aeada37c9cb0fc871163134f55", "emitter.rs::", "tests/emitter.rs::"),
            "4821-155": ("24977c7491f5d431044c151e471673d46da37c7140523ce8260feb43b5e02b86", "udp.rs::", "tests/emitter.rs::"),
            "4821-070": ("4fa18c5818d8f04a348af8f33cb47a9bdd641bcf1184d13729174ccb22e401aa", "udp.rs::", "tests/emitter.rs::"),
            "4821-158": ("d5ef9a250f1805ff1c3597ff704dffaa8635ba81ce8506d1f1d379d8acc58356", "udp.rs::", "tests/emitter.rs::"),
            "4821-159": ("5c528853c42f89ac3eaba13ff596b1d6db4830cd642c0d41d15ff85a25c9c0c8", "udp.rs::", "tests/emitter.rs::"),
            "4821-192": ("08b0e91d355fdda941fc6d0ecaa0cbac1c56962c37d882c365ee0587498a4ae5", "udp.rs::", "tests/emitter.rs::"),
            "4821-183": ("67c60bfe15e664d2014297374a43a971d4334ed859419a5e2ccc5e6e1e52bdcd", "adjunct.rs::", "tests/adjunct.rs::"),
            "4821-186": ("a2d5f52d63e66dc9e31356e1a962376687a53077e2c1567a08e6dd19bc888d59", "emitter.rs::", "tests/emitter.rs::"),
        }
        canonical = {}
        for key, (digest, source, test) in closed.items():
            row = rows[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), digest, key)
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(len(row["evidence"]), 2, key)
            self.assertTrue(row["evidence"][0].startswith("crates/stacks/ntcp-host/src/" + source), key)
            self.assertTrue(row["evidence"][1].startswith("crates/stacks/ntcp-host/src/" + test), key)
            self.assertNotRegex(row["reason"], r"raw-datagram stack|outside TCP|not implemented yet", key)
            canonical[(row["target"], normalize(row["quote"]))] = row
        for key in ("4821-070", "4821-158", "4821-159", "4821-192"):
            self.assertIn("Probe mode (UdpSendMode::Probe", rows[key]["reason"], key)
            self.assertIn("writes no shared state (the application reports the outcome through Host::udp_report_probe, 4821-160)",
                          rows[key]["reason"], key)
            self.assertIn("integration/rfc_host probe-mode case", rows[key]["reason"], key)
        self.assertIn("even when it is smaller than the first-hop MTU", rows["4821-155"]["reason"])
        self.assertIn("despite the preference for forward-only methods", rows["4821-183"]["reason"])
        self.assertIn("NotLarger on an unlearned path", rows["4821-183"]["reason"])
        self.assertIn("separate Host-wide control", rows["4821-186"]["reason"])
        kinds = {key: set() for key in canonical}
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in source_annotations(path.read_text()):
                key = (annotation["target"], normalize(annotation["quote"]))
                if key in canonical:
                    self.assertEqual(annotation["reason"], canonical[key]["reason"],
                                     (canonical[key]["id"], str(path), annotation["line"]))
                    kinds[key].add(annotation["kind"])
        for key, seen in kinds.items():
            self.assertEqual(seen, {"CITATION", "TEST"}, canonical[key]["id"])
        # Probe-outcome reporting is T12's obligation, not an actor
        # exception: closed by Host::udp_report_probe with Host evidence and
        # the receiver-backed namespace report.
        self.assertEqual(rows["4821-160"]["status"], "covered")
        self.assertEqual(rows["4821-160"]["evidence"], [
            "crates/stacks/ntcp-host/src/udp/receipts.rs::    pub fn udp_report_probe(",
            "crates/stacks/ntcp-host/src/tests/probe_receipts.rs::fn each_outcome_changes_only_the_reporting_flows_bounds_and_sizing()",
        ])
        self.assertNotRegex(rows["4821-160"]["reason"], r"\bRemaining\b")
        self.assertEqual(hashlib.sha256((rows["4821-160"]["target"] + "\n" + " ".join(rows["4821-160"]["quote"].split())).encode()).hexdigest(),
                         "f615a0be418316eb0f2da0a07f944efca2d0a26b229df687daa1bae12ef9843c")
        for fragment in ("T13's Probe mode", "authority granted by the Host owner",
                         "Host::udp_report_probe", "Success, IsolatedLoss, TimeoutFailure and Inconclusive",
                         "UdpLimits::probe_receipts", "feedback horizon", "changes only the reporting flow's own bounds",
                         "PathService::confirm_delivery_as", "owner-trusted application evidence",
                         "tests/probe_receipts.rs", "integration/rfc_host probe-report case",
                         "real Linux receiver", "refused as Consumed", "refused as StaleRevision"):
            self.assertIn(fragment, rows["4821-160"]["reason"])
        self.assertNotIn("No API lets an application inform the Host", rows["4821-160"]["reason"])
        self.assertIn("Host::udp_report_probe", rows["4821-188"]["reason"])
        self.assertNotIn("is 4821-160 (T12)", rows["4821-188"]["reason"])
        self.assertIn("raise or bound for that flow only", rows["4821-155"]["reason"])
        # 187 stays an exception that states the implemented bounded alternative.
        self.assertEqual(rows["4821-187"]["status"], "exception")
        for fragment in ("not implemented as described", "no datagram-count threshold", "least recently used entry without an outstanding probe",
                         "separate from PathService's shared learned ceilings", "reclaims an idle (unpinned) slot"):
            self.assertIn(fragment, rows["4821-187"]["reason"])
        # Rewritten exceptions keep their status and say what exists.
        self.assertEqual(rows["4821-154"]["status"], "exception")
        self.assertIn("User disposition of the SHOULD (recorded)", rows["4821-154"]["reason"])
        self.assertEqual(rows["4821-156"]["status"], "exception")
        self.assertIn("The second sentence is met", rows["4821-156"]["reason"])
        self.assertIn("safe-MTU policy of the first sentence is declined", rows["4821-156"]["reason"])
        for key in ("4821-188", "4821-189", "4821-190", "4821-191"):
            self.assertEqual(rows[key]["status"], "exception", key)
            self.assertIn("Probe mode", rows[key]["reason"], key)
            self.assertIn("pplication", rows[key]["reason"], key)
        for key in ("1191-085", "1191-087", "1191-088", "1191-089", "8201-077"):
            self.assertEqual(rows[key]["status"], "exception", key)
            self.assertIn("stack-managed non-repacketizing retransmission algorithm", rows[key]["reason"], key)
            self.assertIn("Fragment mode", rows[key]["reason"], key)
        # Superseded claims: upward values cached without any search
        # transition, a discovery flag with no effect at all, (parent decision
        # D17) queued ICMP or stateless output making a change Busy, and the
        # status reconciliation left to stage 8.
        superseded = ("equal or above it, it is cached only", "stored and reported only",
                      "does not yet suppress probes", "stages 3-8", "does not yet clear IPv4 DF", "Busy when final output",
                      "control-segment, software-GSO-segment and Echo-reply evidence",
                      "no system-utility", "not yet by a system utility", "stages 5-8",
                      "utility interface exists yet", "stages 7-8", "T12 stage 8 reconciles status")
        # Closed: every IPv4 packet of a flagged route, Host::udp_send's whole
        # datagrams included, leaves DF clear, so the IPv4 route flag and its
        # utility lead-in are covered with no remainder.
        for key in ("1191-090", "1191-091", "1191-093"):
            self.assertEqual(rows[key]["status"], "covered", key)
            self.assertEqual(len(rows[key]["evidence"]), 2, key)
            self.assertNotRegex(rows[key]["reason"], r"\bRemaining\b", key)
            for fragment in ("IdentifierAllocator", "fragmenting datagram emitter", "Probe mode", "route-isolation case",
                             "defines a search transition", "a failed targeted probe is not reopened",
                             "DF-clear IP_PMTUDISC_DONT output proves no size", "one serialized Host::admin_apply transaction",
                             "The discovery-disable flag is enforced",
                             "whole UDP datagrams of Host::udp_send and Host::udp_send_datagram and Host source fragments",
                             "RFC 1122 section 3.3.3 EMTU_S",
                             "best-effort output never blocks a change",
                             "each physical software-GSO segment",
                             "T12 stage 6 adds the system utility", "SO_PEERCRED",
                             "real utility process round trips", "Namespace evidence (integration/rfc_host admin",
                             "Host::udp_send, the T9 whole-datagram API", "UdpSendError::Backpressure",
                             "disabled_ipv4_route_clears_df_on_whole_udp_send_datagrams",
                             "integration/rfc_host admin refuse case"):
                self.assertIn(fragment, rows[key]["reason"], key)
            for stale in (*superseded, "leaves DF clear on every packet of the route or path", "T12 repair",
                          "except those of Host::udp_send", "with DF set and without a leased Identification"):
                self.assertNotIn(stale, rows[key]["reason"], key)
        self.assertIn("the user's recorded decision B", rows["1191-093"]["reason"])
        # Closed: the route PMTU value and the whole RFC 8201 section 5.6
        # path utility, with the utility (or the 1280 budget) and its tests.
        for key in ("1191-092", "8201-079", "8201-080", "8201-081", "8201-082"):
            row = rows[key]
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(len(row["evidence"]), 2, key)
            for fragment in ("ntcp-pathctl", "integration/rfc_host admin"):
                self.assertIn(fragment, row["reason"], key)
            self.assertNotRegex(row["reason"], r"\bRemaining\b", key)
            for stale in superseded:
                self.assertNotIn(stale, row["reason"], key)
        for key in ("1191-092", "8201-079", "8201-080", "8201-081"):
            self.assertEqual(rows[key]["evidence"], [
                "crates/adapters/ntcp-path-control/src/cli.rs::fn run(",
                "crates/adapters/ntcp-path-control/tests/control.rs::fn utility_process_round_trips_both_families()",
            ], key)
            self.assertIn("SO_PEERCRED", rows[key]["reason"], key)
            self.assertIn("one serialized Host::admin_apply transaction", rows[key]["reason"], key)
        for key in ("1191-092", "8201-081"):
            for fragment in ("compared with the path's accepted network estimate", "a fresh negative revision",
                             "an identical value is a no-op", "a failed targeted probe is not reopened",
                             "Clearing removes the cap and keeps every hold"):
                self.assertIn(fragment, rows[key]["reason"], key)
        # Whole-key closures of T17: the complete original quotations, the
        # source and asserting-test citations, every annotation copy, and
        # reasons that state the whole obligation (8201-050: the complete
        # header H in every output mode, fragmentation and the T16 receive
        # indication; 8201-060: decision D8's type-specific disposition and
        # a witness whose first and last encoded addresses differ).
        t17 = {
            "8201-050": ("a555cbc7fdcad0ffcdd9addbd00178b0967d60c5cd740069934d5d838aaf4912", [
                "crates/stacks/ntcp-host/src/lib.rs::    pub fn header_plan(",
                "crates/stacks/ntcp-host/src/tests/segment_routes.rs::"
                "fn tcp_over_a_segment_route_sizes_and_repairs_segments_with_h()"],
                ("complete IPv6 header H", "8 + 16(n + 1)-octet Segment Routing Header",
                 "scalar, shared, reserved and software GSO output", "EMTU_S - H - 8",
                 "1500 octets for IPv6", "repeat the unfragmentable part",
                 "TCP never source-fragments", "Host::reassembly_capacity",
                 "Host::receive_ip_capability", "integration/rfc_host srh cases")),
            "8201-060": ("7dca119cc6ea95fe712577b228622de5bb9f0d416be441d22afb128c32f551df", [
                "crates/stacks/ntcp-ip-common/src/ipv6.rs::    pub fn final_destination(",
                "crates/stacks/ntcp-icmp/tests/extension_quote.rs::"
                "fn routed_quotes_correlate_with_the_type_specific_final_destination()"],
                ("Segments Left equal to zero, the Destination Address field", "decision A, D8",
                 "last address Address[n]", "Segment List[0]", "declines attribution",
                 "quote-decoder evidence only: no Type 0 header is ever originated",
                 "validated against the route generation", "first and last addresses differ",
                 "base Destination Address S1 different from the final destination")),
        }
        canonical = {}
        for key, (digest, evidence, fragments) in t17.items():
            row = rows[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), digest, key)
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(row["evidence"], evidence, key)
            for fragment in fragments:
                self.assertIn(fragment, row["reason"], key)
            self.assertNotRegex(row["reason"], r"\bRemaining\b|T17 owns|accepts no extension header", key)
            canonical[(row["target"], normalize(row["quote"]))] = row
        kinds = {key: set() for key in canonical}
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in source_annotations(path.read_text()):
                key = (annotation["target"], normalize(annotation["quote"]))
                if key in canonical:
                    self.assertEqual(annotation["reason"], canonical[key]["reason"],
                                     (canonical[key]["id"], str(path), annotation["line"]))
                    kinds[key].add(annotation["kind"])
        for key, seen in kinds.items():
            self.assertEqual(seen, {"CITATION", "TEST"}, canonical[key]["id"])
        todos8201 = tomllib.loads((ROOT / "duvet/rfc8201-todos.toml").read_text())
        for key in t17:
            self.assertFalse([t for t in todos8201.get("TODO", [])
                              if " ".join(t["quote"].split()) == " ".join(rows[key]["quote"].split())], key)
        # No reason in these ledgers or their TOML dispositions still claims
        # that fragmentation, a Host datagram service or an allocator is absent,
        # and every mention of Host Echo Replies states how a source-routed
        # request's reply is routed and sized (T14 answers it; D15's
        # limitation is gone), qualified as IPv4 source routing: IPv6
        # replies use only owner-configured routes (T17).
        stale = (r"raw-datagram stack|UDP/raw datagram fragmentation service|no IP fragmentation service"
                 r"|does not offer host IP fragmentation|does not require a host datagram fragmentation"
                 r"|not fragmentation-based PLPMTUD|source fragmentation, including DF on originated fragments, is not")
        reasons = [p["reason"] for p in rows.values()]
        for n in (1191, 8201, 4821, 5927):
            todos = tomllib.loads((ROOT / f"duvet/rfc{n}-todos.toml").read_text())
            reasons += [t["reason"] for kind in ("TODO", "exception") for t in todos.get(kind, [])]
        for reason in reasons:
            self.assertNotRegex(reason, stale)
            self.assertNotIn("until T14", reason)
            if "Echo Replies" in reason:
                self.assertIn("a reply to an IPv4 source-routed Echo Request takes the reversed, "
                              "policy-authorized return route, registers no adjunct demand "
                              "and is never sized by an adjunct-confirmed bound, while IPv6 "
                              "Echo Replies use only owner-configured routes", reason)

    def test_t12_closures_keep_full_keys_and_every_annotation_copy(self):
        # Whole-obligation closures: the original full target + quote, the
        # source and test evidence, and every annotation copy's reason.
        closed = {
            "1191-092": "f615dc529b2101e513cbbc25aa34ef54fba85bc172c7e5390676d3e87f02cf63",
            "8201-079": "baa2c5e8f29c538a4bc72a3e0114eb38e01ad1705d7501833fbf6ba48b97f84c",
            "8201-080": "38b723ebea0b7eb93b9d7e1d6c027ee79ba299d760ee61e4ddbdd897b861da6e",
            "8201-081": "ab44a19971efe13bd7d5c5b85479b07c8b7468922ba1b91c3334aa9ca4ed37d8",
            "8201-082": "6f688de8256452cdfae1421cc70b0b9875daeba6b234f2f160b6ff18874d93bf",
            "4821-019": "0fc57e6e68a7bb7985d393a66226d3cd93d351f9089dae2b39063de8864274a1",
            "4821-160": "f615a0be418316eb0f2da0a07f944efca2d0a26b229df687daa1bae12ef9843c",
            "1191-050": "a6f118cde6ed60255175e2018dcd6f0d1575f98b73f11edc919a3c195dc5152f",
            "1191-090": "b75cc8c75c9b1c475b34a1f69261b4f9c0d9887caaf21b30e8e185ffe216b3f0",
            "1191-091": "a45f51957f49fdbfdd921463a3bc00f25182e15ecda353f5df6c33d0529c9065",
            "1191-093": "356cde6ba94f574f39842209e74feac7da48ff8553b172b8245cfb95dae4b5f9",
        }
        rows = {p["id"]: p for n in (1191, 8201, 4821, 5927, 6864) for p in self.inventory(n)["paragraphs"]}
        canonical = {}
        for key, digest in closed.items():
            row = rows[key]
            full_key = row["target"] + "\n" + " ".join(row["quote"].split())
            self.assertEqual(hashlib.sha256(full_key.encode()).hexdigest(), digest, key)
            self.assertEqual(row["status"], "covered", key)
            self.assertEqual(len(row["evidence"]), 2, key)
            self.assertNotIn("T12 repair", row["reason"], key)
            canonical[(row["target"], normalize(row["quote"]))] = row
        kinds = {key: set() for key in canonical}
        for path in (ROOT / "crates").rglob("*.rs"):
            for annotation in source_annotations(path.read_text()):
                key = (annotation["target"], normalize(annotation["quote"]))
                if key in canonical:
                    self.assertEqual(annotation["reason"], canonical[key]["reason"],
                                     (canonical[key]["id"], str(path), annotation["line"]))
                    kinds[key].add(annotation["kind"])
        for key, seen in kinds.items():
            self.assertEqual(seen, {"CITATION", "TEST"}, canonical[key]["id"])
        # Reasons that T12 made false: absent owner integration of plateaus
        # and aging, outcome reporting still to come, stage-8 placeholders,
        # and claims that every IPv4 fragment carries DF without the owner's
        # flagged-route disposition.
        stale = (r"owned by T12|No route/cache or socket-parser integration|Owner-authorized utility integration is independently T12"
                 r"|status reconciliation \(stage 8\)|T12 stage 8|leaves DF clear on every packet, source fragments included"
                 r"|DF on every IPv4 fragment \(4821-155\);|neither described non-PMTUD category applies"
                 r"|only for non-atomic datagrams \(source fragments and DF-clear IP_PMTUDISC_DONT TCP packets\)")
        reasons = [p["reason"] for p in rows.values()]
        for n in (1191, 8201, 4821, 5927, 6864):
            todos = tomllib.loads((ROOT / f"duvet/rfc{n}-todos.toml").read_text())
            reasons += [t["reason"] for kind in ("TODO", "exception") for t in todos.get(kind, [])]
        for path in (ROOT / "crates").rglob("*.rs"):
            reasons += [a["reason"] for a in source_annotations(path.read_text())]
        for reason in reasons:
            self.assertNotRegex(reason, stale)
        for key in ("1191-068", "1191-095", "8201-069", "8201-084"):
            self.assertIn("Host::admin_set_search_aging", rows[key]["reason"], key)
            self.assertIn("ntcp-pathctl utility's aging command", rows[key]["reason"], key)
        for key in ("1191-005b", "1191-006a", "4821-062", "4821-154", "4821-153", "5927-068", "6864-id-purpose"):
            self.assertRegex(rows[key]["reason"], r"owner-disabled|owner disabled discovery", key)
        self.assertEqual(rows["1191-006a"]["status"], "exception")
        self.assertEqual(rows["6864-nonatomic-boundary"]["status"], "context")
        self.assertIn("owner-disabled IPv4 route or path", rows["6864-nonatomic-boundary"]["reason"])

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
