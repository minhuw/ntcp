# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
import ipaddress
import json
import os
import struct
import sys
import time
import unittest
from unittest.mock import patch

# The harness modules beside this file, also when run by path from the root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bridge import checksum
from linux_peer import fnv, pattern
import admin
import bridge
import icmp
import mss
import ndproxy
import options
import redirect
import rejected
import run
import scoped
import srh


class NamespaceGuard(unittest.TestCase):
    def test_in_namespace_claim_without_inherited_proof_cannot_reach_setup(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(run, "setup") as setup:
            with self.assertRaises(KeyError):
                run.child(dict(family=4, role="client", policy="hmac", scenario="ordinary"))
            setup.assert_not_called()

    def test_real_current_namespace_fd_cannot_authorize_mutation_even_as_root(self):
        fd = os.open("/proc/self/ns/net", os.O_RDONLY)
        try:
            with patch.dict(os.environ, {"T5_PARENT_NET_FD": str(fd)}, clear=True), patch.object(run, "setup") as setup:
                with self.assertRaisesRegex(AssertionError, "refuse mutation in parent net namespace"):
                    run.child(dict(family=6, role="server", policy="linux", scenario="warm"))
                setup.assert_not_called()
        finally:
            os.close(fd)

    def test_required_matrix_retains_both_roles_families_policies_and_controls(self):
        cases = run.matrix()
        self.assertEqual(len(cases), len({tuple(sorted(c.items())) for c in cases}))
        for family in (4, 6):
            for role, policies in (("client", ("hmac",)), ("server", ("hmac", "linux"))):
                for policy in policies:
                    required = {"ordinary", "warm", "deferred", "disabled", "client-disabled", "strip", "drop", "stale"}
                    required |= {"refused"} if role == "client" else {"expiry", "partial"}
                    if role == "server" and policy == "linux":
                        required.add("expiry-no-issuer")
                    actual = {c["scenario"] for c in cases if (c["family"], c["role"], c["policy"]) == (family, role, policy)}
                    self.assertTrue(required <= actual)


class AdminScenario(unittest.TestCase):
    def test_admin_cases_without_inherited_proof_cannot_reach_setup(self):
        for kind, scenario in (("admin", "utility"), ("native-admin", "utility"), ("admin", "refuse"),
                               ("admin", "reenable")):
            with patch.dict(os.environ, {}, clear=True), patch.object(icmp, "setup") as setup, \
                    patch.object(run, "setup") as native_setup:
                with self.assertRaises(KeyError):
                    run.child(dict(kind=kind, family=4, scenario=scenario))
                setup.assert_not_called()
                native_setup.assert_not_called()

    def test_cases_cover_both_embeddings_and_families(self):
        self.assertEqual({(c["kind"], c["family"], c["scenario"]) for c in admin.cases()},
                         {(k, f, "utility") for k in ("admin", "native-admin") for f in (4, 6)}
                         | {("admin", 4, "refuse")} | {("admin", f, "reenable") for f in (4, 6)})
        self.assertEqual(len(admin.cases()), 7)
        self.assertFalse(any(c in icmp.cases() or c in run.matrix() for c in admin.cases()))
        # The reenable case's waits fit the per-case limit with its setup.
        self.assertLess(admin.DISABLED_WAIT + admin.PROBE_WAIT + admin.REPLY_WAIT, 60)
        # IPv6 administrative values are never below its minimum link MTU;
        # downward is below the 1500 accepted estimate, upward above it.
        for family, values in admin.VALUES.items():
            self.assertTrue(values["downward"] < values["upward"] < 1500, family)
            self.assertTrue(family == 4 or min(values.values()) >= 1280, family)
        self.assertTrue(admin.IPV4_OFFLINK < admin.VALUES[4]["disabled"] < admin.VALUES[4]["downward"])

    def test_utility_records_are_parsed_per_kind(self):
        text = "route token=00ab generation=3 disabled=1 estimate=-\npath token=01 destination=198.18.2.2\n"
        self.assertEqual(admin.parse_records(text, "route"),
                         [dict(token="00ab", generation="3", disabled="1", estimate="-")])
        self.assertEqual(admin.parse_records(text, "path"), [dict(token="01", destination="198.18.2.2")])

    def test_identification_check_requires_one_nonzero_unrepeated_id_per_datagram(self):
        whole = lambda t, i: dict(fragmented=False, protocol=6, time_ns=t, ip_id=i)
        piece = lambda i: dict(fragmented=True, protocol=17, time_ns=0, ip_id=i)
        self.assertEqual(admin.check_ids([whole(1, 5), whole(2, 6), piece(7), piece(7)]), 3)
        with self.assertRaisesRegex(AssertionError, "repeated"):
            admin.check_ids([whole(1, 5), whole(2, 5)])
        with self.assertRaisesRegex(AssertionError, "zero"):
            admin.check_ids([whole(1, 0)])

    def test_capture_reports_the_whole_packet_identification(self):
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0xbeef, 0, 64, 17, 0,
                             bytes([198, 18, 1, 2]), bytes([198, 18, 2, 2]))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        event = icmp.parse(header + struct.pack("!HHHH", 1, 2, 8, 0))
        self.assertEqual((event["ip_id"], event["df"], event["fragmented"]), (0xbeef, False, False))


class IcmpScenario(unittest.TestCase):
    def test_icmp_case_without_inherited_proof_cannot_reach_setup(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(icmp, "setup") as setup:
            with self.assertRaises(KeyError):
                run.child(dict(kind="icmp", family=4, scenario="udp-quoted"))
            setup.assert_not_called()

    def test_cases_cover_both_families_both_quoted_transports_the_forged_control_fanout_and_staged_repair(self):
        self.assertEqual({(c["family"], c["scenario"]) for c in icmp.cases()},
                         {(f, s) for f in (4, 6) for s in ("udp-quoted", "tcp-quoted", "forged", "shared-fanout",
                                                            "tcp-staged", "tcp-burst", "fragment", "probe-mode",
                                                            "fragment-ptb", "adjunct-silence", "probe-report")}
                         | {(4, "route-isolation")})
        self.assertFalse(any(c in run.matrix() for c in icmp.cases()))
        self.assertEqual(len(icmp.cases()), 23)

    def test_driven_cases_state_their_deployment_configuration(self):
        self.assertEqual(set(icmp.DRIVER_SETTINGS), set(icmp.DRIVEN))
        # fragment-ptb's first fragments exceed the 1280 egress with nothing learned.
        self.assertGreater(icmp.fragment_packet(4, icmp.DRIVER_SETTINGS["fragment-ptb"]["initial"]), 1280)
        self.assertGreater(icmp.fragment_packet(6, icmp.DRIVER_SETTINGS["fragment-ptb"]["initial"]), 1280)
        # Only the silence case enables the adjunct.
        self.assertEqual({s for s, c in icmp.DRIVER_SETTINGS.items() if c["adjunct"]}, {"adjunct-silence"})

    def test_silence_counters_sum_the_owned_drop_rules(self):
        listing = {"nftables": [{"metainfo": {}}, {"table": {"name": icmp.SILENCE_TABLE}}] + [
            {"rule": {"expr": [{"match": {}}, {"counter": {"packets": n, "bytes": 0}}, {"drop": None}]}}
            for n in (3, 0)]}
        result = icmp.silence_counters(lambda args: __import__("json").dumps(listing))
        self.assertEqual((result["dropped"], len(result["rules"])), (3, 2))

    def fragments(self, family, datagram, data_per_fragment, order):
        """Physical fragments of DATAGRAM (atomic IP packet) as captured events."""
        hl = 20 if family == 4 else 40
        body = datagram[hl:]
        pieces = []
        for offset in range(0, len(body), data_per_fragment):
            chunk, more = body[offset:offset + data_per_fragment], offset + data_per_fragment < len(body)
            if family == 4:
                header = bytearray(datagram[:20])
                struct.pack_into("!HHH", header, 2, 20 + len(chunk), 0x77, 0x4000 | (0x2000 if more else 0) | offset // 8)
                header[10:12] = b"\0\0"
                struct.pack_into("!H", header, 10, checksum(bytes(header)))
                packet = bytes(header) + chunk
            else:
                header = bytearray(datagram[:40])
                struct.pack_into("!H", header, 4, 8 + len(chunk))
                header[6] = 44
                packet = bytes(header) + struct.pack("!BBHI", datagram[6], 0, offset | more, 0x12345678) + chunk
            event = icmp.parse(packet)
            event.update(direction="from-ntcp", time_ns=offset, raw=packet)
            pieces.append(event)
        return [pieces[i] for i in order(len(pieces))]

    def test_capture_reassembles_fragments_before_transport_parsing(self):
        for family in (4, 6):
            original = bytearray(self.original(family))
            hl = 20 if family == 4 else 40
            pseudo = (original[12:20] + bytes([0, 17]) + struct.pack("!H", len(original) - hl) if family == 4
                      else original[8:40] + struct.pack("!I", len(original) - hl) + bytes([0, 0, 0, 17]))
            original[hl + 6:hl + 8] = b"\0\0"
            struct.pack_into("!H", original, hl + 6, checksum(bytes(pseudo + original[hl:])))
            for order in (lambda n: range(n), lambda n: reversed(range(n))):
                pieces = self.fragments(family, bytes(original), 600, order)
                self.assertTrue(all(p["fragmented"] and "sport" not in p for p in pieces))
                (datagram, fragments), = icmp.reassemble(pieces)
                self.assertEqual(datagram["payload"], len(original) - hl - 8)
                self.assertTrue(datagram["checksum_valid"] and datagram["dport"] == 18090, family)
                self.assertEqual([f["offset"] for f in fragments], [0, 600, 1200])
            # A missing fragment leaves nothing complete.
            self.assertEqual(icmp.reassemble(self.fragments(family, bytes(original), 600, lambda n: range(1, n))), [])
        self.assertEqual(icmp.fragment_packet(4, 1024), 1020)
        self.assertEqual(icmp.fragment_packet(4, 1280), 1276)
        self.assertEqual(icmp.fragment_packet(6, 1280), 1280)

    def original(self, family):
        payload = bytes(range(200)) * 8
        if family == 4:
            header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0x4000, 64, 17, 0,
                                           bytes([198, 18, 1, 2]), bytes([198, 18, 2, 2])))
            struct.pack_into("!H", header, 10, checksum(bytes(header)))
        else:
            header = bytearray(struct.pack("!IHBB16s16s", 6 << 28, 8 + len(payload), 17, 64,
                                           bytes(15) + b"\2", bytes(15) + b"\3"))
        return bytes(header) + struct.pack("!HHHH", 18080, 18090, 8 + len(payload), 0x1234) + payload

    def test_forged_variants_alter_a_correlated_field_with_well_formed_inner_headers(self):
        for family in (4, 6):
            original = self.original(family)
            exact = icmp.mutate(family, original, "exact")
            self.assertTrue(icmp.quotes(exact, original))
            self.assertEqual(len(exact), 548 if family == 4 else 1232)
            for name in ("udp-checksum", "udp-port", "ip-length", "destination"):
                forged = icmp.mutate(family, original, name)
                self.assertEqual(len(forged), len(exact))
                self.assertFalse(icmp.quotes(forged, original), (family, name))
                if family == 4:
                    self.assertEqual(checksum(forged[:20]), 0, name)
            # Router-mutated TTL/hop limit alone does not break the match.
            routed = bytearray(exact)
            routed[8 if family == 4 else 7] -= 1
            self.assertTrue(icmp.quotes(bytes(routed), original))

    def test_decoder_reports_ptb_mtu_and_quote(self):
        original = self.original(4)
        quote = icmp.mutate(4, original, "exact")
        body = bytearray(struct.pack("!BBHHH", 3, 4, 0, 0, 1280) + quote)
        struct.pack_into("!H", body, 2, checksum(bytes(body)))
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 1, 0,
                                       bytes([198, 18, 1, 1]), bytes([198, 18, 1, 2])))
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        event = icmp.parse(bytes(header + body))
        self.assertTrue(event["ptb"] and event["checksum_valid"] and event["ip_checksum_valid"])
        self.assertEqual((event["mtu"], event["source"], event["quote"]), (1280, "198.18.1.1", quote))

    def tcp(self, options):
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(options), 0, 0x4000, 64, 6, 0,
                             bytes([198, 18, 2, 2]), bytes([198, 18, 1, 2]))
        tcp = bytearray(struct.pack("!HHIIBBHHH", 18082, 18081, 7, 9, (20 + len(options)) // 4 << 4, 0x10,
                                    1000, 0, 0) + options)
        pseudo = header[12:20] + bytes([0, 6]) + struct.pack("!H", len(tcp))
        struct.pack_into("!H", tcp, 16, checksum(pseudo + bytes(tcp)))
        return icmp.parse(header + bytes(tcp))

    def test_decoder_reports_handshake_negotiation(self):
        # MSS 8960, SACK-permitted, timestamps, NOP, window scale 7.
        options = (struct.pack("!BBH", 2, 4, 8960) + b"\4\2" + struct.pack("!BBII", 8, 10, 11, 0)
                   + b"\1" + struct.pack("!BBB", 3, 3, 7))
        event = self.tcp(options)
        self.assertTrue(event["checksum_valid"])
        self.assertEqual((event["mss"], event["window_scale"], event["sack_permitted"], event["timestamp"],
                          event["window"]), (8960, 7, True, (11, 0), 1000))
        self.assertEqual(icmp.negotiation(b""), dict(mss=None, window_scale=None, sack_permitted=False, timestamp=None))
        # A wrong option length or a truncated option yields nothing.
        for bad in (struct.pack("!BBHB", 2, 5, 1460, 0) + b"\0\0\0", struct.pack("!BBH", 2, 4, 1460)[:3]):
            self.assertEqual(icmp.negotiation(bad)["mss"], None, bad)

    def test_decoder_reports_sack_blocks_after_other_options(self):
        # NOP, NOP, timestamps, NOP, NOP, SACK with two blocks.
        options = (b"\1\1" + struct.pack("!BBII", 8, 10, 5, 6) + b"\1\1"
                   + struct.pack("!BBIIII", 5, 18, 100, 200, 0xfffffff0, 16))
        event = self.tcp(options)
        self.assertTrue(event["checksum_valid"])
        self.assertEqual(event["sack"], [(100, 200), (0xfffffff0, 16)])
        self.assertIsNone(self.tcp(b"")["sack"])
        # A truncated or misaligned SACK option yields no blocks.
        self.assertIsNone(self.tcp(struct.pack("!BBI", 5, 10, 1) + b"\0\0")["sack"])
        self.assertIsNone(self.tcp(struct.pack("!BBII", 5, 9, 1, 2) + b"\0\0\0")["sack"])


class MssScenario(unittest.TestCase):
    def test_mss_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in mss.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(mss, "setup") as setup, \
                    patch.object(icmp, "setup") as icmp_setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()
                icmp_setup.assert_not_called()

    def test_cases_cover_both_families_and_both_scenarios(self):
        self.assertEqual({(c["kind"], c["family"], c["scenario"]) for c in mss.cases()},
                         {("mss", f, s) for f in (4, 6) for s in ("receive-offer", "send-space")})
        self.assertEqual(len(mss.cases()), 4)
        self.assertFalse(any(c in icmp.cases() or c in admin.cases() or c in options.cases() or c in run.matrix()
                             for c in mss.cases()))
        # Unequal links, both at least the IPv6 minimum and above the egress.
        self.assertTrue(1280 < mss.SMALL_MTU < mss.LARGE_MTU)
        self.assertEqual(run.TWO_LINK.name, "two_link")

    def test_receive_mss_derivation(self):
        two = [(1400, 65575), (9000, 65575)]
        self.assertEqual((icmp.receive_mss(4, two, 65535), icmp.receive_mss(6, two, 65575)), (8960, 8940))
        # Reassembly below the largest link, and no reassembly term.
        self.assertEqual(icmp.receive_mss(4, two, 1500), 1460)
        self.assertEqual(icmp.receive_mss(4, two, None), 8960)
        # A link that cannot receive its own MTU counts at its capacity.
        self.assertEqual(icmp.receive_mss(4, [(9000, 2000), (1500, 65575)], 65535), 1960)
        # The family wire limits: 65495 exactly when everything supports it.
        self.assertEqual(icmp.receive_mss(4, [(65535, 65575)], 65535), 65495)
        self.assertEqual(icmp.receive_mss(4, [(65535, 65575)], 65534), 65494)
        self.assertEqual(icmp.receive_mss(6, [(65575, 65575)], None), 65515)
        self.assertEqual(icmp.receive_mss(6, [(70000, 70000)], None), 65515)

    def test_send_space_rounds_to_whole_segments_and_keeps_a_sub_segment_buffer(self):
        q = 1348
        for capacity, expected in ((1, 1), (q - 1, q - 1), (q, q), (q + 1, q), (2 * q - 1, q), (3 * q, 3 * q),
                                   (2 * q + q // 2, 2 * q), ((1 << 30) - 1, ((1 << 30) - 1) // q * q)):
            self.assertEqual(mss.send_space(capacity, q), expected, capacity)

    def segment(self, direction, seq, ack, payload, flags=0x10):
        if direction == "from-ntcp":
            ports = (18100, 18082)
        else:
            ports = (18082, 18100)
        return dict(protocol=6, direction=direction, sport=ports[0], dport=ports[1], seq=seq, ack=ack,
                    payload=payload, flags=flags)

    def test_outstanding_counts_distinct_payload_above_the_cumulative_ack(self):
        base = 0xfffffff0  # sequence wrap inside the flow
        ntcp = lambda offset, n, flags=0x18: self.segment("from-ntcp", (base + offset) & 0xffffffff, 0, n, flags)
        peer = lambda ack: self.segment("to-ntcp", 0, (base + ack) & 0xffffffff, 0)
        events = [peer(0), ntcp(0, 100), ntcp(100, 100), ntcp(0, 100), dict(protocol=1, direction="to-ntcp"),
                  peer(100), ntcp(200, 100), ntcp(300, 0, 0x11), peer(300)]
        counts, first = mss.outstanding(events, (18100, 18082), base)
        # A retransmission adds nothing; a FIN occupies no payload.
        self.assertEqual(counts, [0, 100, 200, 200, 100, 200, 0])
        self.assertEqual((first, max(counts[:first])), (4, 200))
        # Another flow's segments are ignored.
        other = dict(self.segment("from-ntcp", base, 0, 500), sport=18101)
        self.assertEqual(mss.outstanding([other], (18100, 18082), base), ([], None))

    def test_handshake_selects_one_connection(self):
        syn = dict(self.segment("from-ntcp", 7, 0, 0, 0x02), mss=8960)
        old = dict(self.segment("to-ntcp", 1, 0, 0, 0x12), sport=18083)
        reply = dict(self.segment("to-ntcp", 9, 8, 0, 0x12), mss=1460)
        self.assertEqual(mss.handshake([old, syn, reply], sport=18100), (syn, reply))
        with self.assertRaisesRegex(AssertionError, "no SYN-ACK"):
            mss.handshake([syn, old], sport=18100)


class OptionScenario(unittest.TestCase):
    def test_option_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in options.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(icmp, "setup") as setup, \
                    patch.object(run, "setup") as native_setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()
                native_setup.assert_not_called()

    def test_cases_cover_each_embedding_the_disabled_interpretation_profile_and_origination(self):
        self.assertEqual({(c["kind"], c["family"], c["embedding"], c["scenario"]) for c in options.cases()},
                         {("ip-options", 4, "tun_echo", "interpreted"), ("ip-options", 4, "tun_echo", "uninterpreted"),
                          ("ip-options", 4, "native", "interpreted"), ("ip-options", 4, "tun_echo", "originated-combined"),
                          ("ip-options", 4, "tun_echo", "originated-addressed")})
        self.assertEqual(len(options.cases()), 5)
        self.assertFalse(any(c in icmp.cases() or c in admin.cases() or c in run.matrix() for c in options.cases()))
        # Every request's option area fits the 40-octet IPv4 limit.
        for name, packet, _ in options.requests("198.18.1.1", "198.18.1.2", "198.18.2.2", "198.18.1.1", 1, True):
            self.assertLessEqual((packet[0] & 15) * 4, 60, name)
            self.assertEqual(checksum(packet[:(packet[0] & 15) * 4]), 0, name)

    def reply(self, request, local, stamps):
        """REQUEST's RR/TS area recorded at LOCAL with the given timestamps."""
        area = b""
        for kind, option in options.tlvs(request):
            if kind not in (7, 68):
                continue
            expected, at = options.recorded(option, local)
            if at is not None:
                expected = expected[:at] + struct.pack("!I", stamps.pop(0)) + expected[at + 4:]
            area += expected
        return options.pad(area)

    def test_continuation_accepts_one_recording_with_a_bracketed_or_marked_time(self):
        local = "198.18.1.2"
        request = options.pad(options.RR + options.TS_ADDRESSED + bytes([30, 2]))
        good = self.reply(request, local, [0x80000123])
        self.assertEqual(good[:15], bytes([7, 15, 12, 198, 18, 9, 9, 198, 18, 1, 2]) + bytes(4))
        self.assertEqual(good[15:27], bytes([68, 20, 13, 1, 198, 18, 1, 2, 0x80, 0, 1, 0x23]))
        unhealthy = (None, None)
        self.assertEqual(options.check_continuation(request, good, local, unhealthy), [0x80000123])
        # 2026-11-03 12:00:00.250 UT and 50 ms later, in nanoseconds.
        noon = (1_793_707_200 * 1000 + 250) * 1_000_000
        healthy = (noon, noon + 50_000_000)
        standard = self.reply(request, local, [43_200_260])
        self.assertEqual(options.check_continuation(request, standard, local, healthy), [43_200_260])
        bad = {
            "unmarked timestamp without a healthy bracket": (self.reply(request, local, [43_200_260]), unhealthy),
            "unmarked timestamp after one healthy read": (standard, (noon, None)),
            "unmarked timestamp before the window": (self.reply(request, local, [43_200_249]), healthy),
            "unmarked timestamp after the window": (self.reply(request, local, [43_200_301]), healthy),
            "no recording": (options.pad(options.RR + options.TS_ADDRESSED), healthy),
            "recorded twice": (self.reply(self.reply(request, local, [0x80000001]), local, [0x80000002]), healthy),
            "truncated": (options.pad(options.RR[:11] + options.TS_ADDRESSED), healthy),
            "unknown reflected": (options.pad(good[:35] + bytes([30, 2])), healthy),
            "other address": (self.reply(request, "198.18.1.3", [0x80000123]), healthy),
        }
        for name, (reply, window) in bad.items():
            with self.assertRaises(AssertionError, msg=name):
                options.check_continuation(request, reply, local, window)
        # A full timestamp area only increments the overflow.
        full = bytes([68, 12, 13, 0x21]) + bytes(8)
        self.assertEqual(options.recorded(full, local), (bytes([68, 12, 13, 0x31]) + bytes(8), None))

    def test_standard_time_needs_healthy_reads_and_handles_midnight(self):
        # 23:59:59.990 UT to 00:00:00.010 UT the next day.
        before = (1_793_750_399 * 1000 + 990) * 1_000_000
        window = (before, before + 20_000_000)
        for value in (86_399_990, 86_399_999, 0, 10):
            self.assertTrue(options.standard_time(value, window), value)
        for value in (86_399_989, 11, 43_200_000, 86_400_000):
            with self.assertRaises(AssertionError, msg=value):
                options.standard_time(value, window)
        self.assertFalse(options.standard_time(0x80000000 | 11, (None, None)))
        ok = dict(state=0, status=0, maxerror=0, seconds=1, fraction=2)
        self.assertEqual(options.healthy_time(**ok), 1_000_002_000)
        self.assertEqual(options.healthy_time(**dict(ok, status=options.STA_NANO)), 1_000_000_002)
        for state in (1, 2, 4):  # TIME_INS, TIME_DEL, TIME_WAIT
            self.assertIsNotNone(options.healthy_time(**dict(ok, state=state)))
        self.assertIsNotNone(options.healthy_time(**dict(ok, maxerror=options.MAX_ERROR_US)))
        PPSSIGNAL = options.STA_PPSSIGNAL
        for name, changes in {
            "failed call": dict(state=-1), "TIME_OOP": dict(state=options.TIME_OOP),
            "TIME_ERROR": dict(state=options.TIME_ERROR),
            "unsynchronized": dict(status=options.STA_UNSYNC),
            "unsynchronized under TIME_WAIT": dict(state=4, status=options.STA_UNSYNC),
            "clock error": dict(status=options.STA_CLOCKERR),
            "PPS frequency without signal": dict(status=options.STA_PPSFREQ),
            "PPS time without signal": dict(status=options.STA_PPSTIME),
            "PPS time jitter": dict(status=options.STA_PPSTIME | options.STA_PPSJITTER | PPSSIGNAL),
            "PPS frequency wander": dict(status=options.STA_PPSFREQ | options.STA_PPSWANDER | PPSSIGNAL),
            "PPS frequency error": dict(status=options.STA_PPSFREQ | options.STA_PPSERROR | PPSSIGNAL),
            "maximum error beyond the limit": dict(maxerror=options.MAX_ERROR_US + 1),
            "negative maximum error": dict(maxerror=-1),
        }.items():
            self.assertIsNone(options.healthy_time(**dict(ok, **changes)), name)
        # The live read is either healthy or None, never a guess.
        live = options.utc_read()
        self.assertTrue(live is None or live > 0)

    def ipv4(self, protocol, area, body):
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45 + len(area) // 4, 0, 20 + len(area) + len(body), 7, 0,
                                       64, protocol, 0, bytes([198, 18, 0, 1]), bytes([198, 18, 0, 2])) + area)
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        return bytes(header) + body

    def test_bridge_validates_variable_headers_and_forwards_icmp_only_when_asked(self):
        area = options.pad(options.RR)
        echo = options.echo_request("198.18.0.1", "198.18.0.2", options.RR, 5, 6, b"data")
        frame = bytes(12) + b"\x08\x00" + echo
        self.assertIsNone(bridge.decode(frame))
        event = bridge.decode(frame, icmp=True)
        self.assertEqual((event["header_len"], event["ip_options"], event["icmp_type"], event["identifier"],
                          event["sequence"], event["ip_hex"]), (20 + len(area), area.hex(), 8, 5, 6, echo.hex()))
        corrupt = bytearray(frame)
        corrupt[14 + 25] ^= 1  # inside the option area
        with self.assertRaisesRegex(AssertionError, "header checksum"):
            bridge.decode(bytes(corrupt), icmp=True)
        # A TCP segment after an option-bearing header is found at its IHL.
        tcp = bytearray(struct.pack("!HHIIBBHHH", 18080, 18081, 1, 2, 5 << 4, 0x10, 100, 0, 0))
        struct.pack_into("!H", tcp, 16, checksum(bytes([198, 18, 0, 1, 198, 18, 0, 2, 0, 6, 0, 20]) + bytes(tcp)))
        decoded, *_ = bridge.decode(bytes(12) + b"\x08\x00" + self.ipv4(6, area, bytes(tcp)))
        self.assertEqual((decoded["sport"], decoded["dport"], decoded["payload"]), (18080, 18081, 0))

    def test_capture_exposes_option_bytes_and_keeps_them_through_reassembly(self):
        area = options.pad(bytes([131, 7, 8, 198, 18, 1, 1]) + options.RR)
        body = struct.pack("!HHHH", 18080, 18090, 8 + 1000, 0) + bytes(range(250)) * 4
        datagram = self.ipv4(17, area, body)
        self.assertEqual(icmp.parse(datagram)["ip_options"], area.hex())
        hl = 20 + len(area)
        pieces = []
        for offset in range(0, len(body), 504):
            chunk, more = body[offset:offset + 504], offset + 504 < len(body)
            # RFC 791: later fragments carry only the copied source route.
            header = bytearray(datagram[:hl] if offset == 0 else datagram[:20] + area[:8])
            header[0] = 0x40 + len(header) // 4
            struct.pack_into("!HHH", header, 2, len(header) + len(chunk), 7, (0x2000 if more else 0) | offset // 8)
            header[10:12] = b"\0\0"
            struct.pack_into("!H", header, 10, checksum(bytes(header)))
            event = icmp.parse(bytes(header) + chunk)
            event.update(direction="from-ntcp", time_ns=offset, raw=bytes(header) + chunk)
            pieces.append(event)
        self.assertEqual(pieces[1]["ip_options"], area[:8].hex())
        (whole, _), = icmp.reassemble(pieces[::-1])
        self.assertEqual((whole["ip_options"], whole["payload"]), (area.hex(), 1000))
        self.assertTrue(whole["checksum_valid"] and whole["ip_checksum_valid"])
        self.assertEqual(icmp.public(whole)["ip_options"], area.hex())

    def test_originated_plans_state_three_registrations_and_fit_or_exceed_the_option_area(self):
        # ntcp, the router and the destination each record once.
        def octets(settings):
            size = 0
            if "NTCP_ORIGINATE_RR" in settings:
                slots, expected = map(int, settings["NTCP_ORIGINATE_RR"].split(","))
                self.assertEqual((slots, expected), (3, 3))
                size += 3 + 4 * slots
            if "NTCP_ORIGINATE_TS" in settings:
                form, slots, expected = settings["NTCP_ORIGINATE_TS"].split(",")
                self.assertEqual((int(slots), int(expected)), (3, 3))
                size += 4 + (8 if form == "addresses" else 4) * int(slots)
            return size
        combined, addressed = (options.ORIGINATIONS[s] for s in ("originated-combined", "originated-addressed"))
        self.assertEqual((octets(combined["settings"]), combined["octets"], combined["kinds"]), (31, 32, [7, 68]))
        self.assertEqual((octets(addressed["settings"]), addressed["octets"], addressed["kinds"]), (28, 28, [68]))
        self.assertEqual(octets(options.OVERSIZED_ORIGINATION), 43)
        self.assertIn("required_octets: 44, maximum: 40", options.OVERSIZED_REFUSAL)
        self.assertEqual(icmp.Ntcp.command("tun_echo", "198.18.1.2", "198.18.2.2:18083")[-1], "198.18.2.2:18083")
        self.assertEqual(len(icmp.Ntcp.command("tun_echo", "198.18.1.2")), 4)

    def originated(self, area, ttl=64, kept=None):
        """An originated SYN from ntcp to the listener with option AREA; KEPT
        keeps that header checksum instead of computing it."""
        src, dst = bytes([198, 18, 1, 2]), bytes([198, 18, 2, 2])
        tcp = bytearray(struct.pack("!HHIIBBHHH", 18080, 18083, 1, 0, 5 << 4, 0x02, 1000, 0, 0))
        struct.pack_into("!H", tcp, 16, checksum(src + dst + bytes([0, 6, 0, 20]) + bytes(tcp)))
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45 + len(area) // 4, 0, 40 + len(area), 0, 0x4000, ttl, 6,
                                       0, src, dst) + area)
        header[10:12] = kept if kept is not None else struct.pack("!H", checksum(bytes(header)))
        raw = bytes(header) + bytes(tcp)
        return dict(icmp.parse(raw), raw=raw)

    # Combined RR and timestamp-only TS (one time 0x033980bb) at the origin,
    # after the router and after the destination, as captured.
    COMBINED = ("070f08c6120102000000000000000044100900033980bb000000000000000000",
                "070f0cc6120102c61203010000000044100d00033980bb033980bb0000000000",
                "070f10c6120102c6120301c612020244101100033980bb033980bb033980bb00")
    ADDRESSED = ("441c0d01c61201020339858d00000000000000000000000000000000",
                 "441c1501c61201020339858dc61201010339858e0000000000000000",
                 "441c1d01c61201020339858dc61201010339858ec61202020339858e")

    def boundaries(self, areas, hop_ttl=63):
        first = self.originated(bytes.fromhex(areas[0]))
        hop = self.originated(bytes.fromhex(areas[1]), hop_ttl)
        return first, hop, self.originated(bytes.fromhex(areas[2]), hop_ttl, kept=hop["raw"][10:12])

    def test_originated_trace_requires_each_boundary_recording_once_at_fixed_size(self):
        combined, addressed = options.ORIGINATIONS["originated-combined"], options.ORIGINATIONS["originated-addressed"]
        result = options.trace(self.boundaries(self.COMBINED), combined, "198.18.1.2", "198.18.2.2")
        self.assertEqual((result["router"], result["times"], result["ttl"]), ({7: "198.18.3.1"}, [0x033980bb] * 3, [64, 63, 63]))
        self.assertTrue(result["destination_checksum_kept"])
        result = options.trace(self.boundaries(self.ADDRESSED), addressed, "198.18.1.2", "198.18.2.2")
        self.assertEqual((result["router"], result["times"]), ({68: "198.18.1.1"}, [0x0339858d, 0x0339858e, 0x0339858e]))
        # A destination that recomputes its header checksum is accepted too.
        first, hop, _ = self.boundaries(self.COMBINED)
        recomputed = self.originated(bytes.fromhex(self.COMBINED[2]), 63)
        self.assertFalse(options.trace((first, hop, recomputed), combined, "198.18.1.2", "198.18.2.2")["destination_checksum_kept"])

        def edit(area, offset, value):
            data = bytearray.fromhex(area)
            data[offset] = value
            return data.hex()
        bad = {
            "origin did not record": (self.COMBINED[0][:6] + "00" * 4 + self.COMBINED[0][14:],) + self.COMBINED[1:],
            "origin pointer": (edit(self.COMBINED[0], 2, 12),) + self.COMBINED[1:],
            "router did not record": (self.COMBINED[0], self.COMBINED[0], self.COMBINED[2]),
            "unwritten entry nonzero": (edit(self.COMBINED[0], 14, 1),) + self.COMBINED[1:],
            "timestamp overflow": self.COMBINED[:2] + (edit(self.COMBINED[2], 18, 0x10),),
            "earlier time changed": self.COMBINED[:2] + (edit(self.COMBINED[2], 22, 0),),
            "earlier address changed": self.COMBINED[:2] + (edit(self.COMBINED[2], 6, 3),),
            "other destination": self.COMBINED[:2] + (edit(self.COMBINED[2], 14, 3),),
            "padding not EOL": self.COMBINED[:2] + (edit(self.COMBINED[2], 31, 1),),
            "shrunk timestamp": tuple(edit(a, 16, 12) for a in self.COMBINED),
        }
        for name, areas in bad.items():
            with self.assertRaises(AssertionError, msg=name):
                options.trace(self.boundaries(areas), combined, "198.18.1.2", "198.18.2.2")
        with self.assertRaises(AssertionError, msg="TTL not decremented"):
            options.trace(self.boundaries(self.COMBINED, hop_ttl=64), combined, "198.18.1.2", "198.18.2.2")
        first, hop, last = self.boundaries(self.COMBINED)
        broken = dict(hop, raw=hop["raw"][:10] + b"\0\0" + hop["raw"][12:], ip_checksum_valid=False)
        with self.assertRaises(AssertionError, msg="invalid forwarded checksum"):
            options.trace((first, broken, last), combined, "198.18.1.2", "198.18.2.2")
        stale = self.originated(bytes.fromhex(self.COMBINED[2]), 63, kept=b"\0\1")
        with self.assertRaises(AssertionError, msg="invalid delivered checksum"):
            options.trace((first, hop, stale), combined, "198.18.1.2", "198.18.2.2")
        with self.assertRaises(AssertionError, msg="unplanned size"):
            options.trace(self.boundaries(self.ADDRESSED), combined, "198.18.1.2", "198.18.2.2")

    def test_originated_times_judge_ntcp_by_its_bracket_and_linux_by_the_realtime_window(self):
        # 2026-11-03 12:00:00.250 UT and 50 ms later, in nanoseconds.
        noon = (1_793_707_200 * 1000 + 250) * 1_000_000
        window, realtime = (noon, noon + 50_000_000), (noon - 1_000_000, noon + 51_000_000)
        self.assertTrue(options.judge_times([43_200_260, 43_200_261, 43_200_270], window, realtime))
        # A marked ntcp time needs no bracket; Linux's still need the window.
        self.assertFalse(options.judge_times([0x80000005, 43_200_261, 43_200_261], (None, None), realtime))
        for name, (times, clock) in {
            "unmarked ntcp time without a healthy bracket": ([43_200_260, 43_200_261, 43_200_270], (noon, None)),
            "ntcp time outside its bracket": ([43_200_301, 43_200_302, 43_200_302], window),
            "marked Linux time": ([43_200_260, 0x80000005, 43_200_270], window),
            "Linux time outside the window": ([0x80000005, 43_200_200, 43_200_270], window),
            "destination before router": ([43_200_260, 43_200_270, 43_200_261], window),
            "router before ntcp": ([43_200_270, 43_200_260, 43_200_271], window),
        }.items():
            with self.assertRaises(AssertionError, msg=name):
                options.judge_times(times, clock, realtime)


class SegmentRouting(unittest.TestCase):
    D, S1, SOURCE = "2001:db8:92::2", "2001:db8:94::1", "2001:db8:91::2"

    def test_srh_case_without_inherited_proof_cannot_reach_setup(self):
        for case in srh.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(icmp, "setup") as setup, \
                    patch.object(run, "setup") as native:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()
                native.assert_not_called()

    def test_cases_cover_both_embeddings(self):
        self.assertEqual({(c["kind"], c["family"], c["embedding"], c["scenario"]) for c in srh.cases()},
                         {("srh", 6, "tun_echo", "transit-ptb"), ("srh", 6, "native", "endpoint")})
        self.assertEqual(len(srh.cases()), 2)
        self.assertFalse(any(c in icmp.cases() or c in admin.cases() or c in options.cases() or c in mss.cases()
                             or c in run.matrix() for c in srh.cases()))

    def packet(self, protocol=6, left=1, fragment=None):
        """A TCP segment to D sent through S1: base header, SRH [D, S1],
        optionally a Fragment header, then the transport."""
        import ipaddress
        d, s1, source = (ipaddress.ip_address(a).packed for a in (self.D, self.S1, self.SOURCE))
        tcp = bytearray(struct.pack("!HHIIBBHHH", 18080, 40000, 7, 9, 5 << 4, 0x10, 1024, 0, 0)) + b"data"
        pseudo = source + d + struct.pack("!I", len(tcp)) + b"\0\0\0\x06"
        struct.pack_into("!H", tcp, 16, checksum(pseudo + bytes(tcp)))
        srh = struct.pack("!BBBBBBH", 44 if fragment else protocol, 4, 4, left, 1, 0, 0) + d + s1
        frag = struct.pack("!BBHI", protocol, 0, fragment[0] | fragment[1], 0x77) if fragment else b""
        body = srh + frag + bytes(tcp)
        base = struct.pack("!IHBB", 6 << 28, len(body), 43, 64) + source + s1
        return base + body, bytes(tcp)

    def test_capture_walks_the_chain_and_checks_transport_with_the_final_destination(self):
        packet, _ = self.packet()
        event = icmp.parse(packet)
        self.assertEqual((event["destination"], event["final_destination"], event["header_len"]),
                         (self.S1, self.D, 80))
        routing, = event["extensions"]
        self.assertEqual((routing["routing_type"], routing["segments_left"], routing["last_entry"],
                          routing["segments"]), (4, 1, 1, [self.D, self.S1]))
        self.assertTrue(event["checksum_valid"])
        self.assertEqual(event["payload"], 4)
        # With Segments Left 0 the base destination (S1 here) is final, so
        # the same bytes no longer check.
        zero, _ = self.packet(left=0)
        self.assertFalse(icmp.parse(zero)["checksum_valid"])
        # A truncated quote is walked as far as its bytes go.
        quote = icmp.parse(packet[:60])
        self.assertIsNone(quote["protocol"])
        self.assertEqual(quote["destination"], self.S1)

    def test_bridge_forwards_extension_bearing_tcp_and_icmpv6(self):
        packet, _ = self.packet()
        frame = bytes(12) + b"\x86\xdd" + packet
        event = bridge.decode(frame)[0]
        self.assertEqual((event["destination"], event["final_destination"]), (self.S1, self.D))
        self.assertEqual(event["extensions"][0]["segments"], [self.D, self.S1])
        corrupt = bytearray(frame)
        corrupt[-1] ^= 1
        with self.assertRaises(AssertionError):
            bridge.decode(bytes(corrupt))

    def test_reassembly_keeps_the_unfragmentable_part(self):
        import ipaddress
        packet, tcp = self.packet(fragment=(0, 0))
        # Cut the transport into two fragments behind base + SRH.
        first_data, second_data = tcp[:16], tcp[16:]
        events = []
        for offset, more, data in ((0, 1, first_data), (16, 0, second_data)):
            prefix = bytearray(packet[:80 + 8])
            struct.pack_into("!H", prefix, 80 + 2, offset | more)
            whole = bytes(prefix) + data
            whole = whole[:4] + struct.pack("!H", len(whole) - 40) + whole[6:]
            event = icmp.parse(whole)
            event.update(direction="from-ntcp", time_ns=offset, raw=whole)
            events.append(event)
        self.assertTrue(all(e["fragmented"] and e["header_len"] == 88 for e in events))
        (datagram, pieces), = icmp.reassemble(events)
        self.assertEqual(datagram["raw"][:80][40], 6, "SRH Next Header repaired")
        self.assertEqual(datagram["raw"][6], 43)
        self.assertEqual(len(datagram["raw"]), 80 + len(tcp))
        self.assertTrue(datagram["checksum_valid"])
        self.assertEqual(datagram["final_destination"], self.D)
        self.assertEqual(str(ipaddress.ip_address(datagram["raw"][24:40])), self.S1)


class ScopedScenario(unittest.TestCase):
    NATIVE_MAC, PEER_MAC = "02:00:00:18:0a:02", "02:00:00:18:0a:01"

    def test_scoped_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in scoped.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(scoped, "setup") as setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()

    def test_cases_cover_one_native_two_link_runtime_and_tun_echo(self):
        self.assertEqual({(c["kind"], c["family"], c["embedding"], c["scenario"]) for c in scoped.cases()},
                         {("scoped", 6, "native", "two-link"), ("scoped", 6, "tun_echo", "link-local-peer")})
        others = icmp.cases() + admin.cases() + options.cases() + mss.cases() + srh.cases() + run.matrix()
        self.assertFalse(any(c in others for c in scoped.cases()))
        # Different first-hop MTUs; the report lies below both, so link B
        # keeps larger packets than link A after it.
        a, b = scoped.LINKS
        self.assertTrue(1280 <= scoped.PTB_MTU < b["mtu"] < a["mtu"])
        self.assertEqual(len({a["native_mac"], a["peer_mac"], b["native_mac"], b["peer_mac"]}), 4)

    def test_one_configuration_owns_both_resolving_ports_with_the_same_address(self):
        text = scoped.config()
        self.assertNotIn("next_hop_mac", text)
        self.assertNotIn("neighbor", text)
        keys = dict(line.split("=", 1) for line in text.splitlines())
        self.assertEqual((keys["io.interface"], keys["port.b.interface"]), tuple(l["native"] for l in scoped.LINKS))
        self.assertEqual(keys["io.address"], keys["port.b.address"])
        self.assertTrue(ipaddress.ip_address(keys["io.address"]).is_link_local)
        self.assertEqual(scoped.solicited_node("fe80::2"), "ff02::1:ff00:2")
        self.assertEqual(scoped.solicited_node("fe80::1:abcd:1234"), "ff02::1:ffcd:1234")

    def ipv6(self, source, destination, protocol, body, hop_limit=255, prefix=b""):
        src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
        body = bytearray(body)
        if protocol == 58:
            pseudo = src + dst + struct.pack("!I", len(body)) + bytes([0, 0, 0, 58])
            struct.pack_into("!H", body, 2, checksum(pseudo + bytes(body)))
        next_header = 0 if prefix else protocol
        header = struct.pack("!IHBB", 6 << 28, len(prefix) + len(body), next_header, hop_limit) + src + dst
        return header + prefix + bytes(body)

    def ether(self, packet, source, destination):
        return bytes.fromhex(destination.replace(":", "")) + bytes.fromhex(source.replace(":", "")) + b"\x86\xdd" + packet

    def test_frame_decodes_neighbor_discovery_targets_flags_and_options(self):
        mac = bytes.fromhex(self.NATIVE_MAC.replace(":", ""))
        ns = struct.pack("!BBHI", 135, 0, 0, 0) + ipaddress.ip_address("fe80::1").packed + bytes([1, 1]) + mac
        event = scoped.frame(self.ether(self.ipv6("fe80::2", "ff02::1:ff00:1", 58, ns), self.NATIVE_MAC,
                                        "33:33:ff:00:00:01"))
        self.assertTrue(event["checksum_valid"])
        self.assertEqual((event["icmp_type"], event["target"], event["hop_limit"], event["eth_dst"]),
                         (135, "fe80::1", 255, "33:33:ff:00:00:01"))
        self.assertEqual(event["options"], [dict(type=1, length=8, value=self.NATIVE_MAC)])
        event.update(direction="out", time_ns=1)
        self.assertEqual(scoped.lladdr(scoped.checked_nd(event), 1), self.NATIVE_MAC)
        na = struct.pack("!BBHI", 136, 0, 0, 0x60000000) + ipaddress.ip_address("fe80::1").packed + bytes([2, 1]) + mac
        event = scoped.frame(self.ether(self.ipv6("fe80::1", "fe80::2", 58, na), self.PEER_MAC, self.NATIVE_MAC))
        self.assertEqual((event["solicited"], event["override"], event["router"]), (True, True, False))
        self.assertEqual(event["options"], [dict(type=2, length=8, value=self.NATIVE_MAC)])
        # Fixed ND checks: Hop Limit 255 and a valid checksum.
        for packet in (self.ipv6("fe80::1", "fe80::2", 58, na, hop_limit=64),
                       self.ipv6("fe80::1", "fe80::2", 58, na)[:-1] + b"\0"):
            event = dict(scoped.frame(self.ether(packet, self.PEER_MAC, self.NATIVE_MAC)), direction="in", time_ns=1)
            with self.assertRaises(AssertionError):
                scoped.checked_nd(event)
        # A DAD probe: unspecified source, no option.
        dad = struct.pack("!BBHI", 135, 0, 0, 0) + ipaddress.ip_address("fe80::2").packed
        event = scoped.frame(self.ether(self.ipv6("::", "ff02::1:ff00:2", 58, dad), self.NATIVE_MAC,
                                        "33:33:ff:00:00:02"))
        self.assertEqual((event["source"], event["options"], event["target"]), ("::", [], "fe80::2"))

    def test_frame_walks_the_router_alert_to_mldv2_records(self):
        record = struct.pack("!BBH", 4, 0, 0) + ipaddress.ip_address("ff02::1:ff00:2").packed
        report = struct.pack("!BBHHH", 143, 0, 0, 0, 1) + record
        alert = bytes([58, 0, 5, 2, 0, 0, 1, 0])
        event = scoped.frame(self.ether(self.ipv6("::", "ff02::16", 58, report, hop_limit=1, prefix=alert),
                                        self.NATIVE_MAC, "33:33:00:00:00:16"))
        self.assertEqual((event["extensions"], event["icmp_type"], event["records"]),
                         ([0], 143, [dict(type=4, group="ff02::1:ff00:2")]))
        self.assertTrue(event["checksum_valid"])

    def test_injected_packet_too_big_is_checksummed_and_quotes_within_the_minimum_mtu(self):
        tcp = bytearray(struct.pack("!HHIIBBHHH", 40002, 18080, 7, 9, 5 << 4, 0x18, 1000, 0, 0) + bytes(1440))
        quoted = self.ipv6("fe80::2", "fe80::1", 6, tcp, hop_limit=64)
        self.assertEqual(len(quoted), 1500)
        frame = scoped.packet_too_big(quoted, scoped.PTB_MTU, "fe80::1", "fe80::2", self.PEER_MAC, self.NATIVE_MAC)
        event = scoped.frame(frame)
        self.assertTrue(event["checksum_valid"])
        self.assertEqual((event["icmp_type"], event["icmp_code"], event["mtu"], event["ip_length"]),
                         (2, 0, scoped.PTB_MTU, 1280))
        self.assertEqual(event["quote"], quoted[:1232])
        self.assertEqual((event["source"], event["destination"], event["eth_src"], event["eth_dst"]),
                         ("fe80::1", "fe80::2", self.PEER_MAC, self.NATIVE_MAC))

    def test_flows_select_one_connection_by_direction_and_ports(self):
        segment = lambda direction, sport, dport, payload, length: dict(
            protocol=6, direction=direction, sport=sport, dport=dport, payload=payload, ip_length=length)
        events = [segment("out", 40000, 18080, 1440, 1500), segment("in", 18080, 40000, 0, 60),
                  segment("out", 40001, 18080, 1340, 1400), segment("in", 40000, 18080, 1440, 1500),
                  dict(protocol=58, direction="in")]
        out, back = scoped.tcp_flow(events, 40000, 18080)
        self.assertEqual((len(out), len(back)), (1, 1))
        self.assertEqual((scoped.lengths(out), scoped.lengths(back)), ([1500], []))
        self.assertTrue(scoped.scoped_name("[fe80::2%3]:40000", "fe80::2", 40000, 3))
        self.assertFalse(scoped.scoped_name("[fe80::2%4]:40000", "fe80::2", 40000, 3))


class NdProxyScenario(unittest.TestCase):
    def test_nd_proxy_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in ndproxy.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(ndproxy, "setup") as setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()

    def test_cases_cover_proxy_both_directions_black_hole_and_gateway(self):
        self.assertEqual({(c["kind"], c["family"], c["scenario"], c["direction"]) for c in ndproxy.cases()},
                         {("nd-proxy", 6, "proxy-ptb", "native-client"), ("nd-proxy", 6, "proxy-ptb", "native-server"),
                          ("nd-proxy", 6, "black-hole", "native-client"),
                          ("nd-proxy", 6, "gateway-ptb", "native-client")})
        others = (icmp.cases() + admin.cases() + options.cases() + mss.cases() + srh.cases() + scoped.cases()
                  + run.matrix())
        self.assertFalse(any(c in others for c in ndproxy.cases()))
        self.assertTrue(1280 == ndproxy.DOWNSTREAM < ndproxy.FIRST_HOP)
        self.assertEqual(len(set(ndproxy.MACS.values())), 4)

    def test_destinations_are_on_link_for_the_proxy_and_routed_for_the_gateway(self):
        own = ipaddress.ip_network(ndproxy.NATIVE + "/64", strict=False)
        for scenario in ("proxy-ptb", "black-hole"):
            self.assertNotIn("gateway", ndproxy.config(scenario))
            self.assertIn(ipaddress.ip_address(ndproxy.DESTINATIONS[scenario]), own)
        keys = dict(line.split("=", 1) for line in ndproxy.config("gateway-ptb").splitlines())
        self.assertEqual(keys["io.gateway." + ndproxy.GATEWAY_PREFIX], ndproxy.ROUTER_LL)
        self.assertTrue(ipaddress.ip_address(ndproxy.ROUTER_LL).is_link_local)
        self.assertNotIn(ipaddress.ip_address(ndproxy.DESTINATIONS["gateway-ptb"]), own)
        self.assertIn(ipaddress.ip_address(ndproxy.DESTINATIONS["gateway-ptb"]),
                      ipaddress.ip_network(ndproxy.GATEWAY_PREFIX))
        for scenario in ndproxy.DESTINATIONS:
            text = ndproxy.config(scenario)
            self.assertNotIn("next_hop_mac", text)
            self.assertNotIn("neighbor", text)
            self.assertIn("io.prefix=64", text)

    def test_repair_coverage_needs_every_dropped_octet(self):
        dropped = dict(seq=0xffffff00, payload=1440)
        whole = [dict(seq=0xffffff00, payload=1220), dict(seq=(0xffffff00 + 1220) & 0xffffffff, payload=220)]
        self.assertTrue(ndproxy.covered(dropped, whole))
        self.assertFalse(ndproxy.covered(dropped, whole[:1]))
        # A segment starting before the dropped one still covers its prefix.
        self.assertTrue(ndproxy.covered(dropped, [dict(seq=0xfffffe00, payload=256 + 1440)]))
        self.assertFalse(ndproxy.covered(dropped, [dict(seq=0xfffffe00, payload=256)]))


class RedirectScenario(unittest.TestCase):
    def test_redirect_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in redirect.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(redirect, "setup") as setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()

    def test_one_case_per_family_and_configuration_follows_the_family(self):
        self.assertEqual({(c["kind"], c["family"]) for c in redirect.cases()}, {("redirect", 4), ("redirect", 6)})
        others = (icmp.cases() + admin.cases() + options.cases() + mss.cases() + srh.cases() + scoped.cases()
                  + ndproxy.cases() + run.matrix())
        self.assertFalse(any(c in others for c in redirect.cases()))
        for family in (4, 6):
            a = redirect.ADDRESSES[family]
            keys = dict(line.split("=", 1) for line in redirect.config(family, "/x/control").splitlines())
            self.assertEqual(keys["io.gateway." + a["destinations"]], a["gateway_r1"])
            self.assertEqual(keys["control.socket"], "/x/control")
            self.assertNotIn("io.next_hop_mac", keys)
            local = ipaddress.ip_network(f"{a['native']}/{a['prefix']}", strict=False)
            for name in ("destination", "other"):
                self.assertIn(ipaddress.ip_address(a[name]), ipaddress.ip_network(a["destinations"]))
                self.assertNotIn(ipaddress.ip_address(a[name]), local)
            neighbors = {k for k in keys if k.startswith("io.neighbor.")}
            if family == 4:
                self.assertEqual(neighbors, {"io.neighbor." + a["r1"], "io.neighbor." + a["r2"]})
                self.assertEqual((keys["io.neighbor." + a["r1"]], keys["io.neighbor." + a["r2"]]),
                                 (redirect.MACS[redirect.R1_UP], redirect.MACS[redirect.R2_UP]))
            else:
                self.assertFalse(neighbors)
                self.assertTrue(all(ipaddress.ip_address(a[k]).is_link_local for k in ("gateway_r1", "gateway_r2")))
        self.assertEqual(len(set(redirect.MACS.values())), len(redirect.MACS))

    def test_redirect_frames_decode_sender_target_and_quoted_tuple(self):
        eth = bytes.fromhex("020000190502" "020000190501")
        tcp = struct.pack("!HHI", 40000, 18192, 0x01020304)
        quoted = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x4000, 63, 6, 0,
                                       bytes([10, 19, 0, 2]), bytes([10, 19, 9, 1]))) + tcp
        body = bytearray(struct.pack("!BBH4s", 5, 1, 0, bytes([10, 19, 0, 3]))) + quoted
        struct.pack_into("!H", body, 2, checksum(bytes(body)))
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 1, 0,
                                       bytes([10, 19, 0, 1]), bytes([10, 19, 0, 2])))
        struct.pack_into("!H", header, 10, checksum(bytes(header)))
        e = redirect.frame(eth + b"\x08\x00" + bytes(header) + bytes(body))
        self.assertEqual((e["icmp_type"], e["icmp_code"], e["gateway"], e["source"]), (5, 1, "10.19.0.3", "10.19.0.1"))
        self.assertTrue(e["checksum_valid"])
        self.assertEqual(e["quoted"], dict(source="10.19.0.2", destination="10.19.9.1", protocol=6, sport=40000,
                                           dport=18192, seq=0x01020304))
        src, dst = ipaddress.ip_address("fe80::1").packed, ipaddress.ip_address("fd19:5::2").packed
        inner = struct.pack("!IHBB", 6 << 28, 20, 6, 63) + dst + ipaddress.ip_address("fd19:9::1").packed + tcp + bytes(12)
        message = bytearray(struct.pack("!BBHI", 137, 0, 0, 0) + ipaddress.ip_address("fe80::3").packed
                            + ipaddress.ip_address("fd19:9::1").packed
                            + bytes([2, 1]) + bytes.fromhex("020000190503")
                            + bytes([4, 1 + len(inner) // 8]) + bytes(6) + inner)
        struct.pack_into("!H", message, 2, checksum(src + dst + struct.pack("!I", len(message)) + bytes([0, 0, 0, 58])
                                                     + bytes(message)))
        packet = struct.pack("!IHBB", 6 << 28, len(message), 58, 255) + src + dst + bytes(message)
        e = redirect.frame(eth + b"\x86\xdd" + packet)
        self.assertTrue(e["checksum_valid"])
        self.assertEqual((e["icmp_type"], e["target"], e["redirect_destination"], e["tllao"], e["hop_limit"]),
                         (137, "fe80::3", "fd19:9::1", "02:00:00:19:05:03", 255))
        self.assertEqual(e["quoted"], dict(source="fd19:5::2", destination="fd19:9::1", protocol=6, sport=40000,
                                           dport=18192, seq=0x01020304))

    def test_next_hop_transition_must_be_one_way(self):
        seg = lambda i, d: dict(index=i, eth_dst=d)
        self.assertEqual(redirect.transition([seg(1, "r1"), seg(4, "r2"), seg(5, "r2")], "r1", "r2"), 4)
        self.assertEqual(redirect.transition([seg(7, "r2")], "r1", "r2"), 7)
        self.assertIsNone(redirect.transition([seg(1, "r1"), seg(2, "r1")], "r1", "r2"))
        self.assertIsNone(redirect.transition([seg(1, "r1"), seg(2, "r2"), seg(3, "r1")], "r1", "r2"))
        self.assertIsNone(redirect.transition([seg(1, "x"), seg(2, "r2")], "r1", "r2"))


class RejectedSynScenario(unittest.TestCase):
    def test_rejected_syn_cases_without_inherited_proof_cannot_reach_setup(self):
        for case in rejected.cases():
            with patch.dict(os.environ, {}, clear=True), patch.object(rejected, "setup") as setup:
                with self.assertRaises(KeyError):
                    run.child(case)
                setup.assert_not_called()

    def test_one_case_per_family_distinct_from_every_other_case(self):
        self.assertEqual({(c["kind"], c["family"], c["embedding"]) for c in rejected.cases()},
                         {("rejected-syn", 6, "tun_echo"), ("rejected-syn", 4, "tun_echo")})
        others = (icmp.cases() + admin.cases() + options.cases() + mss.cases() + srh.cases() + scoped.cases()
                  + ndproxy.cases() + redirect.cases() + run.matrix())
        self.assertFalse(any(c in others for c in rejected.cases()))

    def test_vectors_are_the_framed_sources_and_the_broadcast_recorded_hop(self):
        self.assertEqual([v[1] for v in rejected.vectors(6)], ["::", "ff02::1"])
        v4 = rejected.vectors(4)
        self.assertEqual([v[1] for v in v4], ["0.0.0.0", "224.0.0.1", "192.0.2.255", "192.0.2.7"])
        self.assertEqual(v4[-1][2], bytes([131, 7, 8, 192, 0, 2, 255, 1]))
        subnet = ipaddress.ip_network("192.0.2.0/" + rejected.ADDRESSES[4]["prefix"])
        self.assertEqual(ipaddress.ip_address(rejected.ADDRESSES[4]["broadcast"]), subnet.broadcast_address)
        self.assertNotEqual(ipaddress.ip_address(rejected.CONTROL_HOP), subnet.broadcast_address)

    def test_injected_syns_are_complete_and_checksummed(self):
        packet = rejected.syn(6, "ff02::1", "2001:db8:19::2", 40001, 18080, 7)
        e = icmp.parse(packet)
        self.assertEqual((e["source"], e["flags"], e["sport"], e["mss"], e["length"]), ("ff02::1", 2, 40001, 1220, 64))
        self.assertTrue(e["checksum_valid"])
        packet = rejected.syn(4, "192.0.2.7", "192.0.2.2", 40003, 18080, 7, rejected.loose_route("192.0.2.255"))
        e = icmp.parse(packet)
        self.assertEqual((e["header_len"], e["ip_options"], e["flags"]), (28, "830708c00002ff01", 2))
        self.assertTrue(e["ip_checksum_valid"] and e["checksum_valid"])

    def test_source_routed_checksum_uses_the_final_destination(self):
        packet = bytearray(rejected.syn(4, "192.0.2.2", "192.0.2.7", 18080, 40100, 9))
        # Re-address to the first hop behind a reversed one-hop route.
        option = bytes([131, 7, 4]) + bytes([192, 0, 2, 7]) + bytes(1)
        packet = packet[:9] + packet[9:10] + bytes(2) + packet[12:16] + bytes([192, 0, 2, 9]) + option + packet[20:]
        packet[0], packet[2:4] = 0x47, struct.pack("!H", len(packet))
        self.assertTrue(rejected.routed_checksum_valid(bytes(packet)))
        packet[-1] ^= 1
        self.assertFalse(rejected.routed_checksum_valid(bytes(packet)))


class FakeHolder:
    """A held namespace that records its cleanup."""

    def __init__(self, pid=None):
        self.pid = pid or os.getpid()
        self.killed = self.waited = False

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def poll(self):
        return None


class FakeCapture:
    """A capture whose INITIAL frames are present from the start and whose
    LATER frames arrive after the first mark (each timestamped when first
    read, so they follow the case's own clock readings)."""

    def __init__(self, initial, later):
        self.events, self.later, self.marked, self.closed = list(initial), list(later), False, False

    def mark(self):
        self.marked = True
        return len(self.events)

    def since(self, start):
        if self.marked and self.later:
            base = time.monotonic_ns() + 10 ** 9
            for i, e in enumerate(self.later):
                e.setdefault("time_ns", base + i * 1000)
            self.events.extend(self.later)
            self.later = []
        return list(self.events[start:])

    def close(self):
        self.closed = True


class FakeProcess:
    """A driven process answering each line with one event (`answer`)."""

    def __init__(self, args, answer):
        self.args, self.answer, self.queue, self.closed = args, answer, [], False
        self.ready = dict(event="ready", namespace=1)

    def send(self, line):
        self.queue.append(self.answer(line.split()))

    def read(self):
        result = self.queue.pop(0)
        assert result["event"] != "error", result
        return result

    def close(self):
        self.closed = True


def stream_answer(local, queries):
    """Answers of the native driver (LOCAL its connection names, QUERIES
    the successive path_mtu readbacks) or, with LOCAL None, of the peer."""
    queries = list(queries)

    def answer(fields):
        verb, name = fields[0], fields[1] if len(fields) > 1 else None
        if verb == "recv":
            return dict(event="received", id=name, hash=fnv(pattern(int(fields[2]), int(fields[3]))))
        if verb in ("connect", "accept"):
            event = "connected" if verb == "connect" else "accepted"
            if local is None:
                return dict(event=event, id=name, local=["fd19::d", 18190])
            port = 40000 if name == "s" else 40001
            return dict(event=event, id=name, local=f"[{local}]:{port}", path_mtu=ndproxy.FIRST_HOP)
        if verb == "query":
            return dict(event="query", id=name, path_mtu=queries.pop(0))
        return dict(event=dict(listen="listening", send="sent", shutdown="shutdown", eof="eof",
                               close="closed")[verb], id=name)
    return answer


def ipv6_bytes(length, seq, sport=40000):
    """An IPv6/TCP packet of LENGTH octets from N to D (only its prefix
    matters to a quote)."""
    header = struct.pack("!IHBB", 6 << 28, length - 40, 6, 64) + ipaddress.ip_address(ndproxy.NATIVE).packed \
        + ipaddress.ip_address(ndproxy.DESTINATIONS["proxy-ptb"]).packed
    tcp = struct.pack("!HHII", sport, ndproxy.PEER_LISTEN, seq, 1) + bytes(12)
    return header + tcp + bytes((i * 7) % 256 for i in range(length - 60))


class NdProxyWorld:
    """Fakes of every process, capture and command of one proxy-ptb
    native-client case. By default the frames are those of a passing run:
    R's solicited proxy NA before the first segment, oversized native
    output after the change, R's kernel PTB (counter and upstream copy)
    quoting it, the repair at 1280 and a later connection at 1280."""

    def __init__(self):
        n, r = ndproxy.MACS[ndproxy.NATIVE_PORT], ndproxy.MACS[ndproxy.ROUTER_UP]
        d = ndproxy.DESTINATIONS["proxy-ptb"]
        self.counter = 5
        self.counter_rise = 1
        self.queries = [1500, 1280, 1280]
        common = dict(checksum_valid=True, hop_limit=255, icmp_code=0, extensions=[], override=False,
                      router=False)
        tcp = lambda t, flags, length, payload, seq, sport=40000, raw=None: dict(
            protocol=6, direction="out", flags=flags, eth_src=n, eth_dst=r, source=ndproxy.NATIVE, destination=d,
            ip_length=length, payload=payload, seq=seq, sport=sport, checksum_valid=True, time_ns=t,
            raw=raw or bytes(14) + ipv6_bytes(length, seq, sport))
        self.native_initial = [
            dict(common, icmp_type=135, direction="out", target=d, source=ndproxy.NATIVE, destination="ff02::1:ff00:d",
                 eth_src=n, eth_dst="33:33:ff:00:00:0d", options=[dict(type=1, value=n)], solicited=False,
                 time_ns=1),
            dict(common, icmp_type=136, direction="in", target=d, source=ndproxy.ROUTER_LL,
                 destination=ndproxy.NATIVE, eth_src=r, eth_dst=n, options=[dict(type=2, value=r)], solicited=True,
                 router=True, time_ns=2),
            tcp(3, 0x02, 80, 0, 1000),
            tcp(4, 0x10, 1500, 1440, 1001),
        ]
        self.original = tcp(None, 0x10, 1500, 1440, 0x10000)
        self.original.pop("time_ns")
        self.ptb = dict(icmp_type=2, direction="in", checksum_valid=True, mtu=ndproxy.DOWNSTREAM, eth_src=r, eth_dst=n,
                        source=ndproxy.ROUTER, destination=ndproxy.NATIVE, quote=self.original["raw"][14:14 + 1232],
                        raw=bytes(200))
        self.repair = [tcp(None, 0x10, 1280, 1220, 0x10000), tcp(None, 0x10, 280, 220, 0x10000 + 1220)]
        self.later = [tcp(None, 0x10, 1280, 1220, 5000, sport=40001)]
        for e in self.repair + self.later:
            e.pop("time_ns")
        self.upstream_later = [dict(protocol=6, direction="in", source=ndproxy.NATIVE, ip_length=1500),
                               dict(icmp_type=2, direction="out", source=ndproxy.ROUTER)]
        self.downstream_later = [dict(protocol=6, direction="out", source=ndproxy.NATIVE, ip_length=1280)]
        self.holders, self.processes, self.captures, self.commands = [], [], [], []

    def native_later(self):
        return [self.original, self.ptb, *self.repair, *self.later]

    def command(self, args):
        self.commands.append(list(map(str, args)))
        if args[-1] == "/proc/net/snmp6":
            lowered = any("mtu" in c and str(ndproxy.DOWNSTREAM) in c for c in self.commands)
            return f"Icmp6OutPktTooBigs {self.counter + (self.counter_rise if lowered else 0)}\nIcmp6InMsgs 0\n"
        if args[:3] == ["ip", "-j", "link"]:
            return '[{"mtu": 1500}]'
        return ""

    def holder(self, proof):
        h = FakeHolder()
        self.holders.append(h)
        return h

    def peer(self, args):
        native = str(args[0]) == "/fake/binary"
        p = FakeProcess(args, stream_answer(ndproxy.NATIVE if native else None,
                                            self.queries if native else ()))
        self.processes.append(p)
        return p

    def capture(self, initial, later):
        c = FakeCapture(initial, later)
        self.captures.append(c)
        return c

    def run(self, case=None):
        case = case or dict(kind="nd-proxy", family=6, scenario="proxy-ptb", direction="native-client")
        settings = dict(namespaces=dict(peer=1, router=2))
        with patch.object(ndproxy, "held_namespace", self.holder), \
                patch.object(ndproxy, "setup", lambda *a: settings), \
                patch.object(ndproxy.scoped, "Capture", lambda name: self.capture(self.native_initial,
                                                                                  self.native_later())), \
                patch.object(ndproxy, "Capture", lambda pid, name: self.capture(
                    [], self.upstream_later if name == ndproxy.ROUTER_UP else self.downstream_later)), \
                patch("builtins.print"):
            return ndproxy.child(case, {}, "/fake/binary", self.peer, self.command)


class NdProxyChildChecks(unittest.TestCase):
    """The proxy case's own checks, driven by fakes: a router-generated PTB
    quoting a native submission passes; an injected or uncorrelated one, or a
    readback that stays at the first hop, fails the case; every failure
    releases the held namespaces, processes and captures."""

    def assert_cleaned(self, world):
        self.assertEqual(len(world.holders), 2)
        self.assertTrue(all(h.killed and h.waited for h in world.holders))
        self.assertTrue(all(p.closed for p in world.processes))
        self.assertTrue(all(c.closed for c in world.captures))

    def test_router_generated_ptb_quoting_a_native_submission_passes(self):
        world = NdProxyWorld()
        evidence = world.run()
        self.assertEqual(evidence["ptb"]["ptbs_at_native"], 1)
        self.assertEqual(evidence["ptb"]["router_counter"]["after"] - evidence["ptb"]["router_counter"]["mid"], 1)
        self.assertEqual(evidence["existing_query"]["path_mtu"], ndproxy.DOWNSTREAM)
        self.assert_cleaned(world)

    def test_a_ptb_the_router_kernel_did_not_count_fails(self):
        world = NdProxyWorld()
        world.counter_rise = 0
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)

    def test_a_ptb_absent_from_the_router_upstream_fails(self):
        world = NdProxyWorld()
        world.upstream_later = world.upstream_later[:1]
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)

    def test_a_ptb_from_another_sender_fails(self):
        world = NdProxyWorld()
        world.ptb.update(eth_src="02:00:00:19:00:99")
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)

    def test_a_ptb_quoting_no_native_submission_fails(self):
        world = NdProxyWorld()
        quote = bytearray(world.ptb["quote"])
        quote[44] ^= 0xff  # the quoted TCP sequence
        world.ptb["quote"] = bytes(quote)
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)

    def test_a_readback_still_at_the_first_hop_fails(self):
        for queries in ([1500, 1500, 1280], [1500, 1280, 1500]):
            world = NdProxyWorld()
            world.queries = queries
            with self.assertRaises(AssertionError):
                world.run()
            self.assert_cleaned(world)

    def test_a_segment_before_the_proxy_advertisement_fails(self):
        world = NdProxyWorld()
        world.native_initial[2]["time_ns"] = 0
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)

    def test_failed_setup_is_raised_and_releases_both_namespaces(self):
        world = NdProxyWorld()

        def failed(*args):
            raise RuntimeError("ip link add failed")
        with patch.object(ndproxy, "setup", failed), patch.object(ndproxy, "held_namespace", world.holder), \
                patch("builtins.print"):
            with self.assertRaises(RuntimeError):
                ndproxy.child(dict(kind="nd-proxy", family=6, scenario="proxy-ptb", direction="native-client"),
                              {}, "/fake/binary", world.peer, world.command)
        self.assert_cleaned(world)

    def test_a_driver_timeout_is_raised_and_cleans_up(self):
        world = NdProxyWorld()
        original = world.peer

        def peer(args):
            p = original(args)
            if str(args[0]) == "/fake/binary":
                def read():
                    raise TimeoutError("peer deadline")
                p.read = read
            return p
        world.peer = peer
        with self.assertRaises(TimeoutError):
            world.run()
        self.assert_cleaned(world)


class HeldNamespace(unittest.TestCase):
    def test_a_holder_that_never_leaves_the_harness_namespace_is_refused(self):
        current = os.stat("/proc/self/ns/net").st_ino
        proof = dict(net=dict(current=current, parent=current + 1))
        holder = FakeHolder(os.getpid())
        holder.poll = lambda: 1  # unshare failed: no namespace capability
        with patch.object(ndproxy.subprocess, "Popen", lambda *a, **k: holder):
            with self.assertRaises(AssertionError):
                ndproxy.held_namespace(proof)


class IndexedCapture(FakeCapture):
    """FakeCapture with redirect.Capture's per-frame capture index."""

    def since(self, start):
        events = super().since(start)
        for i, e in enumerate(self.events):
            e["index"] = i
        return events


class FakePathctl:
    """ntcp-pathctl answers from the world's state: D's replacement path
    (next hop R2) once R1's route changed, the later client once opened."""

    def __init__(self, world):
        self.world, self.log = world, []

    def paths(self):
        w, a = self.world, self.world.a
        moved = w.route_changed and w.moves
        d = dict(destination=a["destination"], valid="1", route="1", token="d2" if moved else "d1",
                 next_hop=a["gateway_r2"] if moved else a["gateway_r1"])
        other = dict(destination=a["other"], valid="1", route="1", token="o1",
                     next_hop=a["gateway_r2"] if w.route_changed and w.other_moves else a["gateway_r1"])
        return [d, other]

    def run(self, verb, token):
        self.log.append((verb, token))
        count = {"d1": 2, "d2": 3 if self.world.later_open else 2, "o1": 1}[token]
        return type("P", (), dict(stdout="".join(f"client kind=tcp id={i}\n" for i in range(count))))()


class RedirectWorld:
    """Fakes of every process, capture, command and utility request of one
    Linux-router Redirect case of FAMILY. By default the frames are those of
    a passing run: R1's kernel Redirect (counted, sent on its bridge port)
    naming R2 and quoting flow a's first submission after the change, the
    flows to D moving to R2 for good and D2 staying with R1."""

    def __init__(self, family):
        self.family, self.a = family, redirect.ADDRESSES[family]
        a, macs = self.a, redirect.MACS
        n, r1, r2 = macs[redirect.NATIVE_PORT], macs[redirect.R1_UP], macs[redirect.R2_UP]
        self.r1, self.r2 = r1, r2
        self.route_changed = self.later_open = self.other_moves = False
        self.moves = True
        self.counter_rise = 1
        self.ports = dict(a=40000, b=40001, e=40002, c=40003)
        self.holders, self.processes, self.captures, self.commands = [], [], [], []

        def tcp(name, via, seq, flags=0x18, payload=100):
            destination = a["other"] if name == "e" else a["destination"]
            return dict(protocol=6, direction="out", sport=self.ports[name], dport=redirect.PEER_LISTEN, seq=seq,
                        flags=flags, payload=payload, eth_src=n, eth_dst=via, source=a["native"],
                        destination=destination, checksum_valid=True,
                        raw=bytes(14) + self.packet(destination, self.ports[name], seq))
        self.initial = []
        if family == 6:
            self.initial += [dict(icmp_type=135, direction="out", target=a["gateway_r1"]),
                             dict(icmp_type=136, direction="in", target=a["gateway_r1"], tllao=r1)]
        self.initial += [tcp(name, r1, 1, flags=0x02, payload=0) for name in ("a", "b", "e")]
        self.original = tcp("a", r1, 1000)
        self.tcp = tcp
        self.before_redirect = []
        self.redirect = dict(direction="in", checksum_valid=True, eth_src=r1, eth_dst=n, destination=a["native"],
                             quote=self.original["raw"][14:14 + (28 if family == 4 else 48)],
                             quoted=dict(source=a["native"], destination=a["destination"], protocol=6,
                                         sport=self.ports["a"], dport=redirect.PEER_LISTEN, seq=1000),
                             raw=bytes(96))
        if family == 4:
            self.redirect.update(icmp_type=5, icmp_code=1, source=a["r1"], gateway=a["r2"])
        else:
            self.redirect.update(icmp_type=137, icmp_code=0, source=a["gateway_r1"], hop_limit=255,
                                 target=a["gateway_r2"], redirect_destination=a["destination"], tllao=r2)
        self.after = [tcp("a", r2, 1100), tcp("b", r2, 1000), tcp("a", r2, 1200),
                      tcp("c", r2, 1, flags=0x02, payload=0), tcp("c", r2, 2), tcp("e", r1, 1000)]
        self.r1_later = [dict(icmp_type=self.redirect["icmp_type"], direction="out")]
        self.r2_later = [dict(protocol=6, direction="in", source=a["native"], eth_src=n, eth_dst=r2)]

    def packet(self, destination, sport, seq):
        src = ipaddress.ip_address(self.a["native"]).packed
        dst = ipaddress.ip_address(destination).packed
        tcp = struct.pack("!HHII", sport, redirect.PEER_LISTEN, seq, 1) + bytes(12) + bytes(100)
        if self.family == 4:
            return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst) + tcp
        return struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst + tcp

    def command(self, args):
        args = list(map(str, args))
        self.commands.append(args)
        if "route" in args and "replace" in args:
            self.route_changed = True
        count = 7 + (self.counter_rise if self.route_changed else 0)
        if args[-1] == "/proc/net/snmp6":
            return f"Icmp6OutRedirects {count}\nIcmp6InMsgs 0\n"
        if args[-1] == "/proc/net/snmp":
            return f"Ip: Forwarding\nIp: 1\nIcmp: InMsgs OutRedirects\nIcmp: 0 {count}\n"
        if "get" in args:
            return json.dumps([dict(dev=redirect.R1_UP, gateway=self.a["gateway_r2"])])
        if args[:3] == ["ip", "-j", "link"]:
            return '[{"mtu": 1500}]'
        return ""

    def holder(self, proof):
        h = FakeHolder()
        self.holders.append(h)
        return h

    def peer(self, args):
        native = str(args[0]) == "/fake/binary"
        world = self

        def answer(fields):
            verb, name = fields[0], fields[1] if len(fields) > 1 else None
            if verb == "recv":
                return dict(event="received", id=name, hash=fnv(pattern(int(fields[2]), int(fields[3]))))
            if verb == "connect":
                if name == "c":
                    world.later_open = True
                port = world.ports[name]
                local = f"[{world.a['native']}]:{port}" if world.family == 6 else f"{world.a['native']}:{port}"
                return dict(event="connected", id=name, local=local)
            if verb == "accept":
                return dict(event="accepted", id=name)
            return dict(event=dict(listen="listening", send="sent", shutdown="shutdown", eof="eof",
                                   close="closed")[verb], id=name)
        p = FakeProcess(args, answer)
        self.processes.append(p)
        return p

    def capture(self, interface, pid=None):
        initial, later = dict(t19n=(self.initial, [self.original, *self.before_redirect, self.redirect, *self.after]),
                              t19r1=([], self.r1_later), t19r2=([], self.r2_later))[interface]
        c = IndexedCapture(initial, later)
        self.captures.append(c)
        return c

    def run(self):
        case = dict(kind="redirect", family=self.family, scenario="linux-router")
        settings = dict(namespaces=dict(peer=1))
        with patch.object(redirect, "held_namespace", self.holder), \
                patch.object(redirect, "setup", lambda *a: settings), \
                patch.object(redirect, "Capture", self.capture), \
                patch.object(redirect, "quiet", lambda capture: None), \
                patch.object(redirect.admin, "Pathctl", lambda binary, control: FakePathctl(self)), \
                patch("builtins.print"):
            return redirect.child(case, {}, "/fake/binary", "/fake/pathctl", self.peer, self.command)


class RedirectChildChecks(unittest.TestCase):
    """The Redirect cases' own causality checks, driven by fakes: only a
    Redirect R1's kernel generated (counted, sent through its bridge port)
    from R1, naming R2, for D and quoting N's actual first submission after
    the change passes, with D's flows moving to R2 for good and D2 staying;
    every failure releases all four held namespaces and the control
    directory."""

    def failing(self, family, change):
        world = RedirectWorld(family)
        change(world)
        directories = set(os.listdir(redirect.tempfile.gettempdir()))
        with self.assertRaises(AssertionError):
            world.run()
        self.assert_cleaned(world)
        self.assertEqual(set(os.listdir(redirect.tempfile.gettempdir())) - directories, set())

    def assert_cleaned(self, world):
        self.assertEqual(len(world.holders), 4)
        self.assertTrue(all(h.killed and h.waited for h in world.holders))
        self.assertTrue(all(p.closed for p in world.processes))
        self.assertTrue(all(c.closed for c in world.captures))

    def test_a_router_generated_redirect_quoting_the_first_submission_passes(self):
        for family in (4, 6):
            world = RedirectWorld(family)
            evidence = world.run()
            self.assertEqual(evidence["redirects"], 1)
            self.assertEqual(evidence["redirect_counter"]["after"] - evidence["redirect_counter"]["before"], 1)
            self.assertEqual(set(evidence["switched"]), {"a", "b", "c"})
            self.assert_cleaned(world)

    def test_a_redirect_the_router_kernel_did_not_count_fails(self):
        for family in (4, 6):
            self.failing(family, lambda w: setattr(w, "counter_rise", 0))

    def test_a_redirect_not_sent_by_r1_fails(self):
        for family in (4, 6):
            self.failing(family, lambda w: setattr(w, "r1_later", []))
            self.failing(family, lambda w: w.redirect.update(eth_src=w.r2))
            source = "r2" if family == 4 else "gateway_r2"
            self.failing(family, lambda w: w.redirect.update(source=w.a[source]))

    def test_a_redirect_to_another_target_or_for_another_destination_fails(self):
        self.failing(4, lambda w: w.redirect.update(gateway="10.19.0.9"))
        self.failing(6, lambda w: w.redirect.update(target="fe80::9"))
        self.failing(6, lambda w: w.redirect.update(redirect_destination=w.a["other"]))
        for family in (4, 6):
            self.failing(family, lambda w: w.redirect["quoted"].update(destination=w.a["other"]))

    def test_a_redirect_quoting_no_submission_fails(self):
        for family in (4, 6):
            def change(w):
                quote = bytearray(w.redirect["quote"])
                quote[-1] ^= 0xff  # the quoted TCP sequence's last octet
                w.redirect["quote"] = bytes(quote)
            self.failing(family, change)
            # A quote of a later segment through R1, not the first
            # submission after the change.
            def later(w):
                w.before_redirect = [w.tcp("a", w.r1, 1050)]
                w.redirect.update(quote=w.before_redirect[0]["raw"][14:14 + len(w.redirect["quote"])],
                                  quoted=dict(w.redirect["quoted"], seq=1050))
            self.failing(family, later)

    def test_output_that_moves_before_the_redirect_or_returns_to_r1_fails(self):
        for family in (4, 6):
            self.failing(family, lambda w: w.original.update(eth_dst=w.r2))
            self.failing(family, lambda w: w.after[2].update(eth_dst=w.r1))
            self.failing(family, lambda w: w.after[3].update(eth_dst=w.r1))

    def test_another_destination_moving_too_fails(self):
        for family in (4, 6):
            self.failing(family, lambda w: w.after[5].update(eth_dst=w.r2))
            self.failing(family, lambda w: setattr(w, "other_moves", True))

    def test_a_pathctl_view_without_the_replacement_path_fails(self):
        for family in (4, 6):
            self.failing(family, lambda w: setattr(w, "moves", False))

    def test_failed_setup_is_raised_and_releases_every_namespace(self):
        world = RedirectWorld(4)

        def failed(*args):
            raise RuntimeError("bridge add failed")
        directories = set(os.listdir(redirect.tempfile.gettempdir()))
        with patch.object(redirect, "setup", failed), patch.object(redirect, "held_namespace", world.holder), \
                patch("builtins.print"):
            with self.assertRaises(RuntimeError):
                redirect.child(dict(kind="redirect", family=4, scenario="linux-router"), {}, "/fake/binary",
                               "/fake/pathctl", world.peer, world.command)
        self.assert_cleaned(world)
        self.assertEqual(set(os.listdir(redirect.tempfile.gettempdir())) - directories, set())


class RejectedSynChecks(unittest.TestCase):
    """The rejected-SYN case's own checks: the unscoped link-local refusal
    must be tun_echo's stated refusal with nothing transmitted and nothing
    reaching the listener, and echo progress counts only tun_echo's own
    payload on the live tuple."""

    class Listener:
        def __init__(self, pending):
            self.pending = pending

        def setblocking(self, flag):
            pass

        def accept(self):
            if self.pending:
                return object(), ("fe80::2", 1)
            raise BlockingIOError

    def refusal(self, returncode, stderr, sent=(), pending=False):
        capture = FakeCapture([], [dict(direction="from-ntcp", **e) for e in sent])
        result = type("R", (), dict(returncode=returncode, stderr=stderr, stdout=""))()
        with patch.object(rejected, "SETTLE", 0), patch.object(rejected.subprocess, "run", lambda *a, **k: result):
            return rejected.refused_unscoped("/fake/tun_echo", capture, {}, self.Listener(pending))

    def test_the_stated_refusal_with_nothing_transmitted_passes(self):
        record = self.refusal(1, "error: " + rejected.SCOPE_REFUSAL + "\n")
        self.assertEqual((record["exit"], record["from_ntcp_packets"], record["listener_pending"]), (1, 0, 0))

    def test_an_open_that_was_not_refused_fails(self):
        with self.assertRaises(AssertionError):
            self.refusal(0, "")
        with self.assertRaises(AssertionError):
            self.refusal(1, "error: no such device\n")

    def test_a_refusal_after_transmission_fails(self):
        with self.assertRaises(AssertionError):
            self.refusal(1, rejected.SCOPE_REFUSAL, sent=[dict(protocol=6, flags=2, destination="fe80::1")])

    def test_an_open_that_reached_the_listener_fails(self):
        with self.assertRaises(AssertionError):
            self.refusal(1, rejected.SCOPE_REFUSAL, pending=True)

    def test_echo_progress_counts_tun_echo_payload_on_the_live_tuple_once(self):
        isn = 0xfffff000
        live = (rejected.PORT, 50000)
        seg = lambda seq, payload, direction="from-ntcp", tuple_=live: dict(
            direction=direction, protocol=6, sport=tuple_[0], dport=tuple_[1], seq=seq & 0xffffffff, payload=payload)
        events = [seg(isn + 1, 4096), seg(isn + 1, 4096),  # a retransmission
                  seg(isn + 4097, 1000, direction="to-ntcp"), seg(isn + 4097, 2000, tuple_=(rejected.PORT, 50001))]
        self.assertEqual(rejected.sent_end(events, live, isn), 4096)
        events.append(seg(isn + 4097, 4096))  # across the sequence wrap
        self.assertEqual(rejected.sent_end(events, live, isn), 8192)
        self.assertEqual(rejected.sent_end([], live, isn), 0)
