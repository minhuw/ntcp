# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
import os
import struct
import unittest
from unittest.mock import patch

from bridge import checksum
import admin
import bridge
import icmp
import options
import run


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
