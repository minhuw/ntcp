import copy
import importlib.util
import itertools
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "integration/rfc_host/check_mac_cost.py"
spec = importlib.util.spec_from_file_location("mac_cost", MODULE)
mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac)


def complete_evidence():
    rows = [{"type": "method", "schema": 2, "debug_assertions": False, "rounds": 9, "batch": 128, "warmup": 16},
            {"type": "complete", "cases": 168, "rounds": 9}]
    for linux, v6, loaded, pooled, mode, enabled in itertools.product((False, True), (False, True), (False, True), (False, True), mac.MODES, (False, True)):
        if linux and mode == "previous-epoch":
            continue
        accepts = mode in ("current", "previous-epoch", "overlap-current", "overlap-retiring")
        for round in range(9):
            rows.append(dict(type="handshake", linux=linux, v6=v6, loaded=loaded, pooled=pooled,
                             mode=mode, enabled=enabled, round=round, iterations=128,
                             valid_calls=128 * (mode != "ordinary") * enabled,
                             issue_calls=128 * (mode != "ordinary" and not (linux and accepts)) * enabled,
                             full_ns=128000, scope_ns=12800 * enabled, outside_scope_ns=128000 - 12800 * enabled,
                             full_quantiles_ns=[900, 950, 1000, 1100, 1200],
                             scope_quantiles_ns=[0, 0, 0, 0, 0], outside_quantiles_ns=[800, 850, 900, 1000, 1100]))
    for linux, v6, mode, kind, round in itertools.product((False, True), (False, True), mac.MODES, range(4), range(9)):
        if mode == "ordinary" or linux and mode == "previous-epoch":
            continue
        rows.append(dict(type="codec", linux=linux, v6=v6, mode=mode, kind=kind, round=round, ns=100000, iterations=1024))
    for kind, round in itertools.product(range(5), range(9)):
        rows.append(dict(type="calibration", kind=kind, round=round, ns=16384 * (10, 60, 15, 65, 70)[kind],
                         iterations=16384, scope_ns=16384 * 25 if kind == 3 else 0,
                         full_internal_ns=16384 * 20 if kind == 4 else 0, calls=16384 if kind == 3 else 0))
    return rows


class MacCostEvidence(unittest.TestCase):
    stdout = f"running 1 test\ntest {mac.TEST} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;"

    def test_complete_declared_matrix_and_libtest_first_line(self):
        mac.validate(complete_evidence(), self.stdout)
        self.assertEqual(mac.parse_rows(f'test {mac.TEST} ... MAC_COST_JSON {{"type":"method"}}\n'), [{"type": "method"}])

    def test_missing_cases_rounds_features_or_executable_run_fail(self):
        rows = complete_evidence()
        for predicate in (
            lambda r: r["type"] == "complete",
            lambda r: r["type"] == "handshake" and r["linux"] and r["mode"] == "overlap-retiring",
            lambda r: r["type"] == "handshake" and not r["enabled"],
            lambda r: r["type"] == "codec" and r["mode"] == "previous-epoch",
            lambda r: r["type"] == "calibration" and r["kind"] == 3,
            lambda r: r["type"] == "calibration" and r["kind"] == 4,
            lambda r: r.get("round") == 8,
        ):
            with self.assertRaises(ValueError):
                mac.validate([r for r in rows if not predicate(r)], self.stdout)
        for stdout in ("running 0 tests\ntest result: ok. 0 passed", self.stdout.replace(mac.TEST, "unrelated")):
            with self.assertRaises(ValueError):
                mac.validate(rows, stdout)

    def test_debug_nonfinite_multiplicity_and_fabricated_residual_fail(self):
        for field, value in (("debug_assertions", True), ("batch", 1)):
            rows = complete_evidence()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                mac.validate(rows, self.stdout)
        for kind, field, value in (("codec", "ns", float("inf")),
                                   ("handshake", "full_ns", float("inf")),
                                   ("handshake", "valid_calls", 999),
                                   ("handshake", "outside_scope_ns", 999),
                                   ("calibration", "full_internal_ns", float("nan")),
                                   ("calibration", "full_internal_ns", -1),
                                   ("handshake", "full_quantiles_ns", [1, 2, 3, 4, float("nan")])):
            rows = copy.deepcopy(complete_evidence())
            next(r for r in rows if r["type"] == kind)[field] = value
            with self.assertRaises(ValueError):
                mac.validate(rows, self.stdout)

    def test_observer_correction_removes_observer_from_both_sides_without_clamping(self):
        # Physical accounting example: true credential200 + remaining600,
        # three50ns observer scopes + a50ns outer timer = full1000. Recorded
        # credential includes three25ns internal read biases, hence275.
        self.assertEqual(mac.corrected_estimates(1000, 275, 3, 25, 50, 50), (200, 600))
        # Timer resolution/noise may overwhelm a tiny operation; preserve that
        # signed result instead of manufacturing a favorable nonnegative value.
        credential, outside = mac.corrected_estimates(10, 5, 2, 25, 50, 50)
        self.assertLess(credential, 0)
        self.assertLess(outside, 0)

    def test_full_correction_uses_internal_interval_not_clock_pair_throughput(self):
        rows = complete_evidence()
        # Clock-pair throughput increments by 50ns, but only 20ns lies inside
        # the matched full interval. Changing throughput must not change either
        # remaining-time estimate when internal elapsed controls stay fixed.
        reports = []
        for throughput in (60, 600):
            for row in rows:
                if row["type"] == "calibration" and row["kind"] == 1:
                    row["ns"] = 16384 * throughput
            with mock.patch.object(mac, "emit") as emit:
                mac.report(rows, self.stdout)
            records = [call.args[0] for call in emit.call_args_list]
            observer = next(r for r in records if r["type"] == "observer_estimates")
            self.assertEqual(observer["read_pair_increment_ns"], throughput - 10)
            self.assertEqual(observer["empty_full_internal_ns"], 20)
            measured = next(r for r in records if r["type"] == "handshake_rounds" and r["mode"] == "request")
            estimates = measured["median_per_packet_ns"]
            self.assertEqual(estimates["corrected_scope_estimate"], 50)
            self.assertEqual(estimates["corrected_outside_estimate"], 830)
            self.assertEqual(estimates["separately_sampled_disabled_remaining_estimate"], 930)
            reports.append(estimates)
        self.assertEqual(reports[0], reports[1])

    def test_sources_are_captured_before_build_and_guarded_after_build_and_execution(self):
        snapshot = {"source_commit": "original", "dirty_status": " M harness",
                    "relevant_source": {"files": {"source": "original"}}, "harness": "original"}
        artifact = {"reason": "compiler-artifact", "executable": "/binary", "target": {"name": "ntcp"},
                    "profile": {"test": True, "debug_assertions": False, "opt_level": "3"},
                    "features": ["tfo-linux-cookie"]}
        for changed_field in snapshot:
            changed = {**snapshot, changed_field: "changed"}
            for stage in (1, 2):
                with self.subTest(field=changed_field, stage=stage):
                    snapshots = [snapshot] * stage + [changed]
                    events = []

                    def capture():
                        events.append("snapshot")
                        return snapshots.pop(0)

                    def run(*args, **kwargs):
                        events.append("build" if events.count("build") == 0 else "execute")
                        return SimpleNamespace(returncode=0, stdout=json.dumps(artifact), stderr="")

                    executable = mock.MagicMock()
                    executable.read_bytes.return_value = b"binary"
                    with (mock.patch.object(mac, "ROOT", mock.MagicMock()),
                          mock.patch.object(mac.os, "chdir"),
                          mock.patch.object(mac, "source_snapshot", side_effect=capture),
                          mock.patch.object(mac.subprocess, "run", side_effect=run),
                          mock.patch.object(mac, "Path", return_value=executable),
                          mock.patch.object(mac, "provenance", return_value={"executable_sha256": mac.digest(b"binary")}) as provenance,
                          mock.patch.object(mac, "emit"), mock.patch.object(mac, "report") as report):
                        with self.assertRaisesRegex(ValueError, "source hashes/list or Git state changed"):
                            mac.main()
                        report.assert_not_called()
                        if stage == 1:
                            self.assertEqual(events, ["snapshot", "build", "snapshot"])
                            provenance.assert_not_called()
                        else:
                            self.assertEqual(events, ["snapshot", "build", "snapshot", "execute", "snapshot"])
                            self.assertIs(provenance.call_args.args[-1], snapshot)

    def test_provenance_uses_rustc_override_instead_of_path_toolchain(self):
        selected = "/toolchains/1.90.0/bin/rustc"
        env = {"PATH": "/toolchains/stable/bin", "RUSTC": selected,
               "CARGO_BUILD_RUSTC": "/unused/configured/rustc"}
        versions = {selected: "rustc 1.90.0 (selected)\nrelease: 1.90.0\nhost: test-host\ncommit-hash: selected",
                    "rustc": "rustc 1.92.0 (PATH)\nrelease: 1.92.0\nhost: test-host\ncommit-hash: PATH"}

        def query(args, query_env):
            if args == ["cargo", "-Vv"]:
                return "cargo 1.92.0"
            if args == ["rustup", "show", "active-toolchain"]:
                return "stable (default)"
            return versions[args[0]]

        invocation = f"     Running `CARGO_CRATE_NAME=ntcp {selected} --crate-name ntcp --test src/lib.rs`"
        with (mock.patch.object(mac, "command", side_effect=query) as command,
              mock.patch.object(mac.shutil, "which", return_value=selected)):
            result = mac.provenance(env, ["cargo", "test"], MODULE, {"profile": {}, "features": []}, invocation, {})
        self.assertEqual(result["rustc"], versions[selected])
        self.assertEqual(result["compiler_selection"]["compiler_path"], selected)
        self.assertEqual(result["rustup_active_toolchain"], "stable (default)")
        self.assertEqual(result["build_environment"]["RUSTC"], selected)
        self.assertEqual(result["build_environment"]["CARGO_BUILD_RUSTC"], env["CARGO_BUILD_RUSTC"])
        self.assertEqual(result["build_environment"]["PATH"], env["PATH"])
        self.assertNotIn(mock.call(["rustc", "-Vv"], env), command.call_args_list)
        command.assert_any_call([selected, "-Vv"], {**env, "CARGO_CRATE_NAME": "ntcp"})

    def test_compiler_selection_uses_recorded_configuration_wrappers_and_environment(self):
        # With no RUSTC override, Cargo configuration can still select a
        # compiler and nested wrappers. Invocation env also controls proxies.
        env = {"PATH": "/bin", "RUSTUP_TOOLCHAIN": "stable"}
        invocation = ("Running `RUSTUP_TOOLCHAIN=1.90.0 CARGO_CRATE_NAME=ntcp "
                      "'/tools/compiler wrapper' /tools/workspace-wrapper /tools/rustc "
                      "--crate-name ntcp --test src/lib.rs`")
        version = "rustc 1.90.0 (selected)\nrelease: 1.90.0\nhost: test-host\ncommit-hash: selected"
        prefix = ["/tools/compiler wrapper", "/tools/workspace-wrapper", "/tools/rustc"]
        with (mock.patch.object(mac, "command", return_value=version) as command,
              mock.patch.object(mac.shutil, "which", side_effect=lambda name, path: name)):
            result = mac.compiler_provenance(env, invocation)
        self.assertEqual(result["rustc"], version)
        self.assertEqual(result["compiler_selection"]["wrapper_paths"], prefix[:-1])
        self.assertEqual(result["compiler_selection"]["version_command"], prefix + ["-Vv"])
        command.assert_called_once_with(prefix + ["-Vv"], {**env, "RUSTUP_TOOLCHAIN": "1.90.0", "CARGO_CRATE_NAME": "ntcp"})
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "stable")

    def test_missing_or_invalid_selected_compiler_provenance_fails(self):
        for invocation in ("no command", "Running `--crate-name ntcp`", "Running `rustc --test`"):
            with self.subTest(invocation=invocation), self.assertRaises(ValueError):
                mac.compiler_provenance({}, invocation)
        with mock.patch.object(mac.shutil, "which", return_value=None), self.assertRaisesRegex(ValueError, "cannot resolve"):
            mac.compiler_provenance({}, "Running `missing-rustc --crate-name ntcp --test`")
        with (mock.patch.object(mac.shutil, "which", return_value="/tools/rustc"),
              mock.patch.object(mac, "command", return_value="unidentified wrapper"),
              self.assertRaisesRegex(ValueError, "version provenance")):
            mac.compiler_provenance({}, "Running `rustc --crate-name ntcp --test`")

    def test_slow_or_noisy_evidence_has_no_arbitrary_ratio_gate(self):
        rows = complete_evidence()
        for r in rows:
            if r["type"] == "handshake":
                r["full_ns"] *= 100000
                r["scope_ns"] = r["full_ns"] - 1 if r["enabled"] else 0
                r["outside_scope_ns"] = r["full_ns"] - r["scope_ns"]
        mac.validate(rows, self.stdout)
