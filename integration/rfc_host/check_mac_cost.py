#!/usr/bin/env python3
"""Run the explicitly ignored core RELEASE measurement and validate its evidence."""
import collections
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TEST = "endpoint::mac_cost_tests::release_mac_cost"
PREFIX = "MAC_COST_JSON "
BASE = "4594fbeab58f91def1f153585cbf304ad00c1b70"
MODES = ("ordinary", "request", "current", "previous-epoch", "overlap-current",
         "overlap-retiring", "invalid", "overlap-invalid", "expired", "revoked", "malformed-length")


def emit(value):
    print(PREFIX + json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def command(args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True, stderr=subprocess.STDOUT).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(paths):
    entries = {p: digest((ROOT / p).read_bytes()) for p in sorted(paths)}
    return {"sha256": digest(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()), "files": entries}


def source_snapshot():
    paths = command(["git", "ls-files"]).splitlines()
    relevant = {p for p in paths if p.startswith(("crates/stacks/ntcp/", "crates/net/ntcp-buffer/", "crates/stacks/ntcp-ip-common/"))}
    relevant.update(("Cargo.toml", "Cargo.lock", "integration/rfc_host/check_mac_cost.py", "crates/stacks/ntcp/src/mac_cost_tests.rs",
                     "duvet/test_mac_cost.py", "duvet/test_fast_open_inventory.py",
                     "duvet/rfc7413-inventory.json", "duvet/rfc7413-todos.toml"))
    harness = fingerprint(["integration/rfc_host/check_mac_cost.py", "crates/stacks/ntcp/src/mac_cost_tests.rs"])
    stripped = (ROOT / "crates/stacks/ntcp/src/fast_open.rs").read_text()
    stripped = re.sub(r'        #\[cfg\(all\(test, feature = "tfo-linux-cookie"\)\)\]\n        let _scope = crate::endpoint::mac_cost_tests::Scope::new\([01]\);\n', '', stripped)
    t5 = command(["git", "show", BASE + ":crates/stacks/ntcp/src/fast_open.rs"]) + "\n"
    return {
        "source_commit": command(["git", "rev-parse", "HEAD"]),
        "dirty_status": command(["git", "status", "--porcelain=v1", "--untracked-files=all"]),
        "tracked_diff_sha256": digest(subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT)),
        "t5_production_commit": BASE, "cookie_algorithm_matches_t5_without_test_hooks": stripped == t5,
        "relevant_source": fingerprint(relevant), "harness": harness,
    }


def verify_sources(snapshot, phase):
    if source_snapshot() != snapshot:
        raise ValueError("source hashes/list or Git state changed " + phase)


def compiler_provenance(env, invocation):
    # Cargo -vv records its selected compiler after any configured wrappers and
    # invocation-specific environment. Query that same command, not PATH rustc:
    # build.rustc/RUSTC can select a different toolchain from Cargo's own rustup.
    match = re.search(r"Running `(.*)`$", invocation)
    if not match:
        raise ValueError("missing recorded compiler command")
    args = shlex.split(match[1])
    compiler_env = dict(env)
    assignments = {}
    while args and re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", args[0]):
        name, value = args.pop(0).split("=", 1)
        compiler_env[name] = value
        assignments[name] = value
    # Cargo places --crate-name immediately after the compiler executable;
    # any preceding command arguments are its (possibly nested) wrappers.
    try:
        boundary = args.index("--crate-name")
    except ValueError as error:
        raise ValueError("missing compiler boundary in Cargo invocation") from error
    if boundary < 1:
        raise ValueError("missing selected compiler in Cargo invocation")
    selected = args[:boundary]
    resolved = []
    for executable in selected:
        path = shutil.which(executable, path=compiler_env.get("PATH", os.defpath))
        if path is None:
            raise ValueError("cannot resolve selected compiler/wrapper: " + executable)
        # Keep rustup proxy symlinks intact when invoking: resolving a rustc
        # symlink to the rustup binary changes the command's meaning.
        resolved.append(os.path.abspath(path))
    query = resolved + ["-Vv"]
    version = command(query, compiler_env)
    if not version.startswith("rustc ") or not all("\n" + field + ": " in version for field in ("release", "host", "commit-hash")):
        raise ValueError("selected compiler did not provide rustc version provenance")
    return {
        "rustc": version,
        "compiler_selection": {"recorded_command_prefix": selected, "resolved_command_prefix": resolved,
                               "compiler_path": resolved[-1], "wrapper_paths": resolved[:-1],
                               "version_command": query, "invocation_environment": assignments},
    }


def provenance(env, build, executable, artifact, build_stderr, snapshot):
    cpu = Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor()
    cpu = next((line.split(":", 1)[1].strip() for line in cpu.splitlines() if line.startswith("model name")), cpu[:200])
    invocations = [line for line in build_stderr.splitlines() if "Running `" in line and "--crate-name ntcp " in line and "--test" in line]
    if len(invocations) != 1:
        raise ValueError("missing unique actual rustc test compiler invocation")
    return {
        "type": "provenance", **snapshot,
        "source_snapshot_checks": ["before-build", "after-build", "after-execution"],
        "executable": str(executable.relative_to(ROOT)), "executable_sha256": digest(executable.read_bytes()),
        **compiler_provenance(env, invocations[0]), "cargo": command(["cargo", "-Vv"], env),
        "rustup_active_toolchain": command(["rustup", "show", "active-toolchain"], env),
        "rustup_toolchain_scope": "contextual rustup selection only; the measured executable's compiler is identified by compiler_selection and rustc",
        "build_command": build, "run_command": [str(executable), TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
        "rustc_invocation": invocations[0], "profile": artifact["profile"], "features": artifact["features"],
        "build_environment": {k: v for k, v in env.items() if k in ("PATH", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_TARGET_DIR", "CARGO_HOME") or k.startswith(("CARGO_PROFILE_RELEASE_", "CARGO_BUILD_RUSTC"))},
        "cpu": cpu, "kernel": platform.uname()._asdict(), "allowed_cpus": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "affinity_mutation": False, "timer": vars(time.get_clock_info("monotonic")),
    }


def validate(rows, stdout):
    if not re.search(r"running 1 test\b", stdout) or not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout) or TEST not in stdout:
        raise ValueError("exactly one intended benchmark must actually pass")
    methods = [r for r in rows if r["type"] == "method"]
    completes = [r for r in rows if r["type"] == "complete"]
    if len(methods) != 1 or len(completes) != 1:
        raise ValueError("missing unique method/completion")
    method = methods[0]
    if method.get("schema") != 2 or method["debug_assertions"] or method["rounds"] != 9 or method["batch"] != 128 or method["warmup"] != 16:
        raise ValueError("wrong release methodology")
    groups = collections.defaultdict(list)
    codecs = collections.defaultdict(list)
    calibrations = collections.defaultdict(list)
    for row in rows:
        kind = row["type"]
        if kind == "handshake":
            key = tuple(row[k] for k in ("linux", "v6", "loaded", "pooled", "mode", "enabled"))
            groups[key].append(row)
            n = row["iterations"]
            offered = row["mode"] != "ordinary"
            accepts = row["mode"] in ("current", "previous-epoch", "overlap-current", "overlap-retiring")
            issues = offered and not (row["linux"] and accepts)
            if n != 128 or row["valid_calls"] != n * offered * row["enabled"] or row["issue_calls"] != n * issues * row["enabled"]:
                raise ValueError("actual credential multiplicities do not match admission")
            if any(not math.isfinite(row[field]) for field in ("full_ns", "scope_ns", "outside_scope_ns")):
                raise ValueError("nonfinite handshake samples")
            if row["full_ns"] <= 0 or row["scope_ns"] < 0 or row["outside_scope_ns"] != row["full_ns"] - row["scope_ns"]:
                raise ValueError("invalid elapsed scope exclusion")
            for field in ("full_quantiles_ns", "scope_quantiles_ns", "outside_quantiles_ns"):
                q = row[field]
                if len(q) != 5 or q != sorted(q) or any(not math.isfinite(x) or x < 0 for x in q):
                    raise ValueError("invalid distributions")
        elif kind == "codec":
            if row["iterations"] != 1024:
                raise ValueError("insufficient codec batch")
            codecs[tuple(row[k] for k in ("linux", "v6", "mode", "kind"))].append(row)
        elif kind == "calibration":
            if row["iterations"] != 16384 or row["calls"] != (16384 if row["kind"] == 3 else 0):
                raise ValueError("invalid observer control")
            internal = row.get("full_internal_ns")
            if internal is None or not math.isfinite(internal) or (internal <= 0 if row["kind"] == 4 else internal != 0):
                raise ValueError("invalid matched full timer control")
            if not math.isfinite(row["scope_ns"]) or (row["scope_ns"] <= 0 if row["kind"] == 3 else row["scope_ns"] != 0):
                raise ValueError("invalid empty scope interval")
            calibrations[row["kind"]].append(row)
    expected = {(linux, v6, loaded, pooled, mode, enabled)
                for linux, v6, loaded, pooled, mode, enabled in itertools.product((False, True), (False, True), (False, True), (False, True), MODES, (False, True))
                if not (linux and mode == "previous-epoch")}
    expected_codecs = {(linux, v6, mode, kind)
                       for linux, v6, mode, kind in itertools.product((False, True), (False, True), MODES, range(4))
                       if mode != "ordinary" and not (linux and mode == "previous-epoch")}
    if set(groups) != expected or set(codecs) != expected_codecs or set(calibrations) != set(range(5)):
        raise ValueError("missing or extra declared workloads")
    if completes[0] != {"type": "complete", "cases": len(expected) // 2, "rounds": 9}:
        raise ValueError("incomplete run")
    for records in itertools.chain(groups.values(), codecs.values(), calibrations.values()):
        if sorted(r["round"] for r in records) != list(range(9)):
            raise ValueError("insufficient/duplicate independent rounds")
        records.sort(key=lambda r: r["round"])
        for r in records:
            if "ns" in r and (not math.isfinite(r["ns"]) or r["ns"] <= 0):
                raise ValueError("nonfinite/empty samples")
    return method, groups, codecs, calibrations


def corrected_estimates(full, scope, calls, internal_scope, enabled_scope, full_internal):
    # The full timer and the scope observer both add elapsed time. Removing
    # internal scope bias alone must not move that bias into the denominator.
    credential = scope - calls * internal_scope
    outside = full - scope - calls * (enabled_scope - internal_scope) - full_internal
    return credential, outside


def observer_estimates(calibrations):
    empty = statistics.median(r["ns"] / 16384 for r in calibrations[0])
    return {
        "empty_loop_ns": empty,
        # Whole-pair throughput includes work outside an internal elapsed
        # interval; retain it as observer cost, never as full_ns timer bias.
        "read_pair_increment_ns": statistics.median(r["ns"] / 16384 for r in calibrations[1]) - empty,
        "enabled_scope_increment_ns": statistics.median(r["ns"] / 16384 for r in calibrations[3]) - statistics.median(r["ns"] / 16384 for r in calibrations[2]),
        "empty_scope_internal_ns": statistics.median(r["scope_ns"] / 16384 for r in calibrations[3]),
        "empty_full_internal_ns": statistics.median(r["full_internal_ns"] / 16384 for r in calibrations[4]),
    }


def report(rows, stdout):
    method, groups, codecs, calibrations = validate(rows, stdout)
    emit(method)
    for kind, records in sorted(calibrations.items()):
        emit({"type": "calibration_rounds", "kind": kind, "iterations": 16384,
              "ns": [r["ns"] for r in records], "scope_ns": [r["scope_ns"] for r in records],
              "full_internal_ns": [r["full_internal_ns"] for r in records]})
    # Retain all per-round totals and quantiles, without thousands of duplicate frames.
    observer = observer_estimates(calibrations)
    enabled_scope = observer["enabled_scope_increment_ns"]
    internal_scope = observer["empty_scope_internal_ns"]
    full_internal = observer["empty_full_internal_ns"]
    emit({"type": "observer_estimates", **observer,
          "correction": "raw first; corrected credential subtracts matched empty-scope internal elapsed. Corrected outside also subtracts the remaining enabled observer increment and matched empty-full internal elapsed. Whole clock-pair throughput is reported separately and is not subtracted from internal elapsed intervals. Disabled-full minus matched empty-full internal elapsed minus corrected-enabled-credential is a separately sampled estimate. All corrections are signed and never clamped. Calibration min/max rounds bound observed control variation descriptively, not a statistical confidence interval or guaranteed observer bound."})
    ratios = collections.defaultdict(list)
    for key in sorted(k for k in groups if k[-1]):
        on, off = groups[key], groups[key[:-1] + (False,)]
        label = dict(zip(("linux", "v6", "loaded", "pooled", "mode"), key[:-1]))
        full = [r["full_ns"] / 128 for r in on]
        disabled = [r["full_ns"] / 128 for r in off]
        scope = [r["scope_ns"] / 128 for r in on]
        calls = [(r["valid_calls"] + r["issue_calls"]) / 128 for r in on]
        outside = [a-b for a, b in zip(full, scope)]
        estimates = [corrected_estimates(f, s, c, internal_scope, enabled_scope, full_internal) for f, s, c in zip(full, scope, calls)]
        corrected = [c for c, _ in estimates]
        corrected_outside = [o for _, o in estimates]
        ratios[(key[0], key[2])].append(statistics.median(s / o for s, o in zip(scope, outside)))
        emit({"type": "handshake_rounds", **label, "iterations_per_round": 128,
              "enabled_full_ns": [r["full_ns"] for r in on], "disabled_full_ns": [r["full_ns"] for r in off],
              "inclusive_scope_ns": [r["scope_ns"] for r in on],
              "valid_calls": on[0]["valid_calls"], "issue_calls": on[0]["issue_calls"],
              "enabled_full_quantiles_ns": [r["full_quantiles_ns"] for r in on],
              "disabled_full_quantiles_ns": [r["full_quantiles_ns"] for r in off],
              "scope_quantiles_ns": [r["scope_quantiles_ns"] for r in on],
              "outside_quantiles_ns": [r["outside_quantiles_ns"] for r in on],
              "median_per_packet_ns": {"enabled_full": statistics.median(full), "disabled_full": statistics.median(disabled), "inclusive_scope": statistics.median(scope), "observed_outside_scope": statistics.median(outside), "corrected_scope_estimate": statistics.median(corrected), "corrected_outside_estimate": statistics.median(corrected_outside), "separately_sampled_disabled_remaining_estimate": statistics.median(d - full_internal - c for d, c in zip(disabled, corrected))},
              "paired_observer_ns_per_packet": [a-b for a, b in zip(full, disabled)],
              "scope_to_observed_outside_ratio": [s / o for s, o in zip(scope, outside)]})
    for key, records in sorted(codecs.items()):
        emit({"type": "codec_rounds", **dict(zip(("linux", "v6", "mode", "kind"), key)), "iterations_per_round": 1024, "ns": [r["ns"] for r in records]})
    emit({"type": "assessment", "measurement_check": "pass", "rfc_status": "TODO pending complete relative-cost review; no numeric compliance rule",
          "scope_to_outside_median_ratio_ranges_by_policy_load": {f"{'linux' if k[0] else 'hmac'}_{'loaded' if k[1] else 'small'}": [min(v), max(v)] for k, v in ratios.items()},
          "limits": "Inclusive credential scope includes registry/lease/error authority. Small and loaded, pooled and allocating cases remain separate. Scope timers perturb execution; signed paired differences and all round distributions retained. A passing harness establishes executable evidence, not universal fast-relative compliance."})


def main():
    os.chdir(ROOT)
    output = ROOT / "workbench" / ("mac-cost-" + str(time.time_ns()))
    output.mkdir(parents=True)
    env = dict(os.environ)
    env.setdefault("CARGO_HOME", str(ROOT / "workbench/cargo-home"))
    # A fresh target directory guarantees the recorded invocation actually built
    # this checked binary, including inherited target/profile overrides.
    env["CARGO_TARGET_DIR"] = str(output / "target")
    build = ["cargo", "test", "--release", "--locked", "-p", "ntcp", "--all-features", "--lib", "--no-run", "--message-format=json", "-vv"]
    snapshot = source_snapshot()
    start = time.monotonic()
    process = subprocess.run(build, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=840)
    (output / "build.jsonl").write_text(process.stdout)
    (output / "build.stderr").write_text(process.stderr)
    if process.returncode:
        raise RuntimeError(process.stderr)
    verify_sources(snapshot, "during compilation")
    artifacts = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
    artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("executable") and a["target"]["name"] == "ntcp" and a["profile"]["test"]]
    if len(artifacts) != 1:
        raise ValueError("missing unique core test executable")
    artifact = artifacts[0]
    if artifact["profile"]["debug_assertions"] or artifact["profile"]["opt_level"] != "3" or "tfo-linux-cookie" not in artifact["features"]:
        raise ValueError("required optimized release/all-features path absent")
    executable = Path(artifact["executable"])
    prov = provenance(env, build, executable, artifact, process.stderr, snapshot)
    emit(prov)
    result = subprocess.run([str(executable), TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=max(1, 895 - (time.monotonic() - start)))
    (output / "raw.stdout").write_text(result.stdout)
    emit({"type": "archive", "raw_stdout": str((output / "raw.stdout").relative_to(ROOT)), "raw_sha256": digest(result.stdout.encode()), "build_stderr_sha256": digest(process.stderr.encode())})
    if result.returncode:
        print(result.stdout[-12000:])
        raise RuntimeError("benchmark failed")
    if digest(executable.read_bytes()) != prov["executable_sha256"]:
        raise ValueError("executable changed during measurement")
    verify_sources(snapshot, "after compilation or during measurement")
    emit({"type": "execution", "elapsed_seconds": time.monotonic() - start, "test_exit": result.returncode,
          "exact_test": TEST, "raw_lines": len(result.stdout.splitlines())})
    rows = parse_rows(result.stdout)
    report(rows, result.stdout)


def parse_rows(stdout):
    # libtest prints `test NAME ... ` before the first nocapture line.
    return [json.loads(line.split(PREFIX, 1)[1]) for line in stdout.splitlines() if PREFIX in line]


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.SubprocessError, OSError) as error:
        print("mac-cost: FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
