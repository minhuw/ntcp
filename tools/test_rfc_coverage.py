import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

from check_rfc_coverage import PREFIX, RFCS, check


def complete_report():
    return {
        "annotations": [
            {"source": "requirements.toml", "line": i + 1,
             "target_path": f"{PREFIX}{rfc}", "type": "SPEC"}
            for i, rfc in enumerate(RFCS)
        ],
        "specifications": {
            f"{PREFIX}{rfc}": {
                "requirements": [i],
                "sections": [{"lines": [[[[i], 0, "Required behavior."]]]}],
            }
            for i, rfc in enumerate(RFCS)
        },
        "refs": [{"spec": True, "citation": True, "test": True},
                 {"spec": True, "citation": True},
                 {"spec": True, "exception": True}],
    }


class CoverageGate(unittest.TestCase):
    def test_config_extracts_all_requested_rfcs_and_all_extension_sections(self):
        config = tomllib.loads((Path(__file__).parent / "duvet.toml").read_text())
        self.assertEqual(set(RFCS), {9293, 2018, 6675, 8985, 6937, 6298,
                                     5681, 6582, 6928, 7323, 2883, 3168, 5961})
        self.assertEqual({s["source"] for s in config["specification"]},
                         {f"{PREFIX}{rfc}" for rfc in RFCS})
        patterns = {r["pattern"] for r in config["requirement"]}
        for rfc in RFCS:
            sections = "section-3*" if rfc == 9293 else "*"
            self.assertIn(f"workbench/duvet/requirements/**/rfc{rfc}/{sections}.toml", patterns)
        self.assertIn("tools/rfc*-additions.toml", patterns)
        self.assertIn("tools/rfc*-todos.toml", patterns)

    def test_all_requested_rfcs_require_complete_spans_and_inventory(self):
        report = complete_report()
        summaries, errors = check(report)
        self.assertEqual(errors, [])
        self.assertEqual(set(summaries), {str(rfc) for rfc in RFCS})
        for key in report["specifications"]:
            for change in ("missing", "empty", "unmapped", "partial"):
                broken = copy.deepcopy(report)
                spec = broken["specifications"][key]
                if change == "missing":
                    del broken["specifications"][key]
                elif change == "empty":
                    spec["requirements"] = []
                elif change == "unmapped":
                    spec["sections"] = []
                else:
                    # Same line has both tested and untested quote fragments.
                    index = spec["requirements"][0]
                    spec["sections"][0]["lines"][0].append([[index], 1, "Missing assertion."])
                with self.subTest(rfc=key, change=change):
                    self.assertTrue(check(broken)[1])

    def test_wrapper_selects_ci_explicitly_and_preserves_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            for name in ("rfc-report.sh", "duvet.toml", "check_rfc_coverage.py"):
                shutil.copyfile(Path(__file__).parent / name, tools / name)
            binaries = root / "workbench/tools/bin"
            binaries.mkdir(parents=True)
            cargo = binaries / "cargo"
            cargo.write_text("#!/bin/sh\nprintf 'duvet v0.4.3:\\n'\n")
            cargo.chmod(0o755)
            duvet = binaries / "duvet"
            duvet.write_text(f"#!{sys.executable}\nimport json, pathlib, sys\n"
                             "pathlib.Path('argv.json').write_text(json.dumps(sys.argv[1:]))\n")
            duvet.chmod(0o755)
            report = root / "workbench/duvet/report.json"
            report.parent.mkdir()
            report.write_text(json.dumps(complete_report()))
            env = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}", CI="0")
            for override in ([], ["--ci", "false"], ["--ci=false"]):
                with self.subTest(override=override):
                    result = subprocess.run(["sh", str(tools / "rfc-report.sh"), *override],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = json.loads((root / "argv.json").read_text())
                    expected = override or ["--ci", "true"]
                    self.assertEqual(arguments[-len(expected):], expected)
                    self.assertEqual(sum(a == "--ci" or a.startswith("--ci=")
                                         for a in arguments), 1)

    def test_explicit_exception_and_unresolved_todo(self):
        report = complete_report()
        spec = report["specifications"][f"{PREFIX}9293"]
        spec["sections"][0]["lines"][0][0][1] = 2
        self.assertEqual(check(report)[1], [])
        self.assertEqual(check(report)[0]["9293"]["excepted"], 1)
        # A TODO remains a failure even if another annotation covers its text.
        report["annotations"].append({
            "source": "todos.toml", "line": 1,
            "target_path": f"{PREFIX}9293", "type": "TODO",
            "comment": "Needs validated adapter feedback before closure.",
        })
        summaries, errors = check(report)
        self.assertEqual(summaries["9293"]["todos"], 1)
        self.assertTrue(any("Needs validated adapter feedback before closure." in e
                            for e in errors))
        report["refs"].append({"spec": True, "citation": True, "test": True, "todo": True})
        spec["sections"][0]["lines"][0] = [[[0, len(RFCS)], 3, "Required behavior."]]
        summaries, errors = check(report)
        self.assertEqual(summaries["9293"]["uncovered"], 1)
        self.assertEqual(summaries["9293"]["untracked"], 0)
        self.assertEqual(summaries["9293"]["excepted"], 0)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
