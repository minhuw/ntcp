#!/usr/bin/env python3
# Duvet 0.4.3 CI checks line presence; this gate checks each requirement span.
import json
import sys
from pathlib import Path

RFCS = (9293, 2018, 6675, 8985, 6937)
PREFIX = "https://www.rfc-editor.org/rfc/rfc"


def check(report):
    errors = []
    summaries = {}
    annotations = report["annotations"]
    for rfc in RFCS:
        target = f"{PREFIX}{rfc}"
        spec = report["specifications"].get(target)
        if spec is None or not spec.get("requirements"):
            errors.append(f"RFC {rfc}: missing requirement inventory")
            continue
        requirements = set(spec["requirements"])
        missing = set()
        seen = set()
        todo_requirements = set()
        excepted = requirements.copy()
        for section in spec["sections"]:
            for line in section["lines"]:
                if isinstance(line, str):
                    continue
                for ids, flags, text in line:
                    relevant = requirements.intersection(ids)
                    if not relevant or not text.strip():
                        continue
                    seen.update(relevant)
                    refs = report["refs"][flags]
                    if refs.get("todo"):
                        todo_requirements.update(relevant)
                    if not refs.get("exception"):
                        excepted.difference_update(relevant)
                    covered = refs.get("exception") or (
                        refs.get("citation") and refs.get("test")
                    )
                    if not covered or refs.get("todo"):
                        missing.update(relevant)
        missing.update(requirements - seen)
        todos = [a for a in annotations
                 if a.get("target_path") == target and a.get("type") == "TODO"]
        summaries[str(rfc)] = {
            "requirements": len(requirements),
            "covered": len(requirements - missing),
            "uncovered": len(missing),
            "excepted": len((excepted & seen) - missing),
            "untracked": len(missing - todo_requirements),
            "todos": len(todos),
        }
        for index in sorted(missing):
            a = annotations[index]
            errors.append(f"RFC {rfc}: incomplete requirement at {a['source']}:{a['line']}")
        for a in todos:
            errors.append(f"RFC {rfc}: TODO at {a['source']}:{a['line']}")
    return summaries, errors


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "workbench/duvet/report.json")
    summaries, errors = check(json.loads(path.read_text()))
    print(json.dumps({"rfcs": summaries, "errors": errors}, indent=2))
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
