"""Canonical registration metadata; extraction is not a full operative audit."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "https://www.rfc-editor.org/rfc/rfc"
# This floor is intentional: editing metadata must never unregister old obligations.
ORIGINAL_RFCS = (9293, 2018, 6675, 8985, 9937, 6298, 5681, 6582, 6928,
                 7323, 2883, 3168, 5961, 3042, 9406, 9438, 1191, 8201,
                 4821, 5927, 7413)
KINDS = {"extracted-requirements", "selected-requirements", "scoped-operative", "full-operative"}


def load_scopes(root=ROOT):
    data = tomllib.loads((root / "duvet/rfc-scopes.toml").read_text())
    if data.get("schema_version") != 1:
        raise ValueError("unsupported RFC scope schema")
    rows = data["rfc"]
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)) or not set(ORIGINAL_RFCS) <= set(ids):
        raise ValueError("duplicate registration or missing original RFC")
    for r in rows:
        if (type(r["id"]) is not int or r["scope_kind"] not in KINDS
                or r["extraction"] not in ("all", "section-3", "manual")
                or r["document_status"] not in ("Standards Track", "Informational", "Experimental", "Historic", "Best Current Practice", "Internet Standard")
                or not r["scope"].strip() or not r["inventory"].strip()):
            raise ValueError(f"invalid RFC metadata: {r}")
        if r["scope_kind"].endswith("operative") and not r["inventory"].endswith(".json"):
            raise ValueError("operative audit claims require a paragraph ledger")
        if r["scope_kind"] == "extracted-requirements" and r["extraction"] == "manual":
            raise ValueError("extracted inventory requires extraction")
        if r["scope_kind"] == "selected-requirements" and r["extraction"] != "manual":
            raise ValueError("selected inventory must remain explicitly manual")
    # Preserve the original extraction obligations even if config and metadata
    # are edited together. RFC7413 may expand its current manual selection.
    for r in rows:
        if r["id"] in set(ORIGINAL_RFCS) - {7413}:
            expected = "section-3" if r["id"] == 9293 else "all"
            if r["extraction"] != expected:
                raise ValueError(f"RFC{r['id']}: must preserve {expected} extraction")
    return {r["id"]: r for r in rows}


def check_registration(root=ROOT):
    scopes = load_scopes(root)
    config = tomllib.loads((root / "duvet/duvet.toml").read_text())
    sources = [s["source"] for s in config["specification"]]
    if len(sources) != len(set(sources)) or set(sources) != {f"{PREFIX}{n}" for n in scopes}:
        raise ValueError("configuration/registry membership mismatch")
    patterns = [r["pattern"] for r in config["requirement"]]
    expected = {"duvet/rfc*-additions.toml", "duvet/rfc*-todos.toml"}
    for n, row in scopes.items():
        if row["extraction"] != "manual":
            section = "section-3*" if row["extraction"] == "section-3" else "*"
            expected.add(f"workbench/duvet/requirements/**/rfc{n}/{section}.toml")
        path = (root / row["inventory"]).resolve()
        if not path.is_relative_to((root / "duvet").resolve()) or not path.is_file():
            raise ValueError(f"RFC{n}: missing or invalid inventory {row['inventory']}")
    if len(patterns) != len(set(patterns)) or set(patterns) != expected:
        raise ValueError("configuration/registry extraction mismatch")
    for path in (root / "duvet").glob("rfc*-*.toml"):
        if path.stem.endswith(("-additions", "-todos")):
            n = int(path.stem.split("-")[0][3:])
            if n not in scopes:
                raise ValueError(f"unregistered annotation inventory: {path.name}")
    for path in (root / "duvet").glob("rfc*-inventory.json"):
        if path.relative_to(root).as_posix() not in {r["inventory"] for r in scopes.values()}:
            raise ValueError(f"unregistered paragraph inventory: {path.name}")
    return scopes
