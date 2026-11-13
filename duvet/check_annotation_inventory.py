#!/usr/bin/env python3
"""Inventory completeness audit, deliberately separate from strict coverage.

Schema 1 is in rfc-scopes.toml. A TOML inventory is an existing [[spec]] list;
its scope can only claim extracted/selected requirements. A JSON ledger uses the
existing PMTU fields: rfc, document_status, scope, text_sha256, paragraphs. Rows
have unique id, section, exact quote, status (context/covered/TODO/exception),
reason, and (unless context) target. Optional parent names a context row. Covered
rows have [source, test] evidence, each repository-relative path::anchor; TODO
rows may retain partial evidence. Dispositions/reasons must match additions and
TODO/exception TOML, and evidence must carry the entire exact target/quotation.
extracted-requirements.json separately fixes the complete extracted target/quote
set to official text hashes; missing generated files/rows cannot shrink it. Its
original 569 keys are regression-locked to the exact base. Explicit empty_reason
is required for an empty extraction (RFC8201's lowercase wording).
New operative ledgers should state scope_kind; full-operative MUST do so and
account for all text in numbered/appendix sections, using context rows where
appropriate. This mechanical completeness check cannot judge a clause's meaning
or whether a test proves it: independent operative/evidence review is required.

Only whitespace and explicit RFC page furniture are removed for provenance.
Legacy book/indented headings are prepared for pinned Duvet with the same text
retention policy; raw downloads and official publication metadata remain bound
by hashes. Category-less legacy Internet Standards require validated RFC Editor
JSON identity, title, publication date, status and source, not an invented header.
--generate always reads the official inputs afresh, deletes the previous
report/extracted requirements, and invokes pinned Duvet without CI abort. The
official inputs are the dev shell's NTCP_RFC_TEXTS: Nix fetches each official URL
by the SHA-256 in rfc-texts.json, so the audit makes no network request. A generator failure is
never a coverage verdict. Without --generate an input/report hash receipt from a
successful generation is required; caches alone cannot establish freshness.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tomllib
from urllib.request import Request

from check_rfc_coverage import check
from rfc_scopes import PREFIX, ROOT, check_registration
from historical_rfc import early_memo, identity, legacy_layout, prepare

ARTIFACTS = Path("workbench/rfc-annotation-gap")
REPORT = Path("workbench/duvet/report.json")
KINDS = {"spec": "SPEC", "TODO": "TODO", "exception": "EXCEPTION"}
MAX_TEXT = 2 * 1024 * 1024


def norm(text):
    # Hard-wrapped RFC words/identifiers occur as both "per-service- port"
    # and "per-service-port", or "SHLD- 13" and "SHLD-13", in annotations.
    # Ignore whitespace after a letter-hyphen before a letter/digit; retain
    # every hyphen, and leave operators such as "<- SEG.ACK" and "a - b" alone.
    text = re.sub(r"(?<=[A-Za-z]-)\s+(?=[A-Za-z0-9])", "", text)
    return " ".join(text.split())


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def official_lines(raw):
    # Match Duvet's RFC furniture policy explicitly. Do not remove arbitrary
    # author names, rejoin hyphenated words, fix errata, or change punctuation.
    for line in prepare(raw).decode("utf-8-sig").splitlines():
        if (re.match(r"^RFC [1-9][0-9]*  ", line)
                or re.match(r"^\[Page [1-9][0-9]*\]", line)
                or re.search(r" \[Page [1-9][0-9]*\]$", line)):
            continue
        yield line


def official_sections(raw):
    sections = defaultdict(list)
    current = "preamble"
    # An early memo has no numbered sections; Duvet's first section must be
    # 1, so body lines beginning with a number ("100 useless entries") are
    # never headings there.
    numbered = not early_memo(raw)
    for line in official_lines(raw):
        heading = numbered and re.match(r"^(?:((?:Appendix|APPENDIX) )([A-Z](?:\.[0-9]+)*)[.:]?|([0-9]+(?:\.[0-9]+)*\.?|[A-Z](?:\.[0-9]+)*\.))\s+\S.*$", line)
        if heading and "..." not in line:
            number = (heading[2] or heading[3]).rstrip(".")
            current = ("appendix-" if heading[1] or number[0].isalpha() else "section-") + number
            continue
        if line in ("Abstract", "Status of This Memo", "Status of this Memo", "Copyright Notice",
                    "Acknowledgement", "Acknowledgements", "Acknowledgments", "Author's Address",
                    "Authors' Addresses", "Full Copyright Statement", "Intellectual Property",
                    "References", "REFERENCES", "Security Considerations", "Table of Contents"):
            current = "name-" + line.lower().replace(" ", "-")
            continue
        sections[current].append(line)
    return {key: norm("\n".join(lines)) for key, lines in sections.items()}


def store_opener(request, timeout):
    """Open an official RFC Editor URL as the dev shell's fixed-output Nix fetch of it."""
    url = request.full_url
    require(os.environ.get("NTCP_RFC_TEXTS"), "NTCP_RFC_TEXTS is unset: run inside nix develop")
    require(url.startswith(PREFIX), f"{url}: not an official RFC URL")
    response = io.BytesIO((Path(os.environ["NTCP_RFC_TEXTS"]) / url.rsplit("/", 1)[1]).read_bytes())
    response.geturl = lambda: url
    response.headers = {}
    return response


def fetch_official(n, directory, opener=store_opener):
    url = f"{PREFIX}{n}.txt"
    error = None
    for attempt in range(3):
        try:
            with opener(Request(url, headers={"User-Agent": "ntcp-annotation-inventory/1"}), timeout=30) as response:
                require(response.geturl() == url, f"RFC{n}: unexpected official URL")
                raw = response.read(MAX_TEXT + 1)
                require(len(raw) <= MAX_TEXT, f"RFC{n}: specification too large")
                require(identity(raw, n), f"RFC{n}: response is not the requested official text")
                metadata = {"url": url, "sha256": digest(raw), "bytes": len(raw),
                            "fetched_ns": time.time_ns(),
                            "etag": response.headers.get("ETag"),
                            "last_modified": response.headers.get("Last-Modified")}
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"rfc{n}.txt").write_bytes(raw)
            if legacy_layout(raw) and not re.search(rb"^Category:", raw, re.M):
                metadata_url = f"{PREFIX}{n}.json"
                with opener(Request(metadata_url, headers={"User-Agent": "ntcp-annotation-inventory/1"}), timeout=30) as response:
                    require(response.geturl() == metadata_url, f"RFC{n}: unexpected official metadata URL")
                    metadata_raw = response.read(MAX_TEXT + 1)
                    require(len(metadata_raw) <= MAX_TEXT, f"RFC{n}: metadata too large")
                validate_legacy_metadata(n, raw, json.loads(metadata_raw))
                (directory / f"rfc{n}.json").write_bytes(metadata_raw)
                metadata["publication_metadata"] = {"url": metadata_url, "sha256": digest(metadata_raw),
                                                     "bytes": len(metadata_raw)}
            (directory / f"rfc{n}.provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
            return n, raw
        except (OSError, ValueError) as exc:
            error = exc
    raise ValueError(f"RFC{n}: official fetch failed after 3 bounded requests: {error}")


def validate_legacy_metadata(n, raw, metadata):
    require(identity(raw, n) and metadata.get("doc_id") == f"RFC{n}"
            and metadata.get("source") == "Legacy"
            and metadata.get("doi") == f"10.17487/RFC{n}"
            and metadata.get("pub_status") == "INTERNET STANDARD"
            and metadata.get("status") == "INTERNET STANDARD"
            and bool(metadata.get("pub_date"))
            and metadata["pub_date"] in raw.decode("utf-8-sig")[:4000],
            f"RFC{n}: invalid official legacy publication metadata")
    # Match words, allowing historical title line breaks and double hyphens.
    title = re.sub(r"[^a-z0-9]+", " ", metadata.get("title", "").lower()).strip()
    preamble = re.sub(r"[^a-z0-9]+", " ", raw.decode("utf-8-sig")[:4000].lower())
    require(title and title in preamble, f"RFC{n}: official metadata title mismatch")
    return "Internet Standard"


def publication_metadata(root, texts):
    return {n: json.loads((root / ARTIFACTS / "official" / f"rfc{n}.json").read_text())
            for n, raw in texts.items() if legacy_layout(raw) and not re.search(rb"^Category:", raw, re.M)}


def local_path(root, relative):
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), f"missing/invalid evidence or inventory: {relative}")
    return path


def toml_entries(path):
    data = tomllib.loads(path.read_text())
    return [(KINDS[kind], {**({"target": data["target"]} if "target" in data else {}), **row})
            for kind in KINDS for row in data.get(kind, [])]


def clause_key(row):
    return row["target"], norm(row["quote"])


def source_annotations(text):
    starts = list(re.finditer(r"(?m)^[ \t]*//= (https://[^\s]+)[ \t]*$", text))
    rows = []
    for i, match in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        block = text[match.end():end]
        # Duvet flushes an annotation at any nonannotation line (including a
        # blank or ordinary comment). Disconnected //# lines are not evidence.
        consecutive = []
        for line in block.splitlines()[1:]:
            if not re.match(r"^[ \t]*//[=#]", line):
                break
            consecutive.append(line)
        block = "\n".join(consecutive)
        quote = "\n".join(re.findall(r"(?m)^\s*//# ?(.*)$", block))
        kind = re.search(r"(?m)^\s*//= type=(\S+)", block)
        reason = re.search(r"(?m)^\s*//= reason=(.*)$", block)
        # Several annotations may precede a group of related declarations.
        # Locate their following code region, ending at the next annotation
        # group; anchor membership is a structural link, not a semantic proof.
        tail = text[match.end():]
        code = re.search(r"(?m)^[ \t]*(?!//|\s*$)\S.*$", tail)
        attached = ""
        if code:
            begin = match.end() + code.start()
            following = next((s.start() for s in starts if s.start() > begin), len(text))
            attached = text[begin:following]
        annotation_kind = kind[1].upper() if kind else "CITATION"
        if annotation_kind == "IMPLEMENTATION":
            annotation_kind = "CITATION"
        rows.append({"target": match[1], "quote": quote,
                     "line": text.count("\n", 0, match.start()) + 1,
                     "kind": annotation_kind,
                     "reason": reason[1] if reason else "", "attached": attached})
    return rows


def validate_inventories(root, scopes, texts, metadata=None):
    entries = []
    source_cache = {}
    for n, scope in scopes.items():
        raw = texts[n]
        official = norm("\n".join(official_lines(raw)))
        sections = official_sections(raw)
        # Status comes from official metadata, not a report annotation.
        if n == 1191:
            require(scope["document_status"] == "Standards Track" and "IAB Standards Track" in raw.decode(),
                    "RFC1191: official document status mismatch")
        elif legacy_layout(raw) and not re.search(rb"^Category:", raw, re.M):
            require(scope["document_status"] == validate_legacy_metadata(n, raw, (metadata or {}).get(n, {})),
                    f"RFC{n}: official document status mismatch")
        else:
            require(re.search(r"^Category:\s*" + re.escape(scope["document_status"]) + r"\b", raw.decode("utf-8-sig"), re.M),
                    f"RFC{n}: official document status mismatch")
        manual = []
        for suffix in ("additions", "todos"):
            relative = f"duvet/rfc{n}-{suffix}.toml"
            if suffix == "todos" and not (root / relative).exists():
                continue
            path = local_path(root, relative)
            for kind, row in toml_entries(path):
                target, quote = clause_key(row)
                require(target.startswith(f"{PREFIX}{n}#"), f"{path.name}: wrong RFC target")
                section = target.split("#", 1)[1]
                require(bool(quote) and quote in official, f"{path.name}: invalid official quotation: {quote[:90]}")
                require(quote in sections.get(section, ""), f"{path.name}: quotation/section mismatch: {section}: {quote[:90]}")
                if kind != "SPEC":
                    require(bool(row.get("reason", "").strip()), f"{path.name}: missing disposition reason")
                manual.append((kind, row))
                entries.append((path.relative_to(root).as_posix(), kind, row))
        specs = [clause_key(row) for kind, row in manual if kind == "SPEC"]
        require(specs and len(specs) == len(set(specs)), f"RFC{n}: empty/duplicate manual inventory")
        inventory = local_path(root, scope["inventory"])
        if inventory.suffix == ".toml":
            require(scope["inventory"] == f"duvet/rfc{n}-additions.toml", f"RFC{n}: incorrect TOML inventory")
            continue
        ledger = json.loads(inventory.read_text())
        require(ledger["rfc"] == n and ledger["document_status"] == scope["document_status"]
                and ledger["scope"] == scope["scope"] and ledger["text_sha256"] == digest(raw),
                f"RFC{n}: ledger metadata/provenance mismatch")
        # Legacy PMTU ledgers predate scope_kind and can only claim scoped audit.
        require(ledger.get("scope_kind", "scoped-operative") == scope["scope_kind"], f"RFC{n}: ledger scope claim mismatch")
        rows = ledger["paragraphs"]
        by_id = {row["id"]: row for row in rows}
        require(rows and len(by_id) == len(rows), f"RFC{n}: empty/duplicate paragraph inventory")
        operative = []
        for row in rows:
            quote = norm(row["quote"])
            require(quote and quote in official, f"{row['id']}: invalid official quotation")
            section = ("section-" if row["section"][0].isdigit() else "appendix-") + row["section"]
            require(quote in sections.get(section, ""), f"{row['id']}: paragraph/section mismatch")
            require(row["status"] in ("context", "covered", "TODO", "exception") and row["reason"].strip(),
                    f"{row['id']}: invalid disposition/reason")
            if "parent" in row:
                parent = by_id[row["parent"]]
                require(parent["status"] == "context" and parent["section"] == row["section"]
                        and quote in norm(parent["quote"]), f"{row['id']}: invalid paragraph parent")
            if row["status"] == "context":
                require(not row.get("evidence"), f"{row['id']}: context cannot claim evidence closure")
                continue
            require(row["target"] == f"{PREFIX}{n}#{section}", f"{row['id']}: target mismatch")
            operative.append(clause_key(row))
            if row["status"] in ("TODO", "exception"):
                matches = [r for k, r in manual if k == row["status"].upper() and clause_key(r) == clause_key(row)]
                require(len(matches) == 1 and matches[0]["reason"] == row["reason"], f"{row['id']}: disposition/reason mismatch")
            else:
                require(not any(k != "SPEC" and clause_key(r) == clause_key(row) for k, r in manual),
                        f"{row['id']}: covered row has TODO/exception")
                require(len(row.get("evidence", [])) == 2, f"{row['id']}: covered needs source and test evidence")
            for i, evidence in enumerate(row.get("evidence", [])):
                path, anchor = evidence.split("::", 1)
                require(bool(anchor.strip()), f"{row['id']}: empty evidence anchor")
                if path not in source_cache:
                    source_cache[path] = source_annotations(local_path(root, path).read_text())
                matches = [a for a in source_cache[path] if clause_key(a) == clause_key(row)
                           and anchor in a["attached"]]
                require(matches, f"{row['id']}: evidence target/quote/anchor mismatch: {evidence}")
                if row["status"] == "covered":
                    require(any(a["kind"] == ("CITATION" if i == 0 else "TEST") for a in matches),
                            f"{row['id']}: incorrect evidence type")
                if row["status"] == "TODO":
                    require(any(a["reason"] == row["reason"] for a in matches), f"{row['id']}: partial evidence reason mismatch")
        require(Counter(operative) == Counter(specs), f"RFC{n}: ledger/manual inventory mismatch")
        for kind in ("TODO", "EXCEPTION"):
            require(Counter(clause_key(r) for k, r in manual if k == kind)
                    == Counter(clause_key(r) for r in rows if r["status"].upper() == kind),
                    f"RFC{n}: extra/missing {kind} disposition")
        if scope["scope_kind"] == "full-operative":
            validate_full_document(n, sections, rows)
    return entries


def validate_full_document(n, sections, rows):
    for section, text in sections.items():
        if not section.startswith(("section-", "appendix-")):
            continue
        covered = bytearray(len(text))
        for row in rows:
            if section != ("section-" if row["section"][0].isdigit() else "appendix-") + row["section"]:
                continue
            quote = norm(row["quote"])
            for match in re.finditer(re.escape(quote), text):
                covered[match.start():match.end()] = b"\1" * len(quote)
        require(all(covered[i] or c.isspace() for i, c in enumerate(text)),
                f"RFC{n}: full-operative inventory omits document text in {section}")


def mapped_quotes(report):
    """Reassemble every annotation, concatenating fragments *within* each line."""
    parts = defaultdict(list)
    for spec in report["specifications"].values():
        for section in spec["sections"]:
            for line in section["lines"]:
                if isinstance(line, str):
                    continue
                by_id = defaultdict(list)
                for ids, flags, text in line:
                    for i in ids:
                        by_id[i].append(text)
                for i, text in by_id.items():
                    parts[i].append("".join(text))
    return {i: norm("\n".join(text)) for i, text in parts.items()}


def normalized_positions(text):
    """The same whitespace policy as norm(), retaining original offsets."""
    value, positions = [], []
    for token in re.finditer(r"\S+", text):
        joined_hyphen = (len(value) >= 2 and value[-1] == "-"
                         and value[-2] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         and token[0][0] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        if value and not joined_hyphen:
            value.append(" ")
            positions.append(token.start() - 1)
        value.extend(token[0])
        positions.extend(range(token.start(), token.end()))
    return "".join(value), positions


def section_projection(section, quote, annotation_id):
    """Check every byte of a quote, exposing Duvet 0.4.3's singleton-line bug.

    Upstream text/view.rs::StrRangeIter::next makes an empty source range for a
    one-character line in either the specification or the annotation. We
    tolerate only those independently verified original lines, never truncated
    words, punctuation on other lines, or invented text. Full quotation
    provenance/evidence remains mandatory, including singletons.
    """
    content, owners, singleton = [], [], set()
    for line in section["lines"]:
        text = line if isinstance(line, str) else "".join(p[2] for p in line)
        offset = len(content)
        if len(text.strip()) == 1:
            singleton.add(offset + len(text) - len(text.lstrip()))
        if isinstance(line, str):
            content.extend(text)
            owners.extend([[] for _ in text])
        else:
            for ids, flags, fragment in line:
                content.extend(fragment)
                owners.extend([ids for _ in fragment])
        content.append("\n")
        owners.append([])
    full, positions = normalized_positions("".join(content))
    expected, quote_positions = normalized_positions(quote)
    source_singletons = set()
    offset = 0
    for line in quote.splitlines(keepends=True):
        if len(line.strip()) == 1:
            source_singletons.add(offset + len(line) - len(line.lstrip()))
        offset += len(line)
    for match in re.finditer(re.escape(expected), full):
        selected = list(zip(full[match.start():match.end()], positions[match.start():match.end()]))
        allowed = {p for j, (c, p) in enumerate(selected)
                   if p in singleton or quote_positions[j] in source_singletons}
        if not all(c.isspace() or p in allowed or annotation_id in owners[p] for c, p in selected):
            continue
        projected = norm("".join(c for c, p in selected if p not in allowed or annotation_id in owners[p]))
        omitted = sum(p in allowed and annotation_id not in owners[p] for c, p in selected if not c.isspace())
        return projected, omitted
    raise ValueError("report contains a partial or mismatched full quotation span")


def extracted_obligations(root, scopes, texts):
    """Independent extraction contract, retained in Git rather than generated caches.

    Schema 1 records official text hashes and exact target/quote pairs per RFC.
    The original entries were captured by pinned Duvet at base 5817f38acc6b;
    additions must establish their extraction contract before registration.
    This is a keyword inventory, never a claim of full operative auditing.
    """
    manifest = json.loads(local_path(root, "duvet/extracted-requirements.json").read_text())
    require(manifest["schema_version"] == 1, "unsupported extraction contract schema")
    registered = {str(n) for n, scope in scopes.items() if scope["extraction"] != "manual"}
    require(set(manifest["rfcs"]) == registered, "extraction contract registration mismatch")
    expected = Counter()
    for number, inventory in manifest["rfcs"].items():
        n = int(number)
        require(inventory["text_sha256"] == digest(texts[n]), f"RFC{n}: extraction contract provenance mismatch")
        sections = official_sections(texts[n])
        rows = inventory["requirements"]
        keys = [clause_key(row) for row in rows]
        require(len(keys) == len(set(keys)) and (keys or inventory.get("empty_reason", "").strip()),
                f"RFC{n}: empty/duplicate extraction contract")
        for target, quote in keys:
            require(target.startswith(f"{PREFIX}{n}#"), f"RFC{n}: extraction contract target mismatch")
            section = target.split("#", 1)[1]
            require(scopes[n]["extraction"] != "section-3" or section == "section-3" or section.startswith("section-3."),
                    f"RFC{n}: extraction contract exceeds section-3 scope")
            require(quote and quote in sections.get(section, ""), f"RFC{n}: invalid extraction contract quotation")
            expected[target, quote] += 1
    return expected


def validate_report(report, scopes, entries, texts, root=ROOT):
    # Checking only the supplied entries would let missing extraction output
    # erase obligations. Compare against the tracked, official-text-bound keys
    # before trusting either the generated inventory or the report.
    expected_extracted = extracted_obligations(root, scopes, texts)
    actual_extracted = Counter(clause_key(row) for path, kind, row in entries
                               if path.startswith("workbench/") and kind == "SPEC")
    require(actual_extracted == expected_extracted, "extracted obligation set mismatch (missing or altered requirements)")
    require(set(report["specifications"]) == {f"{PREFIX}{n}" for n in scopes}, "report registration mismatch")
    annotations, refs = report["annotations"], report["refs"]
    require(isinstance(annotations, list) and isinstance(refs, list) and refs, "malformed report tables")
    section_index = {}
    for target, spec in report["specifications"].items():
        official = official_sections(texts[int(target.removeprefix(PREFIX))])
        requirements = spec["requirements"]
        require(requirements and len(requirements) == len(set(requirements)), f"{target}: missing/duplicate requirements")
        for i in requirements:
            require(type(i) is int and 0 <= i < len(annotations) and annotations[i].get("type") == "SPEC"
                    and annotations[i]["target_path"] == target, "invalid report requirement reference")
        require(set(requirements) == {i for i, a in enumerate(annotations)
                                     if a.get("type") == "SPEC" and a["target_path"] == target},
                "report omits registered requirement annotations")
        require(spec["sections"], f"{target}: missing sections")
        require({s["id"] for s in spec["sections"] if s["id"].startswith(("section-", "appendix-"))}
                == {s for s in official if s.startswith(("section-", "appendix-"))},
                f"{target}: report omits official document sections")
        for section in spec["sections"]:
            require(isinstance(section["id"], str), "invalid report section")
            require((target, section["id"]) not in section_index, "duplicate report section")
            section_index[target, section["id"]] = section
            full = norm("\n".join(line if isinstance(line, str) else "".join(p[2] for p in line)
                                  for line in section["lines"]))
            if section["id"].startswith(("section-", "appendix-")):
                require(full == official.get(section["id"]), f"{target}#{section['id']}: report/official text mismatch")
            for line in section["lines"]:
                if isinstance(line, str):
                    continue
                require(isinstance(line, list), "malformed report line")
                for ids, flags, text in line:
                    require(isinstance(ids, list) and type(flags) is int and 0 <= flags < len(refs)
                            and isinstance(text, str), "malformed report fragment")
                    for i in ids:
                        require(type(i) is int and 0 <= i < len(annotations)
                                and annotations[i]["target_path"] == target
                                and annotations[i].get("target_section") == section["id"], "invalid report annotation reference")
                    for field, kind in (("spec", "SPEC"), ("citation", "CITATION"), ("test", "TEST"),
                                        ("exception", "EXCEPTION"), ("todo", "TODO"), ("implication", "IMPLICATION")):
                        require(bool(refs[flags].get(field)) == any(annotations[i].get("type", "CITATION") == kind for i in ids),
                                "report flags disagree with annotation evidence")
                    if text.strip() and set(ids).intersection(requirements):
                        flags_row = refs[flags]
                        require(flags_row.get("exception") or flags_row.get("todo")
                                or flags_row.get("citation") and flags_row.get("test"),
                                "untracked in-scope requirement fragment")
    quotes = mapped_quotes(report)
    actual = Counter()
    by_key = defaultdict(list)
    for i, a in enumerate(annotations):
        require(a["target_path"] in report["specifications"], "annotation has unregistered target")
        if a.get("type") in KINDS.values():
            key = (a["source"], a["type"], a["target_path"] + "#" + a["target_section"])
            actual[key] += 1
            by_key[key].append(i)
    expected = Counter((path, kind, row["target"]) for path, kind, row in entries)
    require(actual == expected, "report inventory mismatch (missing or stale annotations)")
    singleton_omissions = 0
    source_cache = {}
    todo_reasons = {clause_key(row): row["reason"] for path, kind, row in entries if kind == "TODO"}
    # Duvet may fuzzy-match a misspelled evidence quotation. Read the actual
    # contributing source annotation by location, then validate both its exact
    # official quotation and its complete mapped span, for every inventory type.
    for i, a in enumerate(annotations):
        kind = a.get("type", "CITATION")
        if kind not in ("CITATION", "TEST"):
            continue
        path = a["source"]
        if path not in source_cache:
            source_cache[path] = source_annotations(local_path(root, path).read_text())
        target = a["target_path"] + "#" + a["target_section"]
        matches = [row for row in source_cache[path] if row["line"] == a["line"]
                   and row["target"] == target and row["kind"] == kind]
        require(len(matches) == 1, f"{path}:{a['line']}: missing/mismatched source evidence annotation")
        row = matches[0]
        # Every full-quote copy must retain the complete gap, including evidence
        # not listed in a ledger pair. Fragments and exceptions have other keys.
        key = clause_key(row)
        if key in todo_reasons:
            require(row["reason"] == todo_reasons[key],
                    f"{path}:{a['line']}: source/test canonical TODO reason mismatch")
        if not norm(row["quote"]):
            # A metadata-only comment cannot contribute closure. Duvet retains
            # it in annotations, so require that it owns no report fragments.
            require(i not in quotes, f"{path}:{a['line']}: empty source/test quotation claims evidence")
            continue
        section_id = a["target_section"]
        official = official_sections(texts[int(a["target_path"].removeprefix(PREFIX))])
        require(norm(row["quote"]) and norm(row["quote"]) in official.get(section_id, ""),
                f"{path}:{a['line']}: source/test quotation lacks exact official provenance")
        try:
            projected, omitted = section_projection(section_index[a["target_path"], section_id], row["quote"], i)
        except ValueError as exc:
            raise ValueError(f"{path}:{a['line']}: source/test {exc}") from exc
        require(projected == quotes.get(i, ""), f"{path}:{a['line']}: source/test mapped quotation mismatch")
        singleton_omissions += omitted
    for path, kind, row in entries:
        key = (path, kind, row["target"])
        target, section_id = row["target"].split("#", 1)
        # Check independently even for automatically extracted requirements.
        require(norm(row["quote"]) in official_sections(texts[int(target.removeprefix(PREFIX))]).get(section_id, ""),
                f"{path}: quotation lacks official section provenance")
        for i in by_key[key]:
            try:
                projected, omitted = section_projection(section_index[target, section_id], row["quote"], i)
            except ValueError:
                continue
            if projected == quotes.get(i, ""):
                by_key[key].remove(i)
                singleton_omissions += omitted
                break
        else:
            raise ValueError(f"{path}: report inventory/quotation mismatch (missing, partial, or stale spans)")
    summaries, errors = check(report)
    require(not any(s["untracked"] for s in summaries.values()), "untracked in-scope requirement spans")
    return summaries, errors, singleton_omissions


def closure_counts(report):
    # A span partly excepted and partly tested is not full source/test closure.
    counts = Counter(source_and_test_closed=0, mixed_closure=0)
    for spec in report["specifications"].values():
        requirements = set(spec["requirements"])
        tested, excepted, closed, seen = requirements.copy(), requirements.copy(), requirements.copy(), set()
        for section in spec["sections"]:
            for line in section["lines"]:
                if isinstance(line, str):
                    continue
                for ids, flags, text in line:
                    if not text.strip():
                        continue
                    relevant = requirements.intersection(ids)
                    seen.update(relevant)
                    refs = report["refs"][flags]
                    if refs.get("todo") or not (refs.get("citation") and refs.get("test")):
                        tested.difference_update(relevant)
                    if refs.get("todo") or not refs.get("exception"):
                        excepted.difference_update(relevant)
                    if refs.get("todo") or not (refs.get("exception") or refs.get("citation") and refs.get("test")):
                        closed.difference_update(relevant)
        counts["source_and_test_closed"] += len((tested & seen) - excepted)
        counts["mixed_closure"] += len((closed & seen) - tested - excepted)
    return dict(counts)


def input_hashes(root):
    # Receipt binds the report to all inputs, including source evidence and the
    # auditor itself. Ignored downloads/extraction are checked separately.
    paths = sorted([*(root / "duvet").glob("*.py"), *(root / "duvet").glob("*.sh"),
                    *(root / "duvet").glob("*.toml"), *(root / "duvet").glob("*.json"),
                    *(root / "crates").rglob("*.rs")])
    return {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in paths}


def generate(root, texts, runner=subprocess.run):
    report_path = root / REPORT
    report_path.unlink(missing_ok=True)
    # Extraction does not delete obsolete TOML files, so remove that cache too.
    shutil.rmtree(root / "workbench/duvet/requirements", ignore_errors=True)
    cache = root / "workbench/duvet/specifications/www.rfc-editor.org/rfc"
    cache.mkdir(parents=True, exist_ok=True)
    for n, raw in texts.items():
        (cache / f"rfc{n}.txt").write_bytes(prepare(raw))
    output = root / ARTIFACTS / "current"
    output.mkdir(parents=True, exist_ok=True)
    started = time.time_ns()
    result = runner(["sh", "duvet/rfc-report.sh", "--generate-only", "--ci", "false"],
                    cwd=root, capture_output=True, timeout=1500)
    (output / "generation.stdout").write_bytes(result.stdout)
    (output / "generation.stderr").write_bytes(result.stderr)
    (output / "generation.exit").write_text(str(result.returncode) + "\n")
    require(result.returncode == 0, f"Duvet generator failed (exit {result.returncode}); see {output}")
    # Some filesystems round mtimes; unlinking above is the primary freshness
    # guarantee. Accept this start second, but reject deliberately old files.
    require(report_path.is_file() and report_path.stat().st_mtime_ns >= started // 1_000_000_000 * 1_000_000_000,
            "generator did not write a fresh report")
    shutil.copyfile(report_path, output / "report.json")
    return json.loads(report_path.read_text())


def extraction_entries(root):
    config = tomllib.loads((root / "duvet/duvet.toml").read_text())
    manifest = json.loads(local_path(root, "duvet/extracted-requirements.json").read_text())
    for entry in config["requirement"]:
        if not entry["pattern"].startswith("workbench/"):
            continue
        paths = sorted(root.glob(entry["pattern"]))
        n = re.search(r"/rfc([0-9]+)/", entry["pattern"])[1]
        contract = manifest["rfcs"][n]
        # Duvet writes no directory for RFC8201's lowercase wording. Only an
        # explicit, provenance-validated empty contract can permit no files.
        require(paths or not contract["requirements"] and contract.get("empty_reason", "").strip(),
                f"missing extraction files: {entry['pattern']}")
        for path in paths:
            for kind, row in toml_entries(path):
                yield path.relative_to(root).as_posix(), kind, row


def audit(root=ROOT, generate_report=False):
    scopes = check_registration(root)
    output = root / ARTIFACTS / "current"
    output.mkdir(parents=True, exist_ok=True)
    receipt_path = output / "receipt.json"
    hashes = input_hashes(root)
    if generate_report:
        receipt_path.unlink(missing_ok=True)
        (output / "outcome.json").unlink(missing_ok=True)
        with ThreadPoolExecutor(max_workers=4) as pool:
            texts = dict(pool.map(lambda n: fetch_official(n, root / ARTIFACTS / "official"), scopes))
    else:
        receipt = json.loads(receipt_path.read_text())
        require(receipt["inputs"] == hashes and receipt["report_sha256"] == digest((root / REPORT).read_bytes()),
                "stale report/inputs; run --generate")
        texts = {n: (root / ARTIFACTS / "official" / f"rfc{n}.txt").read_bytes() for n in scopes}
        require(receipt["official"] == {str(n): digest(raw) for n, raw in texts.items()}, "stale official provenance")
    metadata = publication_metadata(root, texts)
    metadata_hashes = {str(n): digest((root / ARTIFACTS / "official" / f"rfc{n}.json").read_bytes()) for n in metadata}
    if not generate_report:
        require(receipt.get("publication_metadata", {}) == metadata_hashes, "stale official publication metadata")
    entries = validate_inventories(root, scopes, texts, metadata)
    report = generate(root, texts) if generate_report else json.loads((root / REPORT).read_text())
    entries.extend(extraction_entries(root))
    summaries, errors, singleton_omissions = validate_report(report, scopes, entries, texts, root=root)
    require(input_hashes(root) == hashes, "inputs changed during generation")
    # Invoke the unchanged strict policy even when it fails with tracked TODOs.
    strict = subprocess.run([sys.executable, "duvet/check_rfc_coverage.py"], cwd=root, capture_output=True)
    (output / "strict.stdout").write_bytes(strict.stdout)
    (output / "strict.stderr").write_bytes(strict.stderr)
    (output / "strict.exit").write_text(str(strict.returncode) + "\n")
    require(strict.returncode == int(bool(errors)) and json.loads(strict.stdout) == {"rfcs": summaries, "errors": errors},
            "strict checker did not return its expected verdict")
    totals = {key: sum(s[key] for s in summaries.values()) for key in ("requirements", "covered", "uncovered", "excepted", "todos", "untracked")}
    totals.update(closure_counts(report))
    mapped = mapped_quotes(report)
    unmapped_sources = [{"source": a["source"], "line": a["line"], "type": a.get("type", "CITATION")}
                        for i, a in enumerate(report["annotations"])
                        if a.get("type", "CITATION") in ("CITATION", "TEST") and i not in mapped]
    outcome = {"verdict": "inventory completeness", "complete": True,
               "strict_coverage": "FAIL" if errors else "PASS", "strict_exit": strict.returncode,
               "totals": totals, "rfcs": summaries,
               "legacy_publications": {str(n): {
                   "text_sha256": digest(texts[n]), "metadata_sha256": metadata_hashes[str(n)],
                   "prepared_text_sha256": digest(prepare(texts[n])),
                   "normalization": "Legacy book page-edge title/date/section headers, numeric/Roman footers and heading indentation; substantive text retained"
               } for n in metadata},
               "duvet_single_character_omissions": singleton_omissions,
               "unmapped_source_annotations": unmapped_sources,
               "limitations": "Duvet 0.4.3 leaves singleton lines in specifications or annotations unmapped; full original quotes are independently validated and retained. Unmapped source annotations contribute no closure. Scope labels describe actual inventory boundaries. Exact quotation and annotation links do not prove semantic conformance or full operative review."}
    (output / "outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
    receipt_path.write_text(json.dumps({"inputs": hashes, "official": {str(n): digest(raw) for n, raw in texts.items()},
                                        "publication_metadata": metadata_hashes,
                                        "report_sha256": digest((root / REPORT).read_bytes()),
                                        "generated_ns": time.time_ns()}, indent=2) + "\n")
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true", help="read the official texts afresh and generate a fresh report with pinned Duvet 0.4.3")
    args = parser.parse_args()
    try:
        print(json.dumps(audit(generate_report=args.generate), indent=2))
        return 0
    except (ValueError, KeyError, TypeError, IndexError, OSError, subprocess.SubprocessError) as exc:
        print(f"inventory audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
