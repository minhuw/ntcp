"""Lossless text preparation for legacy RFC book and indented-heading layouts.

Only recognized publication furniture at page edges and heading indentation are
changed. Body text, including figures, spelling and punctuation, is retained.
The raw official download remains the provenance authority.

An early memo (RFC 826: a "Request For Comments:" identity line, no Category,
no section numbers or page furniture) has only centered named headings; their
indentation is removed so that Duvet recognizes them. Its other headings are
unnumbered text ("Packet Reception:") that Duvet cannot section, so the body
remains in the named section that precedes it.
"""
import re


IDENTITY = re.compile(r"^(?:Request [Ff]or Comments:|RFC:)\s*([1-9][0-9]*)\b", re.M)
DATE = re.compile(r"(?:January|February|March|April|May|June|July|August|September|October|November|December) [12][0-9]{3}")


def identity(raw, number):
    text = raw.decode("utf-8-sig")
    matches = IDENTITY.findall(text[:4000])
    if not matches:
        return False
    # The colon-form identity can be repeated inside a book; compact running
    # headers identify indented legacy publications. Conflicting identities
    # cannot be explained away as removable page furniture.
    matches += re.findall(r"^RFC:\s*([1-9][0-9]*)\b", text, re.M)
    matches += re.findall(r"^RFC([1-9][0-9]*) {2,}", text, re.M)
    return bool(matches) and set(matches) == {str(number)}


# The named headings Duvet's IETF parser recognizes that occur in early memos.
NAMED_HEADINGS = ("Abstract",)


def early_memo(raw):
    text = raw.decode("utf-8-sig")
    return bool(re.search(r"^Request For Comments:\s*[1-9][0-9]*\b", text[:4000], re.M)
                and not re.search(r"^Category:", text, re.M))


def legacy_layout(raw):
    text = raw.decode("utf-8-sig")
    return bool(re.search(r"^RFC:\s*[1-9][0-9]*\b", text[:4000], re.M)
                or re.search(r"^RFC[1-9][0-9]* {2,}", text, re.M)
                or early_memo(raw))


def prepare(raw):
    if not legacy_layout(raw):
        return raw
    text = raw.decode("utf-8-sig")
    early = early_memo(raw)
    book = bool(re.search(r"^RFC:\s*[1-9][0-9]*\b", text[:4000], re.M))
    # Book running headers repeat the publication title/date and the enclosing
    # top-level section title. Derive those strings from actual title/headings;
    # never classify arbitrary body lines as furniture by their indentation.
    headings = set(re.findall(r"^\s*[1-9][0-9]*\.\s+([A-Z][A-Z &-]+)\s*$", text, re.M))
    titles = set(re.findall(r"^ {8,}([A-Z][A-Z ]*[A-Z]) *$", text[:4000], re.M))
    dates = set(DATE.findall(text[:4000]))
    furniture = {s.casefold() for s in headings | titles | dates}
    output = []
    for page_index, page in enumerate(text.split("\f")):
        lines = page.splitlines()
        nonempty = [i for i, line in enumerate(lines) if line.strip()]
        edge = set(nonempty[:3]) if page_index else set()
        book_header = (book and any(lines[i].strip() in dates for i in edge)
                       and any(lines[i].strip().upper() in titles for i in edge))
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Numeric and Roman book page numbers, including trailing spaces.
            if re.fullmatch(r"\[Page (?:[1-9][0-9]*|[ivxlcdm]+)\]", stripped):
                continue
            if re.fullmatch(r"RFC[1-9][0-9]* {2,}.*", line) and i in edge:
                continue
            if book_header and i in edge and stripped.casefold() in furniture:
                continue
            # A hierarchical heading (with a textual title) or a centered,
            # uppercase top-level heading. Dotted TOC entries stay untouched.
            if i > 0 and not lines[i - 1].strip() and "..." not in line and (re.fullmatch(r"\s*[1-9][0-9]*(?:\.[0-9]+)+\.?\s+[A-Z].*", line)
                                      or re.fullmatch(r"\s*[1-9][0-9]*\.\s+[A-Z][A-Z &-]+\s*", line)):
                line = line.lstrip()
            # A centered named heading of an early memo, set off by blank lines.
            if (early and stripped in NAMED_HEADINGS and i > 0 and not lines[i - 1].strip()
                    and (i + 1 == len(lines) or not lines[i + 1].strip())):
                line = stripped
            output.append(line)
        output.append("")
    return ("\n".join(output).rstrip("\n") + "\n").encode()
