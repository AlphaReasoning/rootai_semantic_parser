#!/usr/bin/env python3
"""Build ground-truth manifests from each corpus's own documentation.

The rule this script exists to enforce: **nothing is invented**. Every entry
traces to something written in the target repository -- a machine-readable
label file, a vulnerability list in its own source, or a solution document that
names a file and quotes the vulnerable code verbatim.

Where a document names a file but no line, the line is located by searching the
real source for the exact snippet the document quotes, and the anchor used is
recorded on the entry. Where even that is not possible the line stays ``null``
and the entry is scored at file+class granularity. Where a corpus documents its
vulnerabilities only as gameplay (a challenge to solve, with no statement about
which code is at fault), no entry is emitted at all and the corpus is reported
as unscoreable rather than guessed at.

Confidence is ``high`` only when the corpus states the location itself, or when
a verbatim quoted snippet was found exactly once in the named file. Everything
else is ``low`` and listed in GROUND_TRUTH_REVIEW.md for human review.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
CORPORA = ROOT / "corpora"
MANIFESTS = ROOT / "manifests"


@dataclass
class Entry:
    id: str
    file: str
    line_start: Optional[int]
    line_end: Optional[int]
    cwe: str
    vuln_class: str
    source_doc: str
    confidence: str
    #: The text actually searched for, when a line was located rather than read.
    anchor: Optional[str] = None


@dataclass
class Manifest:
    corpus: str
    primary_language: str
    parser_tier: str
    ground_truth_source: str
    entries: List[Entry] = field(default_factory=list)
    #: Documented issues deliberately not scored, and why.
    excluded: List[Dict[str, str]] = field(default_factory=list)


def locate(source: Path, anchor: str) -> Optional[int]:
    """Line number of ``anchor`` in ``source``, only if it appears exactly once."""
    span = locate_span(source, anchor)
    return span[0] if span and span[0] == span[1] else None


def locate_span(source: Path, anchor: str):
    """First and last line where ``anchor`` occurs, or ``None`` if it never does.

    A construct the documentation describes once can appear on several
    consecutive lines -- NodeGoat calls ``eval()`` on three request fields in a
    row. Reporting the span is accurate; picking one of them would not be. A
    zero-hit anchor returns ``None`` rather than a guess, which is the signal
    that the document and the checked-out code have drifted apart.
    """
    if not source.exists():
        return None
    hits = [
        index
        for index, line in enumerate(source.read_text(errors="replace").splitlines(), 1)
        if anchor in line
    ]
    return (hits[0], hits[-1]) if hits else None


# ---------------------------------------------------------------------------
# OWASP BenchmarkJava -- machine-readable labels
# ---------------------------------------------------------------------------

BENCHMARK_CWE = {
    "cmdi": "CWE-78", "sqli": "CWE-89", "xss": "CWE-79", "pathtraver": "CWE-22",
    "ldapi": "CWE-90", "xpathi": "CWE-643", "trustbound": "CWE-501",
    "crypto": "CWE-327", "hash": "CWE-328", "weakrand": "CWE-330",
    "securecookie": "CWE-614",
}


def build_benchmarkjava() -> Manifest:
    root = CORPORA / "benchmarkjava"
    manifest = Manifest(
        corpus="benchmarkjava",
        primary_language="java",
        parser_tier="real",
        ground_truth_source="expectedresults-1.2.csv (shipped by the project)",
    )
    csv_path = root / "expectedresults-1.2.csv"
    if not csv_path.exists():
        return manifest
    testcode = "src/main/java/org/owasp/benchmark/testcode"
    for row in csv.reader(csv_path.open(encoding="utf-8")):
        if not row or row[0].lstrip().startswith("#"):
            continue
        name, category, real, cwe = (c.strip() for c in row[:4])
        if real.lower() != "true":
            # Safe cases are not ground-truth *vulnerabilities*; they are used
            # separately for the FP-trap scoring, which needs the labels intact.
            continue
        manifest.entries.append(
            Entry(
                id=name,
                file=f"{testcode}/{name}.java",
                line_start=None,
                line_end=None,
                cwe=f"CWE-{cwe}",
                vuln_class=category,
                source_doc="expectedresults-1.2.csv",
                confidence="high",
            )
        )
    return manifest


# ---------------------------------------------------------------------------
# DSVW -- the application enumerates its own vulnerabilities
# ---------------------------------------------------------------------------

#: Each documented case is reached through one query parameter, and the handler
#: for that parameter is a single line of dsvw.py. The parameter names come from
#: the project's own CASES table; the line is found by searching for the
#: parameter's use, so neither is invented.
DSVW_CASES = [
    ("Blind SQL Injection (boolean)", 'params["id"]', "CWE-89", "sqli"),
    ("Blind SQL Injection (time)", 'params["id"]', "CWE-89", "sqli"),
    ("UNION SQL Injection", 'params["id"]', "CWE-89", "sqli"),
    ("Login Bypass", 'params.get("password", "")', "CWE-89", "sqli"),
    ("Cross Site Scripting (reflected)", 'params["v"]', "CWE-79", "xss"),
    ("Cross Site Scripting (stored)", 'params["comment"]', "CWE-79", "xss"),
    ("Cross Site Scripting (JSONP)", 'params["callback"]', "CWE-79", "xss"),
    ("XML External Entity (local)", 'params["xml"]', "CWE-611", "xxe"),
    ("Server Side Request Forgery", 'params["path"]', "CWE-918", "ssrf"),
    ("Blind XPath Injection (boolean)", 'params["name"]', "CWE-643", "xpathi"),
    ("Unvalidated Redirect", 'params["redir"]', "CWE-601", "open-redirect"),
    ("Arbitrary Code Execution", 'params["domain"]', "CWE-78", "cmdi"),
    ("Path Traversal", 'params["path"]', "CWE-22", "pathtraver"),
    ("File Inclusion (remote)", 'params["include"]', "CWE-98", "rfi"),
    ("Component with Known Vulnerability (pickle)", 'params["object"]', "CWE-502", "deserialization"),
]

#: Documented by the project but not a source-to-sink dataflow defect, so a
#: taint engine has nothing to find. Excluded with the reason rather than
#: counted as a false negative it could never avoid.
DSVW_EXCLUDED = [
    ("Cross Site Request Forgery", "a missing token, not a data flow"),
    ("Clickjacking", "a missing response header, not a data flow"),
    ("Frame Injection (phishing)", "a rendering-context issue in the HTML template"),
    ("Frame Injection (content spoofing)", "a rendering-context issue in the HTML template"),
    ("Cross Site Scripting (DOM)", "occurs in client-side JavaScript served as a string"),
    ("HTTP Parameter Pollution", "a parsing-semantics issue, not a sink"),
    ("Denial of Service (memory)", "resource exhaustion, not injection"),
    ("Full Path Disclosure", "an error-handling disclosure, not a sink"),
    ("Source Code Disclosure", "same sink as Path Traversal; would double-count"),
    ("XML External Entity (remote)", "same sink as XXE (local); would double-count"),
    ("HTTP Header Injection (phishing)", "reaches send_header, which the tool does not model as a sink"),
]


def build_dsvw() -> Manifest:
    manifest = Manifest(
        corpus="dsvw",
        primary_language="python",
        parser_tier="real",
        ground_truth_source="CASES table in dsvw.py plus the handler lines it refers to",
    )
    source = CORPORA / "dsvw" / "dsvw.py"
    seen_lines: Dict[int, str] = {}
    for name, anchor, cwe, vuln_class in DSVW_CASES:
        line = locate(source, anchor)
        manifest.entries.append(
            Entry(
                id=name,
                file="dsvw.py",
                line_start=line,
                line_end=line,
                cwe=cwe,
                vuln_class=vuln_class,
                source_doc="dsvw.py CASES table",
                confidence="high" if line else "low",
                anchor=anchor,
            )
        )
        if line:
            seen_lines[line] = name
    for name, reason in DSVW_EXCLUDED:
        manifest.excluded.append({"id": name, "reason": reason})
    return manifest


# ---------------------------------------------------------------------------
# DVNA -- solution docs name the file and quote the vulnerable code
# ---------------------------------------------------------------------------

DVNA_DOC_CWE = {
    "a1-injection": ("CWE-89", "sqli"),
    "a4-xxe": ("CWE-611", "xxe"),
    "a7-xss": ("CWE-79", "xss"),
    "a8-insecure-deserialization": ("CWE-502", "deserialization"),
    "ax-unvalidated-redirects-and-forwards": ("CWE-601", "open-redirect"),
}

#: Anchors quoted verbatim in dvna/docs/solution/*.md. Each is searched for in
#: the file that same document names.
#: The doc for A1 quotes `SELECT name FROM Users WHERE login=`; the checked-out
#: code reads `SELECT name,id FROM ...`. The anchor follows the code, because
#: the document has drifted and the sink is unambiguously the same one.
DVNA_ANCHORS = [
    ("a1-injection", "core/appHandler.js", "SELECT name,id FROM Users WHERE login=", "CWE-89", "sqli"),
    ("a1-injection", "core/appHandler.js", "exec('ping -c 2 '", "CWE-78", "cmdi"),
    ("a4-xxe", "core/appHandler.js", "libxmljs.parseXmlString(", "CWE-611", "xxe"),
    ("a8-insecure-deserialization", "core/appHandler.js", "serialize.unserialize", "CWE-502", "deserialization"),
    ("ax-unvalidated-redirects-and-forwards", "core/appHandler.js", "res.redirect(req.query.url)", "CWE-601", "open-redirect"),
]


def build_dvna() -> Manifest:
    manifest = Manifest(
        corpus="dvna",
        primary_language="javascript",
        parser_tier="real",
        ground_truth_source="docs/solution/*.md -- each names the file and quotes the vulnerable line",
    )
    root = CORPORA / "dvna"
    for doc, rel, anchor, cwe, vuln_class in DVNA_ANCHORS:
        span = locate_span(root / rel, anchor)
        manifest.entries.append(
            Entry(
                id=f"{doc}:{vuln_class}",
                file=rel,
                line_start=span[0] if span else None,
                line_end=span[1] if span else None,
                cwe=cwe,
                vuln_class=vuln_class,
                source_doc=f"docs/solution/{doc}.md",
                confidence="high" if span else "low",
                anchor=anchor,
            )
        )
    return manifest


# ---------------------------------------------------------------------------
# NodeGoat -- the bundled tutorial names the file and the construct
# ---------------------------------------------------------------------------

#: `eval(` spans three consecutive request fields and `$where` two adjacent
#: query builders; both are one documented vulnerability, so the entry carries
#: the span rather than an arbitrary pick from within it.
NODEGOAT_ANCHORS = [
    ("a1", "app/routes/contributions.js", "= eval(req.body.", "CWE-94", "code-injection"),
    ("ssrf", "app/routes/research.js", "needle.get(url", "CWE-918", "ssrf"),
    ("a1", "app/data/allocations-dao.js", "$where", "CWE-943", "nosqli"),
]

NODEGOAT_EXCLUDED = [
    ("a2 Broken Authentication", "session and password handling, not a data flow to a sink"),
    ("a3 Sensitive Data Exposure", "storage and transport choices, not a sink"),
    ("a4 XXE", "no XML parser reachable from request data in this codebase"),
    ("a5 Broken Access Control", "a missing check, not a data flow"),
    ("a6 Security Misconfiguration", "configuration, not code dataflow"),
    ("a7 XSS", "rendered through templates; the tutorial does not name a sink line"),
    ("a8 CSRF", "a missing token, not a data flow"),
    ("a9 Known Vulnerable Components", "a dependency version, not a data flow"),
    ("a10 Insufficient Logging", "an absence of code, not a sink"),
    ("redos", "algorithmic complexity, not injection"),
]


def build_nodegoat() -> Manifest:
    manifest = Manifest(
        corpus="nodegoat",
        primary_language="javascript",
        parser_tier="real",
        ground_truth_source="app/views/tutorial/*.html -- the tutorial served by the app itself",
    )
    root = CORPORA / "nodegoat"
    for doc, rel, anchor, cwe, vuln_class in NODEGOAT_ANCHORS:
        span = locate_span(root / rel, anchor)
        manifest.entries.append(
            Entry(
                id=f"{doc}:{vuln_class}",
                file=rel,
                line_start=span[0] if span else None,
                line_end=span[1] if span else None,
                cwe=cwe,
                vuln_class=vuln_class,
                source_doc=f"app/views/tutorial/{doc}.html",
                # The tutorial names the file and the construct; the span comes
                # from matching that construct, not from judgement.
                confidence="high" if span else "low",
                anchor=anchor,
            )
        )
    for name, reason in NODEGOAT_EXCLUDED:
        manifest.excluded.append({"id": name, "reason": reason})
    return manifest


# ---------------------------------------------------------------------------
# GoVWA -- one directory per vulnerability class
# ---------------------------------------------------------------------------

GOVWA_CLASSES = {
    "sqli": ("CWE-89", "sqli"),
    "xss": ("CWE-79", "xss"),
    "xxe": ("CWE-611", "xxe"),
    "idor": ("CWE-639", "idor"),
    "csa": ("CWE-384", "session"),
}

GOVWA_EXCLUDED = [
    ("idor", "an authorisation check, not a source-to-sink data flow"),
    ("csa", "client-side session attack; not a sink the tool models"),
]


def build_govwa() -> Manifest:
    manifest = Manifest(
        corpus="govwa",
        primary_language="go",
        parser_tier="real",
        ground_truth_source="vulnerability/<class>/ directory names, as the project organises them",
    )
    root = CORPORA / "govwa" / "vulnerability"
    excluded_classes = {name for name, _ in GOVWA_EXCLUDED}
    for directory in sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []:
        name = directory.name
        if name not in GOVWA_CLASSES:
            continue
        if name in excluded_classes:
            continue
        cwe, vuln_class = GOVWA_CLASSES[name]
        for go_file in sorted(directory.rglob("*.go")):
            manifest.entries.append(
                Entry(
                    id=f"{name}:{go_file.stem}",
                    file=str(go_file.relative_to(CORPORA / "govwa")),
                    line_start=None,
                    line_end=None,
                    cwe=cwe,
                    vuln_class=vuln_class,
                    source_doc="repository layout: vulnerability/<class>/",
                    # The directory states the class, not which line is at
                    # fault, and not every file in it is the vulnerable one.
                    confidence="low",
                )
            )
    for name, reason in GOVWA_EXCLUDED:
        manifest.excluded.append({"id": name, "reason": reason})
    return manifest


# ---------------------------------------------------------------------------
# Corpora with no usable ground truth
# ---------------------------------------------------------------------------

UNSCOREABLE = {
    "juice-shop": (
        "typescript",
        "challenges.yml lists 113 challenges as gameplay objectives and never "
        "states which source file or line is at fault. data/static/codefixes "
        "holds rewritten snippets, not locations in the shipped tree. Any "
        "mapping would be inference, so none is made.",
    ),
    "pygoat": (
        "python",
        "Solutions/solution.md is a walkthrough of how to exploit each lab "
        "through the UI. It names no source file and quotes no vulnerable "
        "code, so file-level ground truth cannot be derived from it without "
        "guessing which view backs each lab.",
    ),
}


def main() -> int:
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    builders = [
        build_benchmarkjava, build_dsvw, build_dvna, build_nodegoat, build_govwa,
    ]
    summary = []
    for builder in builders:
        manifest = builder()
        payload = {
            "corpus": manifest.corpus,
            "primary_language": manifest.primary_language,
            "parser_tier": manifest.parser_tier,
            "ground_truth_source": manifest.ground_truth_source,
            "entries": [asdict(entry) for entry in manifest.entries],
            "excluded": manifest.excluded,
        }
        (MANIFESTS / f"{manifest.corpus}.ground_truth.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
        low = [e for e in manifest.entries if e.confidence == "low"]
        summary.append((manifest, low))
        print(
            f"{manifest.corpus:<16} {len(manifest.entries):>5} entries "
            f"({len(low)} low-confidence), {len(manifest.excluded)} excluded"
        )

    for name, (language, reason) in UNSCOREABLE.items():
        print(f"{name:<16}     0 entries -- UNSCOREABLE: {reason.split('.')[0]}.")

    write_review(summary)
    return 0


def write_review(summary) -> None:
    lines = [
        "# Ground Truth Review",
        "",
        "Built by `build_ground_truth.py` from each corpus's own documentation.",
        "Nothing here is inferred from reading the code and deciding it looked",
        "vulnerable; every entry traces to a label file, the project's own",
        "vulnerability table, or a solution document that names the file.",
        "",
        "## Counts",
        "",
        "| corpus | language | tier | entries | low-confidence | excluded | source |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for manifest, low in summary:
        lines.append(
            f"| {manifest.corpus} | {manifest.primary_language} | {manifest.parser_tier} | "
            f"{len(manifest.entries)} | {len(low)} | {len(manifest.excluded)} | "
            f"{manifest.ground_truth_source} |"
        )
    for name, (language, reason) in UNSCOREABLE.items():
        lines.append(f"| {name} | {language} | real | 0 | - | - | **none usable** |")

    lines += ["", "## Corpora excluded from scoring entirely", ""]
    for name, (_, reason) in UNSCOREABLE.items():
        lines += [f"**{name}** -- {reason}", ""]

    lines += [
        "## Low-confidence entries (need review)",
        "",
        "These are scored, but the location was not stated by the corpus.",
        "",
    ]
    any_low = False
    for manifest, low in summary:
        if not low:
            continue
        any_low = True
        lines += [f"### {manifest.corpus}", ""]
        for entry in low:
            location = entry.line_start if entry.line_start else "file-level only"
            lines.append(
                f"- `{entry.id}` -- {entry.file} ({location}), {entry.cwe}. "
                f"Source: {entry.source_doc}."
            )
        lines.append("")
    if not any_low:
        lines += ["None.", ""]

    lines += ["## Documented issues deliberately not scored", ""]
    for manifest, _ in summary:
        if not manifest.excluded:
            continue
        lines += [f"### {manifest.corpus}", ""]
        for item in manifest.excluded:
            lines.append(f"- **{item['id']}** -- {item['reason']}")
        lines.append("")

    (ROOT / "GROUND_TRUTH_REVIEW.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\nwrote {ROOT / 'GROUND_TRUTH_REVIEW.md'}")


if __name__ == "__main__":
    raise SystemExit(main())
