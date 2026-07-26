#!/usr/bin/env python3
"""Validate the scanner against real open-source targets with known outcomes.

The unit suite proves individual behaviours and the benchmark proves them on
miniature applications this project wrote itself. Neither says how the scanner
behaves on code written by other people. This does.

Two kinds of target:

* **Deliberately vulnerable** applications with documented issues. These measure
  recall. DVWA is particularly useful because it ships each module at four
  difficulty tiers with ``impossible.php`` as the *fixed* version -- a finding
  there is unambiguously a false positive.
* **Mature libraries** with no known injection vulnerabilities. These measure the
  false-positive rate on ordinary code, which is what decides whether findings
  are worth a human's attention.

Requires network access to clone, so it is not part of the default test run.

    python tools/validate_corpus.py --workdir /tmp/rootai-corpus
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


@dataclass
class Target:
    """One corpus entry and what we expect the scanner to do with it."""

    name: str
    url: str
    scan_subdir: str
    kind: str  # "vulnerable" or "clean"
    #: Substrings of paths that are the *fixed* implementations. A finding in one
    #: of these is a false positive regardless of what else the target contains.
    fixed_markers: List[str]
    #: Minimum findings for a vulnerable target; maximum for a clean one.
    expect_at_least: int = 0
    expect_at_most: Optional[int] = None
    note: str = ""


TARGETS: List[Target] = [
    Target(
        name="nodegoat",
        url="https://github.com/OWASP/NodeGoat.git",
        scan_subdir="app",
        kind="vulnerable",
        fixed_markers=[],
        expect_at_least=2,
        note="OWASP teaching app; documented SSJS injection and SSRF",
    ),
    Target(
        name="dvwa",
        url="https://github.com/digininja/DVWA.git",
        scan_subdir="",
        kind="vulnerable",
        fixed_markers=["/impossible.php"],
        expect_at_least=15,
        note="four difficulty tiers per module; impossible.php is the fix",
    ),
]

CLEAN_TARGETS: List[Target] = [
    Target(
        name="flask",
        url="https://github.com/pallets/flask.git",
        scan_subdir="src",
        kind="clean",
        fixed_markers=[],
        expect_at_most=7,
        note="mature; the known findings are exec(compile(config_file.read())) -- real dataflow, intentional behaviour",
    ),
    Target(
        name="requests",
        url="https://github.com/psf/requests.git",
        scan_subdir="src",
        kind="clean",
        fixed_markers=[],
        expect_at_most=2,
        note="mature HTTP client; the known finding is its own URL fetch",
    ),
]


def clone(target: Target, workdir: Path) -> Optional[Path]:
    destination = workdir / target.name
    if destination.exists():
        return destination
    result = subprocess.run(
        ["git", "clone", "-q", "--depth", "1", target.url, str(destination)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        print(f"  ! clone failed for {target.name}: {result.stderr.strip()[:120]}")
        return None
    return destination


def scan(path: Path) -> Dict:
    """Scan a checkout and return its findings.

    Counts here are pre-filter: the report is built directly rather than through
    the CLI, so profile min-score filtering is not applied and the numbers run
    slightly higher than a `semantic-parser scan` on the same target. That is
    deliberate -- the corpus should notice noise before a threshold hides it.
    """
    from core.runtime import MultiFileParser
    from models import AnalysisOptions, SecurityConfig, TaintConfig
    from reports.renderers import build_bounty_report

    started = time.perf_counter()
    parser = MultiFileParser(
        str(path),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    report = parser.scan(taint_config=TaintConfig.profile("bugbounty"))
    bounty = build_bounty_report(report, "bugbounty", False)
    findings = bounty.findings if hasattr(bounty, "findings") else bounty.get("findings", [])
    return {
        "seconds": time.perf_counter() - started,
        "findings": [f if isinstance(f, dict) else vars(f) for f in findings],
        "nodes": report.node_count,
        "skipped": len(getattr(parser, "skipped_files", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default="/tmp/rootai-corpus")
    parser.add_argument("--keep", action="store_true", help="keep clones for inspection")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    failures: List[str] = []
    print(f"corpus workdir: {workdir}\n")

    for target in TARGETS + CLEAN_TARGETS:
        checkout = clone(target, workdir)
        if checkout is None:
            failures.append(f"{target.name}: clone failed")
            continue
        scan_root = checkout / target.scan_subdir if target.scan_subdir else checkout
        result = scan(scan_root)
        findings = result["findings"]

        print(f"{target.name} ({target.kind}) -- {target.note}")
        print(
            f"  {len(findings)} findings, {result['nodes']} nodes, "
            f"{result['seconds']:.1f}s, {result['skipped']} generated files skipped"
        )

        in_fixed = [
            f
            for f in findings
            if any(marker in str(f.get("sink_location", "")) for marker in target.fixed_markers)
        ]
        if in_fixed:
            failures.append(f"{target.name}: {len(in_fixed)} finding(s) in the FIXED implementation")
            for finding in in_fixed[:3]:
                print(f"  ! false positive in fix: {finding.get('sink_location')}")

        if target.kind == "vulnerable" and len(findings) < target.expect_at_least:
            failures.append(
                f"{target.name}: recall regression, {len(findings)} < {target.expect_at_least}"
            )
        if target.expect_at_most is not None and len(findings) > target.expect_at_most:
            failures.append(
                f"{target.name}: noise regression, {len(findings)} > {target.expect_at_most}"
            )
            for finding in findings[: target.expect_at_most + 2]:
                print(f"    {finding.get('impact')} -> {finding.get('sink_location')}")
        print()

    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)

    if failures:
        print("FAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("all corpus expectations met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
