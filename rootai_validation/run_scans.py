#!/usr/bin/env python3
"""Scan every corpus and record findings, timing, and graph statistics.

Static analysis only. Nothing here installs a target's dependencies or runs a
target application; each corpus is read as source text and nothing else.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent
CORPORA = ROOT / "corpora"
SCANS = ROOT / "scans"
CLI = ROOT / ".venv" / "bin" / "semantic-parser"

PROFILE = "bugbounty"
MIN_SCORE = "4.5"

#: Corpus -> subdirectory to scan. Empty means the whole checkout. BenchmarkJava
#: is restricted to its generated test cases: the surrounding harness, crawler
#: and helpers belong to no test case and would only add unattributable noise.
TARGETS: Dict[str, str] = {
    "dsvw": "",
    "nodegoat": "app",
    "dvna": "",
    "govwa": "",
    "pygoat": "",
    "juice-shop": "routes",
    "benchmarkjava": "src/main/java/org/owasp/benchmark/testcode",
}


def run(corpus: str, subdir: str) -> Dict:
    path = CORPORA / corpus / subdir if subdir else CORPORA / corpus
    if not path.exists():
        return {"corpus": corpus, "error": f"missing path {path}"}

    result: Dict = {"corpus": corpus, "scan_root": str(path.relative_to(ROOT))}
    for fmt, suffix in (("sarif", "sarif.json"), ("bounty-json", "bounty.json")):
        started = time.perf_counter()
        completed = subprocess.run(
            [str(CLI), "--profile", PROFILE, "--min-score", MIN_SCORE, str(path),
             "scan", "--format", fmt],
            capture_output=True, text=True, timeout=3600,
        )
        elapsed = time.perf_counter() - started
        out = SCANS / f"{corpus}.{suffix}"
        if completed.returncode != 0:
            result.setdefault("errors", []).append(
                {"format": fmt, "returncode": completed.returncode,
                 "stderr": completed.stderr[-800:]}
            )
            continue
        out.write_text(completed.stdout, encoding="utf-8")
        result[f"time_to_answer_{fmt}"] = round(elapsed, 2)
        result[f"output_{fmt}"] = str(out.relative_to(ROOT))
        # The scan writes progress and graph statistics to stderr.
        result[f"stderr_{fmt}"] = completed.stderr[-2000:]
    return result


def main() -> int:
    SCANS.mkdir(parents=True, exist_ok=True)
    results: List[Dict] = []
    for corpus, subdir in TARGETS.items():
        print(f"scanning {corpus} ...", flush=True)
        outcome = run(corpus, subdir)
        if "error" in outcome or "errors" in outcome:
            print(f"  ! {outcome.get('error') or outcome['errors']}")
        else:
            print(f"  {outcome.get('time_to_answer_sarif')}s (sarif)")
        results.append(outcome)
    (SCANS / "scan_index.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
